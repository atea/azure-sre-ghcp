"""CopilotInvestigator: a bounded, host-controlled investigation yielding an InvestigationReport."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, StringConstraints

from azure_sre.config import BudgetPolicy
from azure_sre.contracts import (
    MAX_MODEL_OUTPUT_BYTES,
    ApplicationRegistry,
    DiagnosticWindow,
    EvidenceBundle,
    EvidenceItem,
    EvidenceStatus,
    InvestigationReport,
    ModelReportDraft,
    NormalizedAlert,
    PartialCategory,
    ReportGap,
    validate_model_output,
)
from azure_sre.diagnostics.collector import CorrelationSelector, DiagnosticsError
from azure_sre.diagnostics.templates import DiagnosticKind
from azure_sre.investigation.backend import ModelBackend, ModelSession, ToolOutcome, ToolSpec
from azure_sre.investigation.budget import BudgetRefused, CallLedger, EvidenceLedger
from azure_sre.investigation.prompt import build_prompt
from azure_sre.security.redaction import redact_text, redact_value
from azure_sre.worker.messages import PoisonMessage, bind_alert
from azure_sre.worker.protocols import InvestigationDeferred

logger = logging.getLogger(__name__)

_TOOL_NAME: Final = "query_diagnostic"
_BASELINE_KINDS: Final = (
    DiagnosticKind.CONTAINER_APP_HEALTH,
    DiagnosticKind.CONTAINER_APP_CONSOLE_ERRORS,
    DiagnosticKind.APP_INSIGHTS_CONFIGURATION,
    DiagnosticKind.APP_INSIGHTS_EXCEPTIONS,
)
_OUTPUT_SCHEMA: Final[dict[str, Any]] = ModelReportDraft.model_json_schema()
# Most to least specific: the first category found among the host gaps wins.
_PRECEDENCE: Final = (
    PartialCategory.BUDGET_EXHAUSTED,
    PartialCategory.PERMISSION_DENIED,
    PartialCategory.TIMEOUT,
    PartialCategory.EVIDENCE_MISSING,
    PartialCategory.SDK_ERROR,
)

_OperationId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:-]{1,128}$")]


class AlertRejected(ValueError):
    """The alert does not match the trusted application registry."""


class CollectorLike(Protocol):
    """Synchronous, standalone collector: returns one item numbered E1."""

    def collect(
        self,
        app_id: str,
        kind: DiagnosticKind,
        window: DiagnosticWindow,
        selector: CorrelationSelector | None = None,
    ) -> EvidenceItem: ...


CollectorFactory = Callable[[NormalizedAlert, threading.Event], CollectorLike]


class _QueryParams(BaseModel):
    """The only arguments the model controls: a fixed kind and an optional correlation id."""

    model_config = ConfigDict(extra="forbid")

    kind: DiagnosticKind
    operation_id: _OperationId | None = None


@dataclass(slots=True)
class _RunContext:
    alert: NormalizedAlert
    app_id: str
    window: DiagnosticWindow
    collector: CollectorLike
    cancel: threading.Event
    deadline: float
    calls: CallLedger
    ledger: EvidenceLedger
    inflight: set[asyncio.Future[EvidenceItem]] = field(default_factory=set)
    # Serializes charge, collect, and admit: the SDK may invoke tools concurrently.
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    gaps: list[ReportGap] = field(default_factory=list)
    primary: PartialCategory | None = None
    refused: bool = False
    stopped: bool = False
    raw: str | None = None
    deferred: InvestigationDeferred | None = None
    ai_link_verified: bool = False

    def mark(self, category: PartialCategory) -> None:
        if self.primary is None:
            self.primary = category

    def remaining(self) -> float:
        return max(self.deadline - time.monotonic(), 0.0)

    def gap(self, description: str, category: PartialCategory, refs: tuple[str, ...] = ()) -> None:
        self.gaps.append(
            ReportGap(description=description[:500], category=category, evidence_refs=refs)
        )


async def _settle(futures: set[asyncio.Future[Any]]) -> None:
    """Wait until every future has finished, even if the caller is cancelled while waiting.

    Cancellation is re-raised once all futures are done, so no worker thread is abandoned.
    """
    pending = set(futures)
    cancelled: asyncio.CancelledError | None = None
    while pending:
        try:
            _, pending = await asyncio.wait(pending)
        except asyncio.CancelledError as exc:
            cancelled = exc
    if cancelled is not None:
        raise cancelled


class CopilotInvestigator:
    """Runs one investigation per alert. Every host budget applies to every diagnostic call."""

    def __init__(
        self,
        *,
        registry: ApplicationRegistry,
        collector_factory: CollectorFactory,
        backend: ModelBackend,
        scratch_root: Path,
        budget: BudgetPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not scratch_root.is_dir():
            raise ValueError("scratch_root must be an existing directory")
        self._registry = registry
        self._factory = collector_factory
        self._backend = backend
        self._scratch_root = scratch_root
        self._budget = budget or BudgetPolicy()
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run(self, alert: NormalizedAlert) -> InvestigationReport:
        self._validate(alert)
        now = self._clock()
        cancel = threading.Event()
        collector = self._factory(alert, cancel)
        ctx = _RunContext(
            alert=alert,
            app_id=alert.app_id,
            window=self._window(alert, now),
            collector=collector,
            cancel=cancel,
            deadline=time.monotonic() + self._budget.investigation_seconds,
            calls=CallLedger(self._budget.diagnostic_calls),
            ledger=EvidenceLedger(alert.incident_key, self._budget.evidence_bytes),
        )
        with tempfile.TemporaryDirectory(dir=self._scratch_root) as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            await self._investigate(ctx, root)
        if ctx.deferred is not None:
            raise ctx.deferred
        return self._report(ctx)

    def _validate(self, alert: NormalizedAlert) -> None:
        """Bind every trusted field to the registry.

        bind_alert silently rebinds a stale fingerprint, so a changed alert is detected here.
        """
        try:
            bound = bind_alert(alert, self._registry)
        except PoisonMessage as exc:
            raise AlertRejected(f"alert rejected: {exc.reason.value}") from None
        if bound != alert:
            raise AlertRejected("alert registry fingerprint is stale")

    def _window(self, alert: NormalizedAlert, now: datetime) -> DiagnosticWindow:
        start = alert.fired_at - timedelta(minutes=self._budget.window_before_minutes)
        # Never query the future: clamp the end to now.
        end = min(alert.fired_at + timedelta(minutes=self._budget.window_after_minutes), now)
        if end <= start:
            raise AlertRejected("alert window is empty")
        return DiagnosticWindow(start=start, end=end)

    async def _investigate(self, ctx: _RunContext, root: Path) -> None:
        session: ModelSession | None = None
        try:
            async with asyncio.timeout(self._budget.investigation_seconds):
                await self._baseline(ctx)
                if not ctx.stopped:
                    session = await self._backend.open(self._tool_specs(ctx), root)
                    if ctx.remaining() <= 0:
                        ctx.mark(PartialCategory.TIMEOUT)
                    else:
                        bundle = EvidenceBundle(
                            incident_key=ctx.alert.incident_key, items=ctx.ledger.items
                        )
                        prompt = build_prompt(ctx.alert, bundle)
                        ctx.raw = await session.send(prompt, _OUTPUT_SCHEMA, ctx.remaining())
        except TimeoutError:
            ctx.mark(PartialCategory.TIMEOUT)
        except InvestigationDeferred as exc:
            ctx.deferred = exc
        except Exception as exc:  # noqa: BLE001 - any SDK/transport failure degrades to a partial report
            logger.warning("investigation sdk error: %s", type(exc).__name__)
            ctx.mark(PartialCategory.SDK_ERROR)
        finally:
            ctx.cancel.set()
            ctx.stopped = True
            try:
                await self._close(ctx, session)
            finally:
                # Runs even if close was cancelled or raised: no worker thread may outlive the run.
                await _settle(set(ctx.inflight))

    async def _close(self, ctx: _RunContext, session: ModelSession | None) -> None:
        if session is None:
            return
        try:
            errors = await session.close()
        except Exception as exc:  # noqa: BLE001 - cleanup failure is reported as a gap, never swallowed
            logger.warning("model session close failed: %s", type(exc).__name__)
            ctx.gap("model session cleanup failed", PartialCategory.SDK_ERROR)
            return
        if errors:
            logger.warning("model session cleanup reported %d error(s)", len(errors))
            ctx.gap(
                f"model session cleanup reported {len(errors)} error(s)",
                PartialCategory.SDK_ERROR,
            )

    async def _baseline(self, ctx: _RunContext) -> None:
        for kind in _BASELINE_KINDS:
            if ctx.stopped:
                return
            await self._collect(ctx, kind, None)
            if kind is DiagnosticKind.APP_INSIGHTS_CONFIGURATION:
                ctx.ai_link_verified = any(
                    item.provenance.source.value == kind.value
                    and item.status is EvidenceStatus.OK
                    and not item.truncated
                    for item in ctx.ledger.items
                )

    def _tool_specs(self, ctx: _RunContext) -> list[ToolSpec]:
        async def handle(params: _QueryParams) -> ToolOutcome:
            if ctx.stopped:
                return ToolOutcome(
                    "Investigation has stopped; no further diagnostics are available.", False
                )
            selector: CorrelationSelector | None = None
            if params.operation_id is not None:
                try:
                    selector = CorrelationSelector(params.operation_id)
                except ValueError:
                    return ToolOutcome("operation_id is not valid.", False)
            return await self._collect(ctx, params.kind, selector)

        return [
            ToolSpec(
                name=_TOOL_NAME,
                description=(
                    "Query one fixed Azure diagnostic for this alert's application and time "
                    "window. kind selects the diagnostic; operation_id is correlation only."
                ),
                params_model=_QueryParams,
                handler=handle,
            )
        ]

    async def _collect(
        self, ctx: _RunContext, kind: DiagnosticKind, selector: CorrelationSelector | None
    ) -> ToolOutcome:
        """Charge one call, run it on a worker thread, and admit its evidence. Every call counts."""
        async with ctx.lock:
            # No await between this check and task creation in _threaded: no call starts after stop.
            if ctx.stopped:
                return ToolOutcome(
                    "Investigation has stopped; no further diagnostics are available.", False
                )
            return await self._collect_locked(ctx, kind, selector)

    async def _collect_locked(
        self, ctx: _RunContext, kind: DiagnosticKind, selector: CorrelationSelector | None
    ) -> ToolOutcome:
        if (
            kind
            in (
                DiagnosticKind.APP_INSIGHTS_EXCEPTIONS,
                DiagnosticKind.APP_INSIGHTS_OPERATIONS,
            )
            and not ctx.ai_link_verified
        ):
            return ToolOutcome(
                "App Insights query blocked: workspace linkage has not been verified.", False
            )
        try:
            ctx.calls.charge()
        except BudgetRefused:
            if not ctx.refused:
                ctx.gap("diagnostic call budget exhausted", PartialCategory.BUDGET_EXHAUSTED)
            ctx.refused = True
            return ToolOutcome(
                "The diagnostic call budget for this investigation is exhausted.", False
            )
        if ctx.ledger.exhausted:
            return ToolOutcome(
                "The evidence byte budget is exhausted; no further evidence can be added.", False
            )
        item = await self._threaded(ctx, kind, selector)
        if item is None:
            return ToolOutcome("The diagnostic could not be completed.", False)
        admitted = ctx.ledger.admit(item)
        if admitted is None:
            ctx.gap(
                "evidence byte budget exhausted; a diagnostic result was not included",
                PartialCategory.BUDGET_EXHAUSTED,
            )
            return ToolOutcome(
                "The evidence byte budget is exhausted; the result was not included.", False
            )
        text = json.dumps(admitted.model_dump(mode="json"), sort_keys=True)
        return ToolOutcome(redact_text(text), True)

    async def _threaded(
        self, ctx: _RunContext, kind: DiagnosticKind, selector: CorrelationSelector | None
    ) -> EvidenceItem | None:
        """Run the sync collector in a worker thread. On timeout, cancel and await the thread."""
        task: asyncio.Future[EvidenceItem] = asyncio.ensure_future(
            asyncio.to_thread(ctx.collector.collect, ctx.app_id, kind, ctx.window, selector)
        )
        ctx.inflight.add(task)
        task.add_done_callback(ctx.inflight.discard)
        timeout = min(float(self._budget.cli_call_seconds), ctx.remaining())
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if task not in done:
            ctx.cancel.set()
            ctx.stopped = True
            ctx.mark(PartialCategory.TIMEOUT)
            ctx.gap("diagnostic call timed out", PartialCategory.TIMEOUT)
            # The worker thread must end (its subprocess is killed on cancel) before we report.
            await _settle({task})
            return None
        error = task.exception()
        if error is None:
            return task.result()
        if isinstance(error, DiagnosticsError):
            if selector is None:
                ctx.gap(
                    "a host-built diagnostic was rejected by the collector",
                    PartialCategory.EVIDENCE_MISSING,
                )
            return None
        if isinstance(error, ValueError):
            if not ctx.refused:
                ctx.gap(
                    "diagnostic result did not fit the host budget",
                    PartialCategory.BUDGET_EXHAUSTED,
                )
            ctx.refused = True
            return None
        logger.warning("diagnostic collection failed: %s", type(error).__name__)
        ctx.gap("diagnostic collection failed", PartialCategory.EVIDENCE_MISSING)
        return None

    def _draft(self, ctx: _RunContext, bundle: EvidenceBundle) -> ModelReportDraft | None:
        """Validate untrusted model output against the schema and the final evidence bundle."""
        raw = ctx.raw
        if raw is None or len(raw.encode("utf-8")) > MAX_MODEL_OUTPUT_BYTES:
            ctx.mark(PartialCategory.INVALID_REPORT)
            return None
        try:
            parsed = json.loads(raw)
        except ValueError:
            ctx.mark(PartialCategory.INVALID_REPORT)
            return None
        if not isinstance(parsed, Mapping):
            ctx.mark(PartialCategory.INVALID_REPORT)
            return None
        try:
            return validate_model_output(dict(redact_value(parsed)), bundle)
        except ValueError:
            ctx.mark(PartialCategory.INVALID_REPORT)
            return None

    def _report(self, ctx: _RunContext) -> InvestigationReport:
        bundle = EvidenceBundle(incident_key=ctx.alert.incident_key, items=ctx.ledger.items)
        gaps = list(ctx.gaps)
        for item in bundle.items:
            if item.status is not EvidenceStatus.OK or item.truncated:
                gaps.append(
                    ReportGap(
                        description=f"{item.evidence_id} {item.status.value}"
                        + ("; truncated" if item.truncated else ""),
                        category=_item_category(item),
                        evidence_refs=(item.evidence_id,),
                    )
                )
        draft = self._draft(ctx, bundle)
        present = {gap.category for gap in gaps}
        category = ctx.primary or next((c for c in _PRECEDENCE if c in present), None)
        if category is None and draft is not None and draft.status == "partial":
            category = PartialCategory.EVIDENCE_MISSING
        status: Literal["complete", "partial"] = "partial" if category is not None else "complete"
        if draft is not None and draft.status != status:
            draft = ModelReportDraft.model_validate({**draft.model_dump(), "status": status})
        return InvestigationReport(
            schema_version=1,
            incident_key=ctx.alert.incident_key,
            alert_id=ctx.alert.alert_id,
            app_id=ctx.alert.app_id,
            severity=ctx.alert.severity,
            sink=ctx.alert.sink,
            generated_at=self._clock(),
            status=status,
            partial_category=category,
            evidence=bundle,
            draft=draft,
            host_gaps=tuple(gaps),
        )


def _item_category(item: EvidenceItem) -> PartialCategory:
    if item.status is EvidenceStatus.PERMISSION_DENIED:
        return PartialCategory.PERMISSION_DENIED
    if item.status is EvidenceStatus.TIMEOUT:
        return PartialCategory.TIMEOUT
    return PartialCategory.EVIDENCE_MISSING
