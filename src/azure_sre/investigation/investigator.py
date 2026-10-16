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
    MAX_VALIDATION_NOTES,
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
    ReportValidationError,
    ValidationNote,
    ValidationNoteCode,
    has_conclusive_basis,
    validate_model_output,
)
from azure_sre.diagnostics.collector import CorrelationSelector, DiagnosticsError
from azure_sre.diagnostics.templates import DiagnosticKind
from azure_sre.investigation.backend import ModelBackend, ModelSession, ToolOutcome, ToolSpec
from azure_sre.investigation.budget import BudgetRefused, CallLedger, EvidenceLedger
from azure_sre.investigation.findings import derive_host_findings
from azure_sre.investigation.prompt import build_prompt, build_repair_prompt
from azure_sre.investigation.salvage import salvage_draft
from azure_sre.security.redaction import redact_text, redact_value
from azure_sre.worker.messages import PoisonMessage, bind_alert
from azure_sre.worker.protocols import InvestigationDeferred

logger = logging.getLogger(__name__)

_MIN_REPAIR_SECONDS: Final = 15.0
_REPAIR_MARGIN_SECONDS: Final = 5.0
_SALVAGEABLE: Final = frozenset(
    {ValidationNoteCode.SCHEMA_VIOLATION, ValidationNoteCode.EVIDENCE_REFERENCE}
)

_TOOL_NAME: Final = "query_diagnostic"
_BASELINE_KINDS: Final = (
    DiagnosticKind.CONTAINER_APP_HEALTH,
    DiagnosticKind.CONTAINER_APP_CONSOLE_ERRORS,
    DiagnosticKind.APP_INSIGHTS_CONFIGURATION,
    DiagnosticKind.APP_INSIGHTS_EXCEPTIONS,
)


def strict_response_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Return a structured-output schema that strict model APIs accept.

    Strict mode requires every object property to be listed in ``required`` and rejects
    ``default``. Defaulted fields here are all collections, so the model returns ``[]``;
    replies are still validated against ``ModelReportDraft`` itself.
    """

    def walk(node: Any) -> Any:
        if isinstance(node, Mapping):
            out = {key: walk(value) for key, value in node.items() if key != "default"}
            properties = out.get("properties")
            if out.get("type") == "object" and isinstance(properties, Mapping):
                out["required"] = list(properties)
                out["additionalProperties"] = False
            return out
        if isinstance(node, list):
            return [walk(value) for value in node]
        return node

    result: dict[str, Any] = walk(schema)
    return result


# Fields the host decides; they are not part of the schema the model answers.
_HOST_OWNED_FIELDS: Final = frozenset({"status"})


def _model_reply_schema() -> dict[str, Any]:
    schema = ModelReportDraft.model_json_schema()
    schema["properties"] = {
        key: value for key, value in schema["properties"].items() if key not in _HOST_OWNED_FIELDS
    }
    schema["required"] = [key for key in schema.get("required", ()) if key in schema["properties"]]
    return schema


_OUTPUT_SCHEMA: Final[dict[str, Any]] = strict_response_schema(_model_reply_schema())
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
    model_stage: str = "start"
    notes: list[ValidationNote] = field(default_factory=list)
    repair_notes: list[Note] = field(default_factory=list)

    def note(self, code: ValidationNoteCode, detail: str) -> None:
        if len(self.notes) < MAX_VALIDATION_NOTES:
            text = redact_text(detail).strip()[:500] or code.value
            self.notes.append(ValidationNote(code=code, detail=text))

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


Note = tuple[ValidationNoteCode, str]

# Alterations that lose model content; a repair turn is attempted when any occurs.
_LOSSY: Final = frozenset(
    {
        ValidationNoteCode.ITEM_DROPPED,
        ValidationNoteCode.REFS_REMOVED,
        ValidationNoteCode.DOWNGRADED,
        ValidationNoteCode.SUMMARY_REPLACED,
    }
)


@dataclass(frozen=True)
class DraftEvaluation:
    """Outcome of validating one model reply; ``notes`` are host-written."""

    draft: ModelReportDraft | None
    notes: tuple[Note, ...] = ()
    # Why strict validation failed, or None when the reply was valid as sent.
    reason: ValidationNoteCode | None = None
    problems: int = 0
    size: int = 0

    @property
    def lossy(self) -> int:
        """Lower is better: a rejected reply scores worst, then by lossy alterations."""
        if self.draft is None:
            return 1_000_000
        return sum(1 for code, _ in self.notes if code in _LOSSY)


def evaluate_model_output(raw: str | None, bundle: EvidenceBundle) -> DraftEvaluation:
    """Strictly validate a reply, salvaging it when only schema or reference checks fail."""
    size = len(raw.encode("utf-8")) if raw is not None else 0

    def reject(code: ValidationNoteCode, problems: tuple[str, ...]) -> DraftEvaluation:
        notes = tuple((code, problem) for problem in problems)
        return DraftEvaluation(None, notes, code, len(problems), size)

    if raw is None:
        return reject(ValidationNoteCode.NO_RESPONSE, ("the model returned no final reply",))
    if size > MAX_MODEL_OUTPUT_BYTES:
        return reject(ValidationNoteCode.OVERSIZED, ("model output exceeds size limit",))
    try:
        parsed = json.loads(raw)
    except ValueError:
        return reject(ValidationNoteCode.INVALID_JSON, ("model output is not valid JSON",))
    if not isinstance(parsed, Mapping):
        return reject(ValidationNoteCode.NOT_OBJECT, ("model output must be a JSON object",))
    # Status is host-owned: validate the reply as a draft and decide status in _report.
    document = {key: value for key, value in parsed.items() if key not in _HOST_OWNED_FIELDS}
    document["status"] = "partial"
    redacted = dict(redact_value(document))
    try:
        return DraftEvaluation(validate_model_output(redacted, bundle), size=size)
    except ReportValidationError as exc:
        try:
            code = ValidationNoteCode(exc.reason)
        except ValueError:
            code = ValidationNoteCode.SCHEMA_VIOLATION
        if code in _SALVAGEABLE:
            draft, notes = salvage_draft(redacted, bundle)
            if draft is not None:
                return DraftEvaluation(draft, tuple(notes), code, len(exc.problems), size)
        return reject(code, exc.problems)
    except ValueError:
        return reject(ValidationNoteCode.SCHEMA_VIOLATION, ("model output failed validation",))


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
                    ctx.model_stage = "session_open"
                    session = await self._backend.open(self._tool_specs(ctx), root)
                    if ctx.remaining() <= 0:
                        ctx.mark(PartialCategory.TIMEOUT)
                    else:
                        bundle = EvidenceBundle(
                            incident_key=ctx.alert.incident_key, items=ctx.ledger.items
                        )
                        prompt = build_prompt(ctx.alert, bundle)
                        ctx.model_stage = "model_turn"
                        ctx.raw = await session.send(prompt, _OUTPUT_SCHEMA, ctx.remaining())
                        await self._repair(ctx, session)
        except TimeoutError:
            ctx.mark(PartialCategory.TIMEOUT)
        except InvestigationDeferred as exc:
            ctx.deferred = exc
        except Exception as exc:  # noqa: BLE001 - any SDK/transport failure degrades to a partial report
            reason = classify_sdk_failure(exc)
            logger.warning(
                "investigation sdk error: stage=%s reason=%s type=%s",
                ctx.model_stage,
                reason,
                type(exc).__name__,
            )
            ctx.mark(PartialCategory.SDK_ERROR)
            ctx.gap(
                f"model session failed during {ctx.model_stage}: {reason}",
                PartialCategory.SDK_ERROR,
            )
        finally:
            ctx.cancel.set()
            ctx.stopped = True
            try:
                await self._close(ctx, session)
            finally:
                # Runs even if close was cancelled or raised: no worker thread may outlive the run.
                await _settle(set(ctx.inflight))

    async def _repair(self, ctx: _RunContext, session: ModelSession) -> None:
        """Give the model one chance to fix a rejected or lossy reply, with host feedback.

        The repaired reply replaces the original only when it loses less content. Any failure
        here (including rate limiting or timeout) keeps the original reply.
        """
        bundle = EvidenceBundle(incident_key=ctx.alert.incident_key, items=ctx.ledger.items)
        first = evaluate_model_output(ctx.raw, bundle)
        if first.lossy == 0 or first.reason is ValidationNoteCode.NO_RESPONSE:
            return
        seconds = ctx.remaining() - _REPAIR_MARGIN_SECONDS
        if seconds < _MIN_REPAIR_SECONDS:
            ctx.repair_notes.append(
                (ValidationNoteCode.REPAIR_ATTEMPTED, "repair turn skipped: not enough time left")
            )
            return
        ctx.model_stage = "repair_turn"
        outcome = "repair turn did not improve the reply; kept the original"
        try:
            async with asyncio.timeout(seconds):
                raw = await session.send(
                    build_repair_prompt(first.notes, bundle), _OUTPUT_SCHEMA, seconds
                )
        except TimeoutError:
            outcome = "repair turn timed out; kept the original reply"
        except Exception as exc:  # noqa: BLE001 - the original reply is still usable
            logger.warning("model repair turn failed: type=%s", type(exc).__name__)
            outcome = "repair turn failed; kept the original reply"
        else:
            second = evaluate_model_output(raw, bundle)
            if second.lossy < first.lossy:
                ctx.raw = raw
                outcome = "repair turn accepted: the corrected reply replaced the original"
        ctx.model_stage = "model_turn"
        logger.info("model repair turn: %s", outcome)
        ctx.repair_notes.append((ValidationNoteCode.REPAIR_ATTEMPTED, outcome))

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
        mapping = self._registry.get(ctx.app_id)
        if mapping is not None and mapping.storage_account_id is not None and not ctx.stopped:
            await self._collect(ctx, DiagnosticKind.STORAGE_ACCOUNT_CONFIGURATION, None)

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
        """Validate untrusted model output against the final bundle and record the outcome."""
        result = evaluate_model_output(ctx.raw, bundle)
        for code, detail in result.notes:
            ctx.note(code, detail)
        incident = ctx.alert.incident_key[:12]
        if result.draft is None:
            ctx.mark(PartialCategory.INVALID_REPORT)
            logger.warning(
                "model output rejected: reason=%s problems=%d bytes=%d incident=%s",
                result.reason.value if result.reason else "unknown",
                result.problems,
                result.size,
                incident,
            )
        elif result.reason is not None:
            logger.warning(
                "model output salvaged: reason=%s problems=%d changes=%d incident=%s",
                result.reason.value,
                result.problems,
                len(result.notes),
                incident,
            )
        for code, detail in ctx.repair_notes:
            ctx.note(code, detail)
        return result.draft

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
        # The host decides status: any host or model gap makes the report partial.
        all_gaps = [*gaps, *(draft.gaps if draft is not None else ())]
        present = {gap.category for gap in all_gaps}
        category = ctx.primary or next((c for c in _PRECEDENCE if c in present), None)
        if category is None and all_gaps:
            category = all_gaps[0].category
        if category is None and draft is not None and not draft.has_findings():
            category = PartialCategory.EVIDENCE_MISSING
        status: Literal["complete", "partial"] = "partial" if category is not None else "complete"
        if draft is not None and draft.status != status:
            draft = ModelReportDraft.model_validate({**draft.model_dump(), "status": status})
        findings = derive_host_findings(bundle)
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
            host_findings=findings,
            conclusion="conclusive" if has_conclusive_basis(draft, findings) else "inconclusive",
            validation_notes=tuple(ctx.notes),
        )


_SDK_FAILURE_RULES: Final = (
    ("authentication", ("token provider", "credential", "unauthorized", "401", "403")),
    ("response_schema", ("response_format", "invalid schema")),
    ("model_unavailable", ("model not", "unknown model", "unsupported model", "model is not")),
    ("model_request_rejected", ("execution failed", "400", "bad request")),
)
_SDK_AUTH_TYPES: Final = frozenset(
    {"PatAuthenticationError", "AppAuthenticationError", "PermissionError"}
)


def classify_sdk_failure(exc: BaseException) -> str:
    """Map an SDK failure to a fixed reason code. The exception text is never retained."""
    if type(exc).__name__ in _SDK_AUTH_TYPES:
        return "authentication"
    text = str(exc).lower()
    for reason, markers in _SDK_FAILURE_RULES:
        if any(marker in text for marker in markers):
            return reason
    if isinstance(exc, OSError | ConnectionError):
        return "runtime_unavailable"
    return "unclassified"


def _item_category(item: EvidenceItem) -> PartialCategory:
    if item.status is EvidenceStatus.PERMISSION_DENIED:
        return PartialCategory.PERMISSION_DENIED
    if item.status is EvidenceStatus.TIMEOUT:
        return PartialCategory.TIMEOUT
    return PartialCategory.EVIDENCE_MISSING
