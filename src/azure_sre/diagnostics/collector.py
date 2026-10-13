"""Bounded, read-only diagnostics collection returning typed evidence."""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from azure_sre.config import BudgetPolicy
from azure_sre.contracts import (
    ApplicationMapping,
    ApplicationRegistry,
    DiagnosticWindow,
    EvidenceBundle,
    EvidenceError,
    EvidenceItem,
    EvidenceProvenance,
    EvidenceSource,
    EvidenceStatus,
)
from azure_sre.diagnostics.budget import fit_items
from azure_sre.diagnostics.executor import CommandCleanupError, CommandResult, CommandRunner
from azure_sre.diagnostics.templates import (
    TEMPLATES,
    DiagnosticKind,
    QueryContext,
    TemplateError,
    project_row,
)
from azure_sre.security.redaction import redact_value

_OPERATION_ID_RE: Final = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SINGLE_OBJECT_KINDS: Final = frozenset({DiagnosticKind.CONTAINER_APP_HEALTH})
_PERMISSION_MARKERS: Final = (b"authorizationfailed", b"forbidden", b"does not have authorization")
_MISSING_MARKERS: Final = (b"failed to resolve", b"could not be found", b"not found")
_NOT_FOUND_MESSAGE: Final = "telemetry table or resource not found"


class DiagnosticsError(ValueError):
    """Caller input was rejected before any command ran."""


@dataclass(frozen=True)
class CorrelationSelector:
    """Bounded correlation key. Only an App Insights operation id is accepted."""

    operation_id: str | None = None

    def __post_init__(self) -> None:
        if self.operation_id is not None and not _OPERATION_ID_RE.fullmatch(self.operation_id):
            raise DiagnosticsError("operation id has unsupported characters")


class DiagnosticsCollector:
    """Runs fixed Azure CLI templates and returns redacted, budget-bounded evidence.

    Calls are sequential within one investigation, so the per-replica concurrency limit is
    enforced by the caller that owns the replica's worker pool.
    """

    def __init__(
        self,
        *,
        registry: ApplicationRegistry,
        runner: CommandRunner,
        env: Mapping[str, str],
        budget: BudgetPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self._registry = registry
        self._runner = runner
        self._env = dict(env)
        self._budget = budget or BudgetPolicy()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._cancel = cancel

    def collect(
        self,
        app_id: str,
        kind: DiagnosticKind,
        window: DiagnosticWindow,
        selector: CorrelationSelector | None = None,
    ) -> EvidenceItem:
        """One bounded CLI call for one kind. Returns an item whose status is never guessed."""
        self._check_window(window)
        mapping = self._mapping(app_id)
        self._check_selector(kind, selector)
        return self._run_one(
            "E1",
            app_id,
            mapping,
            kind,
            window,
            selector,
            timeout_seconds=float(self._budget.cli_call_seconds),
        )

    def collect_bundle(
        self,
        *,
        incident_key: str,
        app_id: str,
        window: DiagnosticWindow,
        kinds: Iterable[DiagnosticKind],
        selector: CorrelationSelector | None = None,
    ) -> EvidenceBundle:
        """Run several kinds under the call, time, and byte budgets, in order."""
        self._check_window(window)
        mapping = self._mapping(app_id)
        unique = list(dict.fromkeys(kinds))
        if len(unique) > self._budget.diagnostic_calls:
            raise DiagnosticsError("too many diagnostics requested for one investigation")
        for kind in unique:
            self._check_selector(kind, selector)

        deadline = time.monotonic() + self._budget.investigation_seconds
        items: list[EvidenceItem] = []
        for index, kind in enumerate(unique, start=1):
            evidence_id = f"E{index}"
            remaining = deadline - time.monotonic()
            if self._cancel is not None and self._cancel.is_set():
                items.append(
                    self._failure(
                        evidence_id,
                        app_id,
                        mapping,
                        kind,
                        window,
                        EvidenceStatus.ERROR,
                        "investigation was cancelled",
                    )
                )
            elif remaining <= 0:
                items.append(
                    self._failure(
                        evidence_id,
                        app_id,
                        mapping,
                        kind,
                        window,
                        EvidenceStatus.TIMEOUT,
                        "investigation time budget exhausted",
                    )
                )
            else:
                items.append(
                    self._run_one(
                        evidence_id,
                        app_id,
                        mapping,
                        kind,
                        window,
                        selector,
                        timeout_seconds=min(float(self._budget.cli_call_seconds), remaining),
                    )
                )
        fitted = fit_items(incident_key, items, self._budget.evidence_bytes)
        return EvidenceBundle(incident_key=incident_key, items=fitted)

    # Internal helpers -------------------------------------------------------------------

    def _mapping(self, app_id: str) -> ApplicationMapping:
        for mapping in self._registry.applications:
            if mapping.app_id == app_id:
                return mapping
        raise DiagnosticsError("unknown application")

    def _check_window(self, window: DiagnosticWindow) -> None:
        limit_minutes = self._budget.window_before_minutes + self._budget.window_after_minutes
        if window.end - window.start > timedelta(minutes=limit_minutes):
            raise DiagnosticsError("diagnostic window exceeds the configured budget")

    @staticmethod
    def _check_selector(kind: DiagnosticKind, selector: CorrelationSelector | None) -> None:
        if selector is not None and selector.operation_id is not None:
            if not TEMPLATES[kind].supports_operation_id:
                raise DiagnosticsError("operation id is not supported for this diagnostic")

    def _run_one(
        self,
        evidence_id: str,
        app_id: str,
        mapping: Any,
        kind: DiagnosticKind,
        window: DiagnosticWindow,
        selector: CorrelationSelector | None,
        *,
        timeout_seconds: float,
    ) -> EvidenceItem:
        template = TEMPLATES[kind]
        operation_id = selector.operation_id if selector is not None else None
        try:
            argv = template.build_argv(
                QueryContext(
                    mapping=mapping,
                    window=window,
                    operation_id=operation_id,
                    row_limit=self._budget.rows_per_query,
                )
            )
        except TemplateError:
            return self._failure(
                evidence_id,
                app_id,
                mapping,
                kind,
                window,
                EvidenceStatus.ERROR,
                "invalid diagnostic input",
            )

        try:
            result = self._runner.run(
                argv,
                env=self._env,
                timeout_seconds=timeout_seconds,
                cancel=self._cancel,
            )
        except CommandCleanupError:
            return self._failure(
                evidence_id,
                app_id,
                mapping,
                kind,
                window,
                EvidenceStatus.ERROR,
                "diagnostic process could not be cleaned up",
            )
        if result.output_limit:
            return self._failure(
                evidence_id,
                app_id,
                mapping,
                kind,
                window,
                EvidenceStatus.ERROR,
                "diagnostic output exceeded the capture limit",
            )
        if result.timed_out:
            return self._failure(
                evidence_id,
                app_id,
                mapping,
                kind,
                window,
                EvidenceStatus.TIMEOUT,
                "diagnostic command timed out",
            )
        if result.cancelled:
            return self._failure(
                evidence_id,
                app_id,
                mapping,
                kind,
                window,
                EvidenceStatus.ERROR,
                "investigation was cancelled",
            )
        if result.returncode != 0:
            status, message = _classify_failure(result)
            return self._failure(evidence_id, app_id, mapping, kind, window, status, message)

        payload = _parse_payload(result.stdout)
        if payload is None:
            return self._failure(
                evidence_id,
                app_id,
                mapping,
                kind,
                window,
                EvidenceStatus.ERROR,
                "diagnostic output was not understood",
            )
        if kind in _SINGLE_OBJECT_KINDS and isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return self._failure(
                evidence_id,
                app_id,
                mapping,
                kind,
                window,
                EvidenceStatus.ERROR,
                "diagnostic output was not understood",
            )

        limit = self._budget.rows_per_query
        truncated = len(payload) > limit
        rows: list[dict[str, Any]] = []
        for raw in payload[:limit]:
            projected = project_row(raw, template.fields)
            if projected is None:
                # A malformed or wrong-schema row is an error, never a healthy-looking empty row.
                return self._failure(
                    evidence_id,
                    app_id,
                    mapping,
                    kind,
                    window,
                    EvidenceStatus.ERROR,
                    "diagnostic output had an unrecognised schema",
                )
            rows.append(redact_value(projected))
        row_count = min(len(payload), limit)
        status = EvidenceStatus.OK if rows else EvidenceStatus.ZERO_ROWS
        summary = (
            f"{template.template_id}: {len(rows)} row(s) returned"
            + (" (truncated at row limit)" if truncated else "")
            if rows
            else f"{template.template_id}: no rows returned; this is not proof of health"
        )
        return EvidenceItem(
            evidence_id=evidence_id,
            provenance=self._provenance(app_id, mapping, kind, window),
            status=status,
            summary=summary,
            rows=tuple(rows),
            row_count=row_count,
            truncated=truncated,
        )

    def _provenance(
        self, app_id: str, mapping: Any, kind: DiagnosticKind, window: DiagnosticWindow
    ) -> EvidenceProvenance:
        return EvidenceProvenance(
            source=EvidenceSource(kind.value),
            template_id=TEMPLATES[kind].template_id,
            scope_ref=f"app:{app_id}/env:{mapping.environment}",
            window=window,
            collected_at=self._clock(),
        )

    def _failure(
        self,
        evidence_id: str,
        app_id: str,
        mapping: Any,
        kind: DiagnosticKind,
        window: DiagnosticWindow,
        status: EvidenceStatus,
        message: str,
    ) -> EvidenceItem:
        return EvidenceItem(
            evidence_id=evidence_id,
            provenance=self._provenance(app_id, mapping, kind, window),
            status=status,
            summary="",
            row_count=0,
            error=EvidenceError(category=status, message=message),
        )


def _classify_failure(result: CommandResult) -> tuple[EvidenceStatus, str]:
    """Map stderr to a fixed category. Raw stderr is never returned or logged."""
    lowered = result.stderr.lower()
    if any(marker in lowered for marker in _PERMISSION_MARKERS):
        return EvidenceStatus.PERMISSION_DENIED, "insufficient permissions for this read"
    if any(marker in lowered for marker in _MISSING_MARKERS):
        return EvidenceStatus.MISSING_TELEMETRY, _NOT_FOUND_MESSAGE
    return EvidenceStatus.ERROR, "diagnostic command failed"


def _parse_payload(stdout: bytes) -> Any | None:
    """Parse CLI JSON. Empty output is ``None`` (an error), never a zero-row success."""
    if not stdout.strip():
        return None
    try:
        return json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
