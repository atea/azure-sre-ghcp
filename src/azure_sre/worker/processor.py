"""Durable incident state machine driven under a conditional lease.

Ordering per incident (one owner at a time, every transition ETag-guarded):

``pending_fired`` -> ``queued`` -> ``investigating`` -> ``report_persisted`` ->
``publishing`` (intent persisted *before* the remote write) -> ``published`` /
``partial_published`` -> optional recovery comment (separate ledger row).

Failures move to ``retryable_failure`` (bounded, jittered) or, when the outcome
of a remote write is unknown, ``publication_uncertain`` which is only ever
reconciled by marker lookup - never blindly re-created.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections.abc import Awaitable
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from pydantic import ValidationError

from azure_sre.contracts import (
    ApplicationRegistry,
    ContractError,
    EvidenceBundle,
    InvestigationReport,
    NormalizedAlert,
    PartialCategory,
    ReportGap,
    Sink,
)
from azure_sre.state.errors import (
    LeaseLost,
    ReportUnavailable,
    StaleTransition,
    StateCorrupt,
    StateError,
    StateTooLarge,
    TransientStateError,
)
from azure_sre.state.records import (
    IncidentPhase,
    IncidentRecord,
    RecoveryLedger,
    RecoveryState,
    issue_marker,
    recovery_marker,
)
from azure_sre.state.reports import ReportRef, ReportStore
from azure_sre.state.repository import FIRED_MISSING_REASON, IncidentClaim, IncidentRepository
from azure_sre.worker.messages import PoisonMessage, bind_alert
from azure_sre.worker.protocols import (
    InvestigationDeferred,
    Investigator,
    PublicationStatus,
    Publisher,
    PublishRequest,
    PublishResult,
    RecoveryRequest,
    RecoveryResult,
)
from azure_sre.worker.retry import Jitter, backoff_delay, retry_transient
from azure_sre.worker.settings import WorkerSettings

__all__ = ["DriveOutcome", "IncidentProcessor", "host_partial_report"]

_log = logging.getLogger("azure_sre.worker")
_MAX_STEPS: Final = 16
_RELEASE_TIMEOUT_SECONDS: Final = 5.0

_PRE_REPORT: Final = frozenset(
    {IncidentPhase.QUEUED, IncidentPhase.INVESTIGATING, IncidentPhase.RETRYABLE_FAILURE}
)
_PUBLISHED: Final = frozenset({IncidentPhase.PUBLISHED, IncidentPhase.PARTIAL_PUBLISHED})
_RECONCILE: Final = frozenset({IncidentPhase.PUBLISHING, IncidentPhase.PUBLICATION_UNCERTAIN})


class DriveOutcome(StrEnum):
    COMPLETED = "completed"  # terminal for now (or nothing left to do)
    DEFERRED = "deferred"  # durable state schedules the next attempt
    BUSY = "busy"  # another owner holds the lease
    LOST = "lost"  # ownership or message lock lost; work cancelled
    ABSENT = "absent"  # no such incident


def _short(key: str) -> str:
    return key[:12]


def host_partial_report(
    alert: NormalizedAlert, category: PartialCategory, now: datetime
) -> InvestigationReport:
    """Host-built partial report used once investigation attempts are exhausted."""
    return InvestigationReport(
        schema_version=1,
        incident_key=alert.incident_key,
        alert_id=alert.alert_id,
        app_id=alert.app_id,
        severity=alert.severity,
        sink=alert.sink,
        generated_at=now,
        status="partial",
        partial_category=category,
        evidence=EvidenceBundle(incident_key=alert.incident_key),
        draft=None,
        host_gaps=(
            ReportGap(
                description=(
                    "Automated investigation did not complete within the retry budget; "
                    "manual triage is required."
                ),
                category=category,
            ),
        ),
    )


class IncidentProcessor:
    """Drives one incident at a time under its lease. Safe to run on many replicas."""

    def __init__(
        self,
        *,
        repository: IncidentRepository,
        reports: ReportStore,
        investigator: Investigator,
        publisher: Publisher,
        registry: ApplicationRegistry,
        settings: WorkerSettings,
        rng: Jitter | None = None,
    ) -> None:
        self._repo = repository
        self._reports = reports
        self._investigator = investigator
        self._publisher = publisher
        self._registry = registry
        self._settings = settings
        self._rng = rng

    @property
    def settings(self) -> WorkerSettings:
        return self._settings

    def _now(self) -> datetime:
        return self._repo.clock()

    def _delay(self, attempt: int, retry_after: float | None = None) -> timedelta:
        s = self._settings
        seconds = backoff_delay(
            attempt,
            base=s.backoff_base_seconds,
            cap=s.backoff_max_seconds,
            rng=self._rng,
            retry_after=retry_after,
        )
        return timedelta(seconds=max(seconds, 1.0))

    async def record(self, alert: NormalizedAlert) -> None:
        s = self._settings
        await retry_transient(
            lambda: self._repo.record_event(alert),
            attempts=s.max_store_attempts,
            base=s.store_backoff_base_seconds,
            cap=s.store_backoff_max_seconds,
            rng=self._rng,
        )

    async def handle_alert(
        self, alert: NormalizedAlert, *, lock_lost: asyncio.Event | None = None
    ) -> DriveOutcome:
        """Durably record the (already registry-bound) alert, then drive the incident."""
        await self.record(alert)
        return await self.drive(alert.incident_key, lock_lost=lock_lost)

    def is_due(self, record: IncidentRecord, now: datetime) -> bool:
        if not record.is_active:
            return False
        if record.lease_token is not None and record.lease_held(now):
            return False
        return record.next_attempt_at is None or record.next_attempt_at <= now

    async def drive(self, key: str, *, lock_lost: asyncio.Event | None = None) -> DriveOutcome:
        loaded = await self._repo.load(key)
        if loaded is None:
            return DriveOutcome.ABSENT
        record = loaded[0]
        now = self._now()
        if not record.is_active:
            return DriveOutcome.COMPLETED
        if record.lease_token is not None and record.lease_held(now):
            return DriveOutcome.BUSY
        if record.next_attempt_at is not None and record.next_attempt_at > now:
            return DriveOutcome.DEFERRED
        claim = await self._repo.claim(
            key, owner=self._settings.owner_id, lease_seconds=self._settings.lease_seconds
        )
        if claim is None:
            return DriveOutcome.BUSY
        return await self._supervise(claim, lock_lost)

    async def _supervise(
        self, claim: IncidentClaim, lock_lost: asyncio.Event | None
    ) -> DriveOutcome:
        work = asyncio.create_task(self._run(claim), name=f"incident-{_short(claim.key)}")
        keepalive = asyncio.create_task(self._keepalive(claim))
        lost_wait = asyncio.create_task(claim.lost.wait())
        watchers: set[asyncio.Task[object]] = {work, keepalive, lost_wait}
        lock_wait: asyncio.Task[bool] | None = None
        if lock_lost is not None:
            lock_wait = asyncio.create_task(lock_lost.wait())
            watchers.add(lock_wait)
        try:
            while True:
                await asyncio.wait(watchers, return_when=asyncio.FIRST_COMPLETED)
                if work.done():
                    break
                if lost_wait.done() or (lock_wait is not None and lock_wait.done()):
                    work.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await work
                    break
                if keepalive.done():
                    watchers.discard(keepalive)
                    keepalive.result()
        finally:
            for task in (keepalive, lost_wait, lock_wait, work):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(t for t in (keepalive, lost_wait, lock_wait) if t is not None),
                return_exceptions=True,
            )
            await self._release(claim)
        reason = "claim_lost" if claim.lost.is_set() else "message_lock_lost"
        if work.cancelled():
            _log.warning("worker.work_cancelled incident=%s reason=%s", _short(claim.key), reason)
            return DriveOutcome.LOST
        exc = work.exception()
        if isinstance(exc, LeaseLost):
            _log.warning("worker.claim_lost incident=%s", _short(claim.key))
            return DriveOutcome.LOST
        if exc is not None:
            raise exc
        return work.result()

    async def _release(self, claim: IncidentClaim) -> None:
        if claim.lost.is_set():
            return
        try:
            await asyncio.wait_for(claim.release(), _RELEASE_TIMEOUT_SECONDS)
        except (StateError, TimeoutError) as exc:
            _log.warning(
                "worker.release_failed incident=%s error=%s", _short(claim.key), type(exc).__name__
            )

    async def _keepalive(self, claim: IncidentClaim) -> None:
        s = self._settings
        while not claim.lost.is_set():
            await asyncio.sleep(s.renew_interval_seconds)
            try:
                await claim.renew()
            except LeaseLost:
                claim.lost.set()
                return
            except TransientStateError:
                if claim.remaining_seconds() <= s.lease_safety_margin_seconds:
                    _log.warning("worker.renew_exhausted incident=%s", _short(claim.key))
                    claim.lost.set()
                    return
            except StateError as exc:
                _log.error("worker.renew_failed incident=%s error=%s", _short(claim.key), exc.code)
                claim.lost.set()
                return

    # ------------------------------------------------------------------ state machine

    async def _run(self, claim: IncidentClaim) -> DriveOutcome:
        for _ in range(_MAX_STEPS):
            try:
                outcome = await self._step(claim)
            except StaleTransition:
                continue
            if outcome is not None:
                return outcome
        _log.error("worker.step_budget_exhausted incident=%s", _short(claim.key))
        return DriveOutcome.DEFERRED

    async def _step(self, claim: IncidentClaim) -> DriveOutcome | None:
        rec = claim.record
        now = self._now()
        if not rec.is_active:
            return DriveOutcome.COMPLETED
        if rec.next_attempt_at is not None and rec.next_attempt_at > now:
            return DriveOutcome.DEFERRED
        if rec.phase is IncidentPhase.PENDING_FIRED:
            return await self._pending_fired(claim, now)
        assert rec.fired is not None  # noqa: S101 - enforced by IncidentRecord invariants
        if rec.phase in _PUBLISHED:
            return await self._recovery(claim)
        try:
            alert = bind_alert(rec.fired, self._registry)
        except PoisonMessage:
            return await self._operator(claim, "registry_mismatch")
        if rec.report_blob is None:
            if rec.phase not in _PRE_REPORT:
                return await self._operator(claim, "invalid_phase")
            return await self._investigate(claim, alert)
        if alert.sink is Sink.TEST:
            # Test sink: the investigated report is persisted; the publisher is never invoked.
            if rec.phase is not IncidentPhase.REPORT_PERSISTED:
                return await self._operator(claim, "invalid_phase")
            await claim.update(
                lambda r: r.evolve(phase=IncidentPhase.TEST_SINK_SUPPRESSED, next_attempt_at=None),
                expect={IncidentPhase.REPORT_PERSISTED},
            )
            _log.info("worker.test_sink_completed incident=%s", _short(rec.incident_key))
            return DriveOutcome.COMPLETED
        if rec.phase in _RECONCILE:
            return await self._reconcile_publication(claim, alert)
        if rec.phase in (IncidentPhase.REPORT_PERSISTED, IncidentPhase.RETRYABLE_FAILURE):
            return await self._publish(claim, alert)
        return await self._operator(claim, "invalid_phase")

    def _route(self, alert: NormalizedAlert) -> tuple[Publisher, str] | None:
        """Only the production sink is ever routed to the publisher."""
        if alert.sink is Sink.PRODUCTION:
            return self._publisher, alert.repository
        return None

    async def _operator(self, claim: IncidentClaim, reason: str) -> DriveOutcome:
        await claim.update(
            lambda r: r.evolve(
                phase=IncidentPhase.OPERATOR_REQUIRED, operator_reason=reason, next_attempt_at=None
            )
        )
        _log.error("worker.operator_required incident=%s reason=%s", _short(claim.key), reason)
        return DriveOutcome.COMPLETED

    async def _pending_fired(self, claim: IncidentClaim, now: datetime) -> DriveOutcome:
        rec = claim.record
        deadline = rec.created_at + timedelta(seconds=self._settings.fired_grace_seconds)
        if now >= deadline:
            # A Resolved without its Fired: never invent the fired time; operator decides.
            await claim.update(
                lambda r: r.evolve(
                    phase=IncidentPhase.OPERATOR_REQUIRED,
                    operator_reason=FIRED_MISSING_REASON,
                    next_attempt_at=None,
                ),
                expect={IncidentPhase.PENDING_FIRED},
            )
            _log.error("worker.fired_missing incident=%s", _short(claim.key))
            return DriveOutcome.COMPLETED
        await claim.update(
            lambda r: r.evolve(next_attempt_at=deadline), expect={IncidentPhase.PENDING_FIRED}
        )
        return DriveOutcome.DEFERRED

    # ------------------------------------------------------------------ investigation

    async def _investigate(
        self, claim: IncidentClaim, alert: NormalizedAlert
    ) -> DriveOutcome | None:
        s = self._settings
        orphan = await self._reports.find(alert.incident_key)
        if orphan is not None:
            _log.info("worker.report_adopted incident=%s", _short(alert.incident_key))
            await self._mark_persisted(claim, orphan)
            return None
        rec = claim.record
        if rec.investigation_attempts >= s.max_investigation_attempts:
            fallback = _category(rec.failure_category)
            await self._persist(claim, host_partial_report(alert, fallback, self._now()))
            return None
        await claim.update(
            lambda r: r.evolve(
                phase=IncidentPhase.INVESTIGATING,
                investigation_attempts=r.investigation_attempts + 1,
                failure_category=None,
                next_attempt_at=None,
            ),
            expect=_PRE_REPORT,
        )
        retry_after: float | None = None
        category: PartialCategory | None = None
        report: InvestigationReport | None = None
        try:
            report = await asyncio.wait_for(
                self._investigator.run(alert), s.investigation_timeout_seconds
            )
        except TimeoutError:
            category = PartialCategory.TIMEOUT
        except InvestigationDeferred as deferred:
            category, retry_after = deferred.category, deferred.retry_after_seconds
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - classified; type name only is logged
            _log.warning(
                "worker.investigation_failed incident=%s error=%s",
                _short(alert.incident_key),
                type(exc).__name__,
            )
            category = PartialCategory.SDK_ERROR
        if report is not None:
            report = _checked_report(report, alert)
            if report is None:
                category = PartialCategory.INVALID_REPORT
        if report is not None:
            try:
                await self._persist(claim, report)
                return None
            except (StateCorrupt, StateTooLarge) as exc:
                _log.warning(
                    "worker.report_rejected incident=%s code=%s",
                    _short(alert.incident_key),
                    exc.code,
                )
                category = PartialCategory.INVALID_REPORT
        assert category is not None  # noqa: S101
        attempts = claim.record.investigation_attempts
        exhausted = attempts >= s.max_investigation_attempts
        next_at = None if exhausted else self._now() + self._delay(attempts, retry_after)
        await claim.update(
            lambda r: r.evolve(
                phase=IncidentPhase.RETRYABLE_FAILURE,
                failure_category=category.value,
                next_attempt_at=next_at,
            ),
            expect={IncidentPhase.INVESTIGATING},
        )
        return None if exhausted else DriveOutcome.DEFERRED

    async def _persist(self, claim: IncidentClaim, report: InvestigationReport) -> None:
        s = self._settings
        token = uuid.uuid4().hex
        ref = await retry_transient(
            lambda: self._reports.put(claim.key, token, report),
            attempts=s.max_store_attempts,
            base=s.store_backoff_base_seconds,
            cap=s.store_backoff_max_seconds,
            rng=self._rng,
        )
        await self._mark_persisted(claim, ref)

    async def _mark_persisted(self, claim: IncidentClaim, ref: ReportRef) -> None:
        await claim.update(
            lambda r: r.evolve(
                phase=IncidentPhase.REPORT_PERSISTED,
                report_blob=ref.name,
                report_sha256=ref.sha256,
                report_status=ref.status,
                failure_category=None,
                next_attempt_at=None,
            ),
            expect=_PRE_REPORT,
        )

    # ------------------------------------------------------------------ publication

    async def _load_report(self, claim: IncidentClaim) -> InvestigationReport | None:
        rec = claim.record
        assert rec.report_blob and rec.report_sha256 and rec.report_status  # noqa: S101
        ref = ReportRef(rec.report_blob, rec.report_sha256, rec.report_status)
        try:
            return await self._reports.get(ref, claim.key)
        except ReportUnavailable as exc:
            _log.error("worker.report_unavailable incident=%s code=%s", _short(claim.key), exc.code)
            return None

    async def _request(
        self, claim: IncidentClaim, alert: NormalizedAlert
    ) -> tuple[Publisher, PublishRequest] | str:
        route = self._route(alert)
        if route is None:
            return "test_sink_unrouted"
        report = await self._load_report(claim)
        if report is None:
            return "report_unavailable"
        publisher, repository = route
        try:
            request = PublishRequest(
                alert=alert,
                report=report,
                repository=repository,
                sink=alert.sink,
                marker=issue_marker(claim.key),
                attempt=max(claim.record.publish_attempts, 1),
            )
        except (ContractError, ValidationError):
            return "invalid_publication"
        return publisher, request

    async def _ensure_publish_window(self, claim: IncidentClaim) -> None:
        await claim.renew()
        s = self._settings
        if claim.remaining_seconds() < s.publish_timeout_seconds + s.lease_safety_margin_seconds:
            claim.lost.set()
            raise LeaseLost()

    async def _publish(self, claim: IncidentClaim, alert: NormalizedAlert) -> DriveOutcome | None:
        s = self._settings
        if claim.record.publish_attempts >= s.max_publish_attempts:
            return await self._operator(claim, "publish_attempts_exhausted")
        prepared = await self._request(claim, alert)
        if isinstance(prepared, str):
            return await self._operator(claim, prepared)
        publisher, _ = prepared
        await self._ensure_publish_window(claim)
        now = self._now()
        rec = await claim.update(
            lambda r: r.evolve(
                phase=IncidentPhase.PUBLISHING,
                publish_marker=issue_marker(r.incident_key),
                publish_intent_at=now,
                publish_attempts=r.publish_attempts + 1,
                reconcile_attempts=0,
                failure_category=None,
                next_attempt_at=None,
            ),
            expect={IncidentPhase.REPORT_PERSISTED, IncidentPhase.RETRYABLE_FAILURE},
        )
        request = prepared[1].model_copy(update={"attempt": rec.publish_attempts})
        result = await self._call(publisher.publish(request))
        return await self._apply_publish(claim, request, result, reconciling=False)

    async def _reconcile_publication(
        self, claim: IncidentClaim, alert: NormalizedAlert
    ) -> DriveOutcome | None:
        s = self._settings
        if claim.record.reconcile_attempts >= s.max_reconcile_attempts:
            return await self._operator(claim, "publication_uncertain")
        prepared = await self._request(claim, alert)
        if isinstance(prepared, str):
            return await self._operator(claim, prepared)
        publisher, request = prepared
        await self._ensure_publish_window(claim)
        await claim.update(
            lambda r: r.evolve(
                phase=IncidentPhase.PUBLICATION_UNCERTAIN,
                reconcile_attempts=r.reconcile_attempts + 1,
            ),
            expect=_RECONCILE,
        )
        result = await self._call(publisher.reconcile(request))
        return await self._apply_publish(claim, request, result, reconciling=True)

    async def _call[R: (PublishResult, RecoveryResult)](self, call: Awaitable[R]) -> R | None:
        """Await a publisher call with the publish timeout; any failure means 'unknown'."""
        try:
            return await asyncio.wait_for(call, self._settings.publish_timeout_seconds)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - outcome unknown; never assume success/absence
            _log.warning("worker.publisher_call_failed error=%s", type(exc).__name__)
            return None

    async def _apply_publish(
        self,
        claim: IncidentClaim,
        request: PublishRequest,
        result: PublishResult | None,
        *,
        reconciling: bool,
    ) -> DriveOutcome | None:
        now = self._now()
        status = PublicationStatus.UNCERTAIN if result is None else result.status
        if result is not None and status is PublicationStatus.PUBLISHED:
            record = result.record
            assert record is not None  # noqa: S101 - enforced by PublishResult
            if (
                record.repository.lower() != request.repository.lower()
                or record.incident_key != claim.key
                or record.marker != request.marker
            ):
                _log.error("worker.publication_mismatch incident=%s", _short(claim.key))
                status = PublicationStatus.UNCERTAIN
            else:
                phase = (
                    IncidentPhase.PUBLISHED
                    if request.report.status == "complete"
                    else IncidentPhase.PARTIAL_PUBLISHED
                )
                # Recording an observed fact: CAS still proves no other owner intervened.
                await claim.update(
                    lambda r: r.evolve(
                        phase=phase,
                        publication=record,
                        failure_category=None,
                        next_attempt_at=None,
                        reconcile_attempts=0,
                    ),
                    expect=_RECONCILE,
                    require_live=False,
                )
                _log.info("worker.published incident=%s", _short(claim.key))
                return None
        reason = (result.reason if result is not None else None) or status.value
        if status is PublicationStatus.ABSENT and result is not None:
            intent_at = claim.record.publish_intent_at or now
            settled = now - intent_at >= timedelta(seconds=self._settings.not_found_settle_seconds)
            if not reconciling and not result.retryable:
                await claim.update(
                    lambda r: r.evolve(
                        phase=IncidentPhase.OPERATOR_REQUIRED,
                        operator_reason=reason,
                        next_attempt_at=None,
                    ),
                    expect=_RECONCILE,
                    require_live=False,
                )
                return DriveOutcome.COMPLETED
            if not reconciling or settled:
                attempts = claim.record.publish_attempts
                next_at = now + self._delay(attempts, result.retry_after_seconds)
                await claim.update(
                    lambda r: r.evolve(
                        phase=IncidentPhase.RETRYABLE_FAILURE,
                        failure_category=reason,
                        publish_intent_at=None,
                        next_attempt_at=next_at,
                    ),
                    expect=_RECONCILE,
                    require_live=False,
                )
                return DriveOutcome.DEFERRED
            settle_at = intent_at + timedelta(seconds=self._settings.not_found_settle_seconds)
            next_at = min(settle_at, now + self._delay(claim.record.reconcile_attempts))
        else:
            retry_after = result.retry_after_seconds if result is not None else None
            next_at = now + self._delay(max(claim.record.reconcile_attempts, 1), retry_after)
        await claim.update(
            lambda r: r.evolve(
                phase=IncidentPhase.PUBLICATION_UNCERTAIN,
                failure_category=reason,
                next_attempt_at=next_at,
            ),
            expect=_RECONCILE,
            require_live=False,
        )
        _log.warning("worker.publication_uncertain incident=%s", _short(claim.key))
        return DriveOutcome.DEFERRED

    # ------------------------------------------------------------------ recovery

    async def _recovery(self, claim: IncidentClaim) -> DriveOutcome | None:
        rec = claim.record
        s = self._settings
        assert rec.resolved is not None and rec.publication is not None  # noqa: S101
        ledger = await claim.recovery_ledger()
        marker = recovery_marker(claim.key)
        if ledger is not None and ledger.state is RecoveryState.COMMENTED:
            await self._recovery_done(claim, ledger)
            return DriveOutcome.COMPLETED
        if ledger is not None and ledger.state is RecoveryState.OPERATOR_REQUIRED:
            await claim.update(lambda r: r.evolve(recovery_blocked=True, next_attempt_at=None))
            return DriveOutcome.COMPLETED
        try:
            resolved = bind_alert(rec.resolved, self._registry)
        except PoisonMessage:
            return await self._recovery_blocked(claim, "registry_mismatch")
        route = self._route(resolved)
        if route is None:
            return await self._recovery_blocked(claim, "test_sink_unrouted")
        publisher = route[0]
        writing = ledger is not None and ledger.state in (
            RecoveryState.WRITING,
            RecoveryState.UNCERTAIN,
        )
        attempts = 0 if ledger is None else ledger.attempts
        reconciles = 0 if ledger is None else ledger.reconcile_attempts
        if writing and reconciles >= s.max_reconcile_attempts:
            return await self._recovery_blocked(claim, "recovery_uncertain")
        if not writing and attempts >= s.max_publish_attempts:
            return await self._recovery_blocked(claim, "recovery_attempts_exhausted")
        await self._ensure_publish_window(claim)
        now = self._now()

        def mark(current: RecoveryLedger | None) -> RecoveryLedger:
            if writing:
                assert current is not None  # noqa: S101
                return current.evolve(
                    state=RecoveryState.UNCERTAIN,
                    reconcile_attempts=current.reconcile_attempts + 1,
                )
            base = current or RecoveryLedger(
                incident_key=claim.key, marker=marker, state=RecoveryState.PENDING, updated_at=now
            )
            return base.evolve(
                state=RecoveryState.WRITING,
                attempts=base.attempts + 1,
                reconcile_attempts=0,
                intent_at=now,
                reason=None,
            )

        await claim.update(
            lambda r: r.evolve(next_attempt_at=None), expect=_PUBLISHED, recovery=mark
        )
        current = await claim.recovery_ledger()
        assert current is not None  # noqa: S101
        try:
            request = RecoveryRequest(
                incident_key=claim.key,
                resolved=resolved,
                publication=rec.publication,
                marker=marker,
                attempt=current.attempts,
            )
        except (ContractError, ValidationError):
            return await self._recovery_blocked(claim, "invalid_recovery")
        call = publisher.reconcile_recovery(request) if writing else publisher.recover(request)
        result = await self._call(call)
        return await self._apply_recovery(claim, current, result, reconciling=writing)

    async def _apply_recovery(
        self,
        claim: IncidentClaim,
        ledger: RecoveryLedger,
        result: RecoveryResult | None,
        *,
        reconciling: bool,
    ) -> DriveOutcome | None:
        now = self._now()
        status = PublicationStatus.UNCERTAIN if result is None else result.status
        reason = (result.reason if result is not None else None) or status.value
        if result is not None and result.comment_id is not None:
            comment_id = result.comment_id
            await claim.update(
                lambda r: r,
                require_live=False,
                recovery=lambda c: _require(c).evolve(
                    state=RecoveryState.COMMENTED, comment_id=comment_id, reason=None
                ),
            )
            done = await claim.recovery_ledger()
            assert done is not None  # noqa: S101
            await self._recovery_done(claim, done)
            return DriveOutcome.COMPLETED
        retry_after = result.retry_after_seconds if result is not None else None
        settle = timedelta(seconds=self._settings.not_found_settle_seconds)
        intent_at = ledger.intent_at or now
        if status is PublicationStatus.ABSENT and result is not None:
            if not reconciling and not result.retryable:
                return await self._recovery_blocked(claim, reason, require_live=False)
            if not reconciling or now - intent_at >= settle:
                next_at = now + self._delay(ledger.attempts, retry_after)
                await claim.update(
                    lambda r: r.evolve(next_attempt_at=next_at),
                    require_live=False,
                    recovery=lambda c: _require(c).evolve(
                        state=RecoveryState.PENDING, intent_at=None, reason=reason
                    ),
                )
                return DriveOutcome.DEFERRED
            next_at = min(intent_at + settle, now + self._delay(ledger.reconcile_attempts))
        else:
            next_at = now + self._delay(max(ledger.reconcile_attempts, 1), retry_after)
        await claim.update(
            lambda r: r.evolve(next_attempt_at=next_at),
            require_live=False,
            recovery=lambda c: _require(c).evolve(state=RecoveryState.UNCERTAIN, reason=reason),
        )
        return DriveOutcome.DEFERRED

    async def _recovery_done(self, claim: IncidentClaim, ledger: RecoveryLedger) -> None:
        comment_id = ledger.comment_id

        def mutate(r: IncidentRecord) -> IncidentRecord:
            publication = r.publication
            if publication is not None and comment_id is not None:
                publication = publication.model_copy(update={"recovery_comment_id": comment_id})
            return r.evolve(recovery_done=True, publication=publication, next_attempt_at=None)

        await claim.update(mutate, require_live=False)

    async def _recovery_blocked(
        self, claim: IncidentClaim, reason: str, *, require_live: bool = True
    ) -> DriveOutcome:
        now = self._now()

        def block(current: RecoveryLedger | None) -> RecoveryLedger:
            base = current or RecoveryLedger(
                incident_key=claim.key,
                marker=recovery_marker(claim.key),
                state=RecoveryState.PENDING,
                updated_at=now,
            )
            return base.evolve(state=RecoveryState.OPERATOR_REQUIRED, reason=reason)

        await claim.update(
            lambda r: r.evolve(recovery_blocked=True, next_attempt_at=None),
            require_live=require_live,
            recovery=block,
        )
        _log.error("worker.recovery_blocked incident=%s reason=%s", _short(claim.key), reason)
        return DriveOutcome.COMPLETED


def _require(ledger: RecoveryLedger | None) -> RecoveryLedger:
    if ledger is None:
        raise StateCorrupt("recovery_ledger_missing")
    return ledger


def _category(code: str | None) -> PartialCategory:
    try:
        return PartialCategory(code) if code else PartialCategory.SDK_ERROR
    except ValueError:
        return PartialCategory.SDK_ERROR


def _checked_report(
    report: InvestigationReport, alert: NormalizedAlert
) -> InvestigationReport | None:
    """Re-validate the investigator's report and bind it to the Fired snapshot."""
    try:
        validated = InvestigationReport.model_validate_json(report.model_dump_json())
    except (ValidationError, ContractError):
        return None
    if (
        validated.incident_key != alert.incident_key
        or validated.alert_id != alert.alert_id
        or validated.app_id != alert.app_id
        or validated.severity != alert.severity
        or validated.sink != alert.sink
    ):
        return None
    return validated
