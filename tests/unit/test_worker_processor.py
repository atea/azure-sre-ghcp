"""Incident processor: lifecycle, ownership, investigation-once and publication safety."""

from __future__ import annotations

import asyncio

import pytest

from azure_sre.contracts import PartialCategory, Sink
from azure_sre.state import (
    FIRED_MISSING_REASON,
    IncidentPhase,
    IncidentRecord,
    RecoveryState,
    TransientStateError,
)
from azure_sre.worker import (
    DriveOutcome,
    InvestigationDeferred,
    PublicationStatus,
    PublishResult,
    RecoveryResult,
    WorkerSettings,
)
from azure_sre.worker.processor import IncidentProcessor
from tests.unit.test_worker_support import (
    REGISTRY,
    Harness,
    complete_report,
    eventually,
    make_alert,
    make_registry,
    published_record,
)

FIRED = make_alert()
RESOLVED = make_alert("Resolved")
KEY = FIRED.incident_key


async def state(h: Harness) -> IncidentRecord:
    loaded = await h.repo.load(KEY)
    assert loaded is not None
    return loaded[0]


async def test_fired_is_investigated_once_and_published() -> None:
    h = Harness()
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.COMPLETED
    rec = await state(h)
    assert rec.phase is IncidentPhase.PUBLISHED and rec.lease_token is None
    assert rec.publication is not None and rec.publication.repository == "contoso/shop"
    assert h.investigator.calls == 1 and len(h.publisher.publish_calls) == 1
    request = h.publisher.publish_calls[0]
    assert request.alert.monitor_condition.value == "Fired" and request.marker.endswith(KEY)
    # Redelivery and a repeated Fired never investigate or publish again.
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.COMPLETED
    assert h.investigator.calls == 1 and len(h.publisher.publish_calls) == 1


async def test_competing_workers_investigate_at_most_once() -> None:
    h = Harness()
    gate = asyncio.Event()

    async def slow(alert: object) -> object:
        await gate.wait()
        return complete_report(FIRED)

    h.investigator.behavior = slow  # type: ignore[assignment]
    other = h.make_processor(h.settings.model_copy(update={"owner_id": "worker-b"}))
    first = asyncio.create_task(h.processor.handle_alert(FIRED))
    await h.investigator.started.wait()
    assert await other.handle_alert(FIRED) is DriveOutcome.BUSY
    gate.set()
    assert await first is DriveOutcome.COMPLETED
    assert h.investigator.calls == 1 and len(h.publisher.publish_calls) == 1


async def test_resolved_then_recovery_comment_once_with_separate_marker() -> None:
    h = Harness()
    await h.processor.handle_alert(FIRED)
    assert await h.processor.handle_alert(RESOLVED) is DriveOutcome.COMPLETED
    rec = await state(h)
    assert rec.recovery_done and rec.publication is not None
    assert rec.publication.recovery_comment_id == 99 and not rec.is_active
    ledger = await h.repo.load_recovery(KEY)
    assert ledger is not None and ledger[0].state is RecoveryState.COMMENTED
    assert ledger[0].marker != rec.publish_marker
    await h.processor.handle_alert(RESOLVED)
    assert len(h.publisher.recover_calls) == 1


async def test_early_resolved_is_preserved_until_fired_arrives() -> None:
    h = Harness()
    assert await h.processor.handle_alert(RESOLVED) is DriveOutcome.DEFERRED
    rec = await state(h)
    assert rec.phase is IncidentPhase.PENDING_FIRED and rec.fired is None
    assert h.investigator.calls == 0
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.COMPLETED
    rec = await state(h)
    assert rec.phase is IncidentPhase.PUBLISHED and rec.recovery_done
    assert h.investigator.calls == 1
    # The investigation used the Fired snapshot, never a fired time from Resolved.
    assert h.publisher.publish_calls[0].alert == FIRED


async def test_fired_missing_after_grace_needs_operator() -> None:
    h = Harness()
    await h.processor.handle_alert(RESOLVED)
    h.clock.advance(h.settings.fired_grace_seconds + 1)
    assert await h.processor.drive(KEY) is DriveOutcome.COMPLETED
    rec = await state(h)
    assert rec.phase is IncidentPhase.OPERATOR_REQUIRED
    assert rec.operator_reason == FIRED_MISSING_REASON and h.investigator.calls == 0
    # A late Fired still recovers the incident.
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.COMPLETED
    assert (await state(h)).phase is IncidentPhase.PUBLISHED


async def test_test_sink_investigates_persists_and_never_publishes() -> None:
    h = Harness()
    alert = make_alert(sink=Sink.TEST)
    assert await h.processor.handle_alert(alert) is DriveOutcome.COMPLETED
    rec = await state(h)
    assert rec.phase is IncidentPhase.TEST_SINK_SUPPRESSED
    assert rec.report_blob is not None and h.investigator.calls == 1
    assert h.reports.blobs
    await h.processor.handle_alert(make_alert("Resolved", sink=Sink.TEST))
    assert h.publisher.publish_calls == [] and h.publisher.recover_calls == []
    assert h.publisher.reconcile_calls == []


async def test_message_lock_lost_cancels_before_publication() -> None:
    h = Harness()
    lock_lost = asyncio.Event()

    async def hang(alert: object) -> object:
        lock_lost.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    h.investigator.behavior = hang  # type: ignore[assignment]
    assert await h.processor.handle_alert(FIRED, lock_lost=lock_lost) is DriveOutcome.LOST
    rec = await state(h)
    assert h.investigator.cancelled == 1 and h.publisher.publish_calls == []
    assert rec.phase is IncidentPhase.INVESTIGATING and rec.lease_token is None


async def test_state_lease_stolen_cancels_and_never_records_success() -> None:
    h = Harness()

    async def stall(alert: object) -> object:
        h.clock.advance(h.settings.lease_seconds + 1)
        thief = await h.repo.claim(KEY, owner="thief", lease_seconds=600)
        assert thief is not None
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    h.investigator.behavior = stall  # type: ignore[assignment]
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.LOST
    rec = await state(h)
    assert rec.lease_owner == "thief" and rec.report_blob is None
    assert h.publisher.publish_calls == [] and h.investigator.cancelled == 1


async def test_state_renewal_failure_cancels_work() -> None:
    h = Harness()

    async def hang(alert: object) -> object:
        h.clock.advance(h.settings.lease_seconds - 1)

        def fail(_pk: str, _ops: object) -> None:
            raise TransientStateError()

        h.store.faults.extend([fail] * 50)
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    h.investigator.behavior = hang  # type: ignore[assignment]
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.LOST
    assert h.investigator.cancelled == 1 and h.publisher.publish_calls == []


async def test_persisted_report_resumes_without_reinvestigation() -> None:
    h = Harness()
    h.publisher.publish_results.append(
        PublishResult(
            status=PublicationStatus.ABSENT, reason="rate_limited", retry_after_seconds=60
        )
    )
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.DEFERRED
    rec = await state(h)
    assert rec.phase is IncidentPhase.RETRYABLE_FAILURE and rec.report_blob is not None
    assert rec.next_attempt_at is not None
    assert await h.processor.drive(KEY) is DriveOutcome.DEFERRED  # not yet due
    h.clock.advance(3600)
    assert await h.processor.drive(KEY) is DriveOutcome.COMPLETED
    assert h.investigator.calls == 1 and len(h.publisher.publish_calls) == 2


async def test_orphaned_report_from_crash_is_adopted() -> None:
    h = Harness()
    await h.repo.record_event(FIRED)
    await h.reports.put(KEY, "c" * 32, complete_report(FIRED))
    assert await h.processor.drive(KEY) is DriveOutcome.COMPLETED
    assert h.investigator.calls == 0 and (await state(h)).phase is IncidentPhase.PUBLISHED


async def test_publish_uncertain_reconciles_and_never_blind_creates() -> None:
    h = Harness()
    h.publisher.publish_results.append(TimeoutError())
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.DEFERRED
    rec = await state(h)
    assert rec.phase is IncidentPhase.PUBLICATION_UNCERTAIN and rec.publish_intent_at is not None
    # The write actually happened remotely; reconciliation finds it by marker.
    h.publisher.issues[rec.publish_marker or ""] = published_record(h.publisher.publish_calls[0])
    h.clock.advance(h.settings.backoff_max_seconds + 1)
    assert await h.processor.drive(KEY) is DriveOutcome.COMPLETED
    assert len(h.publisher.publish_calls) == 1 and len(h.publisher.reconcile_calls) == 1
    assert (await state(h)).phase is IncidentPhase.PUBLISHED


async def test_not_found_during_settle_window_stays_uncertain() -> None:
    h = Harness(not_found_settle_seconds=600.0, backoff_max_seconds=60.0)
    h.publisher.publish_results.append(PublishResult(status=PublicationStatus.UNCERTAIN))
    await h.processor.handle_alert(FIRED)
    h.clock.advance(61)
    assert await h.processor.drive(KEY) is DriveOutcome.DEFERRED
    rec = await state(h)
    assert rec.phase is IncidentPhase.PUBLICATION_UNCERTAIN
    assert len(h.publisher.publish_calls) == 1
    h.clock.advance(600)
    assert await h.processor.drive(KEY) is DriveOutcome.DEFERRED  # settled ABSENT -> retryable
    assert (await state(h)).phase is IncidentPhase.RETRYABLE_FAILURE
    h.clock.advance(3600)
    assert await h.processor.drive(KEY) is DriveOutcome.COMPLETED
    assert len(h.publisher.publish_calls) == 2


async def test_crash_mid_publish_only_reconciles() -> None:
    h = Harness()
    h.publisher.publish_gate = asyncio.Event()
    task = asyncio.create_task(h.processor.handle_alert(FIRED))
    await eventually(lambda: bool(h.publisher.publish_calls))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    rec = await state(h)
    assert rec.phase is IncidentPhase.PUBLISHING
    h.publisher.publish_gate = None
    h.publisher.reconcile_results.append(PublishResult(status=PublicationStatus.UNCERTAIN))
    assert await h.processor.drive(KEY) is DriveOutcome.DEFERRED
    assert len(h.publisher.publish_calls) == 1
    assert (await state(h)).phase is IncidentPhase.PUBLICATION_UNCERTAIN


async def test_reconcile_budget_exhaustion_needs_operator() -> None:
    h = Harness(max_reconcile_attempts=2, backoff_max_seconds=10.0, backoff_base_seconds=1.0)
    h.publisher.publish_results.append(RuntimeError("boom"))
    h.publisher.reconcile_results.extend([PublishResult(status=PublicationStatus.UNCERTAIN)] * 5)
    await h.processor.handle_alert(FIRED)
    for _ in range(3):
        h.clock.advance(11)
        await h.processor.drive(KEY)
    rec = await state(h)
    assert rec.phase is IncidentPhase.OPERATOR_REQUIRED
    assert rec.operator_reason == "publication_uncertain"
    assert len(h.publisher.publish_calls) == 1


async def test_mismatched_publication_record_is_not_accepted() -> None:
    h = Harness()
    request_holder: list[object] = []

    async def wrong(request: object) -> PublishResult:
        request_holder.append(request)
        return PublishResult(
            status=PublicationStatus.PUBLISHED,
            record=published_record(request.model_copy(update={"repository": "evil/repo"})),  # type: ignore[attr-defined]
        )

    h.publisher.publish = wrong  # type: ignore[method-assign]
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.DEFERRED
    assert (await state(h)).phase is IncidentPhase.PUBLICATION_UNCERTAIN


async def test_non_retryable_absent_needs_operator() -> None:
    h = Harness()
    h.publisher.publish_results.append(
        PublishResult(status=PublicationStatus.ABSENT, retryable=False, reason="forbidden")
    )
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.COMPLETED
    rec = await state(h)
    assert rec.phase is IncidentPhase.OPERATOR_REQUIRED and rec.operator_reason == "forbidden"


async def test_investigation_failures_are_bounded_then_host_partial_published() -> None:
    h = Harness(max_investigation_attempts=2)

    async def fail(alert: object) -> object:
        raise InvestigationDeferred(PartialCategory.RATE_LIMITED, retry_after_seconds=30)

    h.investigator.behavior = fail  # type: ignore[assignment]
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.DEFERRED
    rec = await state(h)
    assert rec.phase is IncidentPhase.RETRYABLE_FAILURE and rec.failure_category == "rate_limited"
    h.clock.advance(3600)
    assert await h.processor.drive(KEY) is DriveOutcome.COMPLETED
    rec = await state(h)
    assert rec.phase is IncidentPhase.PARTIAL_PUBLISHED and h.investigator.calls == 2
    report = h.publisher.publish_calls[0].report
    assert report.draft is None and report.partial_category is PartialCategory.RATE_LIMITED


async def test_invalid_or_mismatched_report_is_retried_not_published() -> None:
    h = Harness(max_investigation_attempts=3)
    other = make_alert(alert_id=FIRED.alert_id + "-other")

    async def wrong(alert: object) -> object:
        return complete_report(other)

    h.investigator.behavior = wrong  # type: ignore[assignment]
    assert await h.processor.handle_alert(FIRED) is DriveOutcome.DEFERRED
    rec = await state(h)
    assert rec.failure_category == "invalid_report" and h.publisher.publish_calls == []


async def test_credential_shaped_report_is_never_persisted() -> None:
    h = Harness(max_investigation_attempts=1)

    async def leaky(alert: object) -> object:
        return complete_report(FIRED, summary="ghp_ABCDEFGHIJKLMNOPQRSTUV")

    h.investigator.behavior = leaky  # type: ignore[assignment]
    await h.processor.handle_alert(FIRED)
    published = h.publisher.publish_calls[0].report
    assert published.draft is None and published.partial_category is PartialCategory.INVALID_REPORT
    assert all(b"ghp_" not in blob for blob in h.reports.blobs.values())


async def test_registry_drift_requires_operator_instead_of_rerouting() -> None:
    h = Harness()
    await h.repo.record_event(FIRED)
    drifted = h.make_processor(h.settings, registry=make_registry(repository="contoso/other"))
    assert await drifted.drive(KEY) is DriveOutcome.COMPLETED
    rec = await state(h)
    assert rec.phase is IncidentPhase.OPERATOR_REQUIRED
    assert rec.operator_reason == "registry_mismatch" and h.publisher.publish_calls == []


async def test_recovery_uncertain_reconciles_by_marker() -> None:
    h = Harness()
    await h.processor.handle_alert(FIRED)
    h.publisher.recover_results.append(TimeoutError())
    assert await h.processor.handle_alert(RESOLVED) is DriveOutcome.DEFERRED
    ledger = await h.repo.load_recovery(KEY)
    assert ledger is not None and ledger[0].state is RecoveryState.UNCERTAIN
    h.publisher.reconcile_recovery_results.append(
        RecoveryResult(status=PublicationStatus.PUBLISHED, comment_id=5)
    )
    h.clock.advance(h.settings.backoff_max_seconds + 1)
    assert await h.processor.drive(KEY) is DriveOutcome.COMPLETED
    assert len(h.publisher.recover_calls) == 1
    rec = await state(h)
    assert rec.recovery_done and rec.publication is not None
    assert rec.publication.recovery_comment_id == 5


async def test_settings_bind_budget_and_cap_concurrency() -> None:
    from types import SimpleNamespace
    from typing import Any

    from azure_sre.config import BudgetPolicy

    config: Any = SimpleNamespace(budget=BudgetPolicy(), registry=REGISTRY)
    settings = WorkerSettings.from_config(config)
    assert settings.concurrency == config.budget.concurrency_per_replica <= 2
    with pytest.raises(ValueError):
        WorkerSettings.from_config(config, concurrency=2)
    with pytest.raises(ValueError):
        WorkerSettings(concurrency=3)
    with pytest.raises(ValueError):
        WorkerSettings(lease_seconds=20, renew_interval_seconds=15)
    with pytest.raises(ValueError):
        WorkerSettings(publish_timeout_seconds=58)


def test_processor_is_constructed_without_test_publisher() -> None:
    import inspect

    assert "test_publisher" not in inspect.signature(IncidentProcessor).parameters
