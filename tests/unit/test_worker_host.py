"""Worker host: settlement, poison handling, concurrency bounds and graceful stop."""

from __future__ import annotations

import asyncio
import json

import pytest

from azure_sre.state import IncidentPhase, TransientStateError
from azure_sre.worker import (
    PoisonReason,
    PublicationStatus,
    PublishResult,
    WorkerFatalError,
    WorkerHost,
)
from tests.unit.test_worker_support import (
    REGISTRY,
    FakeMessage,
    FakeSource,
    FixedRng,
    Harness,
    complete_report,
    eventually,
    make_alert,
    make_registry,
)

FIRED = make_alert()


def host_for(h: Harness, source: FakeSource, *, reconcile: bool = False) -> WorkerHost:
    return WorkerHost(
        source=source,  # type: ignore[arg-type]
        processor=h.processor,
        repository=h.repo,
        registry=REGISTRY,
        settings=h.settings,
        rng=FixedRng(),
        reconcile=reconcile,
    )


async def run_until_drained(host: WorkerHost, source: FakeSource) -> None:
    task = asyncio.create_task(host.run())
    await asyncio.wait_for(source.drained.wait(), 5)
    await eventually(lambda: host.active == 0)
    host.request_stop()
    await asyncio.wait_for(task, 5)


async def test_message_completed_after_durable_handling() -> None:
    h = Harness()
    message = FakeMessage.of(FIRED)
    source = FakeSource([message, FakeMessage.of(FIRED, delivery_count=2)])
    host = host_for(h, source)
    await run_until_drained(host, source)
    assert message.settled == ["complete"]
    assert h.investigator.calls == 1 and len(h.publisher.publish_calls) == 1
    assert source.closed is False  # the host never owns closing the injected source


@pytest.mark.parametrize(
    ("body", "message_id", "reason"),
    [
        (b"{not json", FIRED.delivery_id, PoisonReason.INVALID_JSON),
        (b"\xff\xfe", FIRED.delivery_id, PoisonReason.INVALID_ENCODING),
        (None, FIRED.delivery_id, PoisonReason.INVALID_ENCODING),
        (FIRED.model_dump_json().encode(), None, PoisonReason.MISSING_MESSAGE_ID),
        (FIRED.model_dump_json().encode(), "f" * 64, PoisonReason.MESSAGE_ID_MISMATCH),
        (b"x" * (70 * 1024), FIRED.delivery_id, PoisonReason.BODY_TOO_LARGE),
        (json.dumps({"x": 1}).encode(), FIRED.delivery_id, PoisonReason.INVALID_CONTRACT),
    ],
)
async def test_poison_messages_are_dead_lettered_with_safe_reasons(
    body: bytes | None, message_id: str | None, reason: PoisonReason
) -> None:
    h = Harness()
    message = FakeMessage(body, message_id)
    source = FakeSource([message])
    await run_until_drained(host_for(h, source), source)
    assert message.settled == ["dead_letter"]
    assert message.dead_letter_reason is reason
    assert h.investigator.calls == 0
    assert await h.repo.load(FIRED.incident_key) is None


async def test_spoofed_routing_is_rejected_against_trusted_registry() -> None:
    h = Harness()
    spoofed = make_alert(registry=make_registry(repository="attacker/repo"))
    message = FakeMessage.of(spoofed)
    source = FakeSource([message])
    await run_until_drained(host_for(h, source), source)
    assert message.dead_letter_reason is PoisonReason.REGISTRY_MISMATCH
    assert h.publisher.publish_calls == []


async def test_concurrency_never_exceeds_two() -> None:
    h = Harness()
    gate = asyncio.Event()

    async def slow(alert: object) -> object:
        await gate.wait()
        return complete_report(alert)  # type: ignore[arg-type]

    h.investigator.behavior = slow  # type: ignore[assignment]
    alerts = [make_alert(alert_id=f"{FIRED.alert_id}-{i}") for i in range(5)]
    messages = [FakeMessage.of(a) for a in alerts]
    source = FakeSource(messages)
    host = host_for(h, source)
    task = asyncio.create_task(host.run())
    await eventually(lambda: host.active >= 2)
    await asyncio.sleep(0.05)
    assert host.active == 2 and source.received == 2
    gate.set()
    await asyncio.wait_for(source.drained.wait(), 5)
    await eventually(lambda: host.active == 0)
    host.request_stop()
    await task
    assert host.max_active == 2
    assert all(m.settled == ["complete"] for m in messages)


async def test_graceful_stop_abandons_in_flight_without_success() -> None:
    h = Harness(shutdown_grace_seconds=0.05)

    async def hang(alert: object) -> object:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    h.investigator.behavior = hang  # type: ignore[assignment]
    message = FakeMessage.of(FIRED)
    source = FakeSource([message])
    host = host_for(h, source)
    task = asyncio.create_task(host.run())
    await asyncio.wait_for(h.investigator.started.wait(), 5)
    host.request_stop()
    await asyncio.wait_for(task, 5)
    assert message.settled == ["abandon"]
    assert h.publisher.publish_calls == []
    loaded = await h.repo.load(FIRED.incident_key)
    assert loaded is not None and loaded[0].phase is not IncidentPhase.PUBLISHED


async def test_lock_lost_abandons_message() -> None:
    h = Harness()
    message = FakeMessage.of(FIRED)

    async def lose(alert: object) -> object:
        message.lock_lost.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    h.investigator.behavior = lose  # type: ignore[assignment]
    source = FakeSource([message])
    await run_until_drained(host_for(h, source), source)
    assert message.settled == ["abandon"] and h.publisher.publish_calls == []


async def test_store_failures_abandon_then_dead_letter_at_cap() -> None:
    h = Harness(max_delivery_attempts=3)

    def fail(_pk: str, _ops: object) -> None:
        raise TransientStateError()

    h.store.faults.extend([fail] * 1000)
    early = FakeMessage.of(FIRED, delivery_count=1)
    last = FakeMessage.of(FIRED, delivery_count=3)
    source = FakeSource([early, last])
    await run_until_drained(host_for(h, source), source)
    assert early.settled == ["abandon"]
    assert last.dead_letter_reason is PoisonReason.PROCESSING_ATTEMPTS_EXHAUSTED


async def test_persistent_failures_stop_host_fatally() -> None:
    h = Harness(max_consecutive_failures=2)

    def fail(_pk: str, _ops: object) -> None:
        raise TransientStateError()

    h.store.faults.extend([fail] * 1000)
    source = FakeSource([FakeMessage.of(FIRED), FakeMessage.of(FIRED), FakeMessage.of(FIRED)])
    with pytest.raises(WorkerFatalError) as info:
        await asyncio.wait_for(host_for(h, source).run(), 5)
    assert info.value.code == "consecutive_failures"


async def test_unexpected_task_error_is_not_swallowed() -> None:
    h = Harness()
    source = FakeSource([FakeMessage.of(FIRED)])
    host = host_for(h, source)

    async def crash(_message: object) -> None:
        raise RuntimeError("handler bug")

    host._handle = crash  # type: ignore[method-assign]
    with pytest.raises(WorkerFatalError) as info:
        await asyncio.wait_for(host.run(), 5)
    assert info.value.code == "task_failed"


async def test_reconciler_resumes_deferred_incidents_after_restart() -> None:
    h = Harness(reconcile_batch=5)

    h.publisher.publish_results.append(TimeoutError())
    source = FakeSource([FakeMessage.of(FIRED)])
    await run_until_drained(host_for(h, source), source)
    loaded = await h.repo.load(FIRED.incident_key)
    assert loaded is not None and loaded[0].phase is IncidentPhase.PUBLICATION_UNCERTAIN
    # A fresh replica (restart) reconciles without any new message and never re-creates.
    h.publisher.reconcile_results.append(PublishResult(status=PublicationStatus.UNCERTAIN))
    h.clock.advance(h.settings.backoff_max_seconds + 1)
    restarted = host_for(h, FakeSource())
    assert await restarted.reconcile_once() == 1
    await eventually(lambda: restarted.active == 0)
    assert len(h.publisher.publish_calls) == 1 and len(h.publisher.reconcile_calls) == 1
