"""State layer: CAS store, encoding, repository merge/claims and report persistence."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from typing import Any

import pytest
from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ResourceExistsError,
    ResourceModifiedError,
    ServiceRequestError,
)
from azure.core.pipeline.transport import AsyncHttpTransport

from azure_sre.contracts import Sink
from azure_sre.state import (
    FIRED_MISSING_REASON,
    AzureBlobReportStore,
    AzureTableEntityStore,
    ConcurrencyConflict,
    Create,
    EventOutcome,
    IncidentPhase,
    IncidentRecord,
    IncidentRepository,
    InMemoryEntityStore,
    InMemoryReportStore,
    LeaseLost,
    RecoveryLedger,
    RecoveryState,
    Replace,
    ReportUnavailable,
    StaleTransition,
    StateAccessDenied,
    StateCorrupt,
    StateTooLarge,
    TransientStateError,
    recovery_marker,
)
from azure_sre.state.entity_store import check_properties
from azure_sre.state.records import (
    INCIDENT_ROW,
    decode_incident,
    decode_recovery,
    encode_incident,
    encode_recovery,
)
from azure_sre.state.reports import report_blob_name, serialize_report
from azure_sre.state.table_store import map_azure_error
from tests.unit.test_worker_support import T0, FakeClock, complete_report, make_alert

KEY = make_alert().incident_key
TOKEN = "a" * 32


def repo_with_clock() -> tuple[InMemoryEntityStore, IncidentRepository, FakeClock]:
    store = InMemoryEntityStore()
    clock = FakeClock()
    return store, IncidentRepository(store, clock=clock), clock


# --- entity store ---------------------------------------------------------------------


async def test_in_memory_store_etag_cas_and_atomic_transactions() -> None:
    store = InMemoryEntityStore()
    (etag,) = await store.transact("p", [Create("r1", {"v": 1})])
    with pytest.raises(ConcurrencyConflict):
        await store.transact("p", [Create("r1", {"v": 2})])
    (etag2,) = await store.transact("p", [Replace("r1", {"v": 2}, etag)])
    assert etag2 != etag
    with pytest.raises(ConcurrencyConflict):  # stale etag
        await store.transact("p", [Replace("r1", {"v": 3}, etag)])
    with pytest.raises(ConcurrencyConflict):  # atomic: neither row written
        await store.transact("p", [Create("r2", {"v": 1}), Replace("r1", {"v": 9}, etag)])
    assert await store.get("p", "r2") is None
    stored = await store.get("p", "r1")
    assert stored is not None and stored.properties["v"] == 2


@pytest.mark.parametrize(
    "props",
    [
        {"bad-name": 1},
        {"x": "y" * 32_001},
        {"x": 2**31},
        {"x": 1.5},
        {"PartitionKey": "p"},
    ],
)
def test_entity_property_limits(props: dict[str, Any]) -> None:
    with pytest.raises((StateTooLarge, StateCorrupt, ValueError)):
        check_properties(props)


# --- record encoding ------------------------------------------------------------------


def record(**changes: Any) -> IncidentRecord:
    data: dict[str, Any] = {
        "incident_key": KEY,
        "phase": IncidentPhase.QUEUED,
        "created_at": T0,
        "updated_at": T0,
        "fired": make_alert(),
    }
    data.update(changes)
    return IncidentRecord.model_validate(data)


def test_incident_encoding_is_flat_json_strings_and_round_trips() -> None:
    rec = record(resolved=make_alert("Resolved"))
    props = encode_incident(rec)
    assert all(isinstance(v, str | int | bool) for v in props.values())
    assert json.loads(str(props["fired_json"]))["monitor_condition"] == "Fired"
    assert "resolved_json" in props and props["active"] is True
    check_properties(props)
    assert decode_incident(KEY, {**props, "Timestamp": "x"}) == rec


def test_decode_rejects_unknown_tampered_or_misplaced_rows() -> None:
    props = encode_incident(record())
    with pytest.raises(StateCorrupt):
        decode_incident(KEY, {**props, "surprise": 1})
    with pytest.raises(StateCorrupt):
        decode_incident(KEY, {**props, "fired_json": "{not json"})
    with pytest.raises(StateCorrupt):
        decode_incident("0" * 64, props)
    resolved = make_alert("Resolved").model_dump(mode="json")
    with pytest.raises(StateCorrupt):  # a Resolved snapshot cannot pose as Fired
        decode_incident(KEY, {**props, "fired_json": json.dumps(resolved)})


def test_record_invariants() -> None:
    with pytest.raises(ValueError):
        record(fired=None, resolved=None)
    with pytest.raises(ValueError):  # only pending_fired may lack Fired
        record(fired=None, resolved=make_alert("Resolved"))
    with pytest.raises(ValueError):  # publishing requires a persisted report and intent
        record(phase=IncidentPhase.PUBLISHING)
    with pytest.raises(ValueError):
        record(phase=IncidentPhase.OPERATOR_REQUIRED)
    assert not record(phase=IncidentPhase.TEST_SINK_SUPPRESSED).is_active


def test_recovery_ledger_round_trip_and_marker() -> None:
    ledger = RecoveryLedger(
        incident_key=KEY,
        marker=recovery_marker(KEY),
        state=RecoveryState.WRITING,
        intent_at=T0,
        updated_at=T0,
    )
    assert decode_recovery(KEY, encode_recovery(ledger)) == ledger
    with pytest.raises(ValueError):
        RecoveryLedger(incident_key=KEY, marker="other", state=RecoveryState.PENDING, updated_at=T0)


# --- repository -----------------------------------------------------------------------


async def test_record_event_is_idempotent_and_never_overwrites_fired() -> None:
    _, repo, _ = repo_with_clock()
    fired = make_alert()
    assert await repo.record_event(fired) is EventOutcome.CREATED
    assert await repo.record_event(fired) is EventOutcome.DUPLICATE
    assert await repo.record_event(make_alert("Resolved")) is EventOutcome.UPDATED
    assert await repo.record_event(make_alert("Resolved")) is EventOutcome.DUPLICATE
    loaded = await repo.load(KEY)
    assert loaded is not None
    rec = loaded[0]
    assert rec.fired == fired and rec.resolved is not None
    assert rec.phase is IncidentPhase.QUEUED


async def test_early_resolved_waits_for_fired_without_inventing_it() -> None:
    _, repo, _ = repo_with_clock()
    await repo.record_event(make_alert("Resolved"))
    loaded = await repo.load(KEY)
    assert loaded is not None
    assert loaded[0].phase is IncidentPhase.PENDING_FIRED and loaded[0].fired is None
    await repo.record_event(make_alert())
    loaded = await repo.load(KEY)
    assert loaded is not None
    rec = loaded[0]
    assert rec.phase is IncidentPhase.QUEUED
    assert rec.fired is not None and rec.resolved is not None


async def test_late_fired_reopens_fired_missing_operator_state() -> None:
    _, repo, _ = repo_with_clock()
    await repo.record_event(make_alert("Resolved"))
    loaded = await repo.load(KEY)
    assert loaded is not None
    rec, etag = loaded
    stuck = rec.evolve(phase=IncidentPhase.OPERATOR_REQUIRED, operator_reason=FIRED_MISSING_REASON)
    await repo.commit(KEY, [Replace(INCIDENT_ROW, encode_incident(stuck), etag)], "b" * 32)
    await repo.record_event(make_alert())
    loaded = await repo.load(KEY)
    assert loaded is not None and loaded[0].phase is IncidentPhase.QUEUED


async def test_concurrent_event_merges_converge() -> None:
    _, repo, _ = repo_with_clock()
    outcomes = await asyncio.gather(
        repo.record_event(make_alert()),
        repo.record_event(make_alert("Resolved")),
        repo.record_event(make_alert()),
    )
    assert outcomes.count(EventOutcome.CREATED) == 1
    loaded = await repo.load(KEY)
    assert loaded is not None
    assert loaded[0].fired is not None and loaded[0].resolved is not None


async def test_ambiguous_write_is_resolved_by_reading_back_write_id() -> None:
    store, repo, _ = repo_with_clock()
    store.ambiguous_next = 1
    assert await repo.record_event(make_alert()) is EventOutcome.CREATED
    assert await repo.load(KEY) is not None


async def test_failed_transient_write_is_not_reported_as_success() -> None:
    store, repo, _ = repo_with_clock()

    def fail(_pk: str, _ops: object) -> None:
        raise TransientStateError()

    store.faults.append(fail)
    with pytest.raises(TransientStateError):
        await repo.record_event(make_alert())
    assert await repo.load(KEY) is None


async def test_claims_are_exclusive_until_expiry() -> None:
    _, repo, clock = repo_with_clock()
    await repo.record_event(make_alert())
    first, second = await asyncio.gather(
        repo.claim(KEY, owner="a", lease_seconds=60), repo.claim(KEY, owner="b", lease_seconds=60)
    )
    assert (first is None) != (second is None)
    winner = first or second
    assert winner is not None
    assert await repo.claim(KEY, owner="c", lease_seconds=60) is None
    clock.advance(61)
    thief = await repo.claim(KEY, owner="c", lease_seconds=60)
    assert thief is not None
    with pytest.raises(LeaseLost):
        await winner.renew()
    assert winner.lost.is_set()
    with pytest.raises(LeaseLost):
        await winner.update(lambda r: r, require_live=False)


async def test_claim_update_reapplies_mutation_after_concurrent_event() -> None:
    _, repo, _ = repo_with_clock()
    await repo.record_event(make_alert())
    claim = await repo.claim(KEY, owner="a", lease_seconds=60)
    assert claim is not None
    await repo.record_event(make_alert("Resolved"))  # bumps the etag underneath the owner
    updated = await claim.update(
        lambda r: r.evolve(phase=IncidentPhase.INVESTIGATING, investigation_attempts=1),
        expect={IncidentPhase.QUEUED},
    )
    assert updated.resolved is not None and updated.phase is IncidentPhase.INVESTIGATING
    with pytest.raises(StaleTransition):
        await claim.update(lambda r: r, expect={IncidentPhase.QUEUED})
    await claim.release()
    loaded = await repo.load(KEY)
    assert loaded is not None and loaded[0].lease_token is None


async def test_expired_local_lease_refuses_side_effect_writes() -> None:
    _, repo, clock = repo_with_clock()
    await repo.record_event(make_alert())
    claim = await repo.claim(KEY, owner="a", lease_seconds=60)
    assert claim is not None
    clock.advance(61)
    with pytest.raises(LeaseLost):
        await claim.update(lambda r: r)
    assert claim.lost.is_set()


async def test_recovery_ledger_written_atomically_with_incident() -> None:
    store, repo, _ = repo_with_clock()
    await repo.record_event(make_alert())
    claim = await repo.claim(KEY, owner="a", lease_seconds=60)
    assert claim is not None

    def fail(_pk: str, _ops: object) -> None:
        raise ConcurrencyConflict()

    store.faults.append(fail)
    ledger = RecoveryLedger(
        incident_key=KEY, marker=recovery_marker(KEY), state=RecoveryState.PENDING, updated_at=T0
    )
    await claim.update(lambda r: r, recovery=lambda _c: ledger)
    loaded = await repo.load_recovery(KEY)
    assert loaded is not None and loaded[0].state is RecoveryState.PENDING
    assert store.raw(KEY, "recovery") is not None


async def test_list_active_skips_corrupt_rows() -> None:
    store, repo, _ = repo_with_clock()
    await repo.record_event(make_alert())
    await store.transact("f" * 64, [Create(INCIDENT_ROW, {"active": True, "junk": "x"})])
    active = await repo.list_active(10)
    assert [r.incident_key for r in active] == [KEY]


# --- reports --------------------------------------------------------------------------


async def test_report_store_put_get_find_and_digest_verification() -> None:
    store = InMemoryReportStore()
    report = complete_report(make_alert())
    ref = await store.put(KEY, TOKEN, report)
    assert ref.name == report_blob_name(KEY, TOKEN)
    assert await store.get(ref, KEY) == report
    assert await store.find(KEY) == ref
    assert await store.put(KEY, TOKEN, report) == ref  # idempotent retry
    store.blobs[ref.name] = store.blobs[ref.name].replace(b"5xx spike", b"6xx spike")
    with pytest.raises(ReportUnavailable):
        await store.get(ref, KEY)
    with pytest.raises(ReportUnavailable):
        await store.get(ref, "0" * 64)


async def test_report_with_credential_shape_is_not_persisted() -> None:
    report = complete_report(make_alert(), summary="token ghp_ABCDEFGHIJKLMNOP leaked")
    with pytest.raises(StateCorrupt):
        serialize_report(report)
    store = InMemoryReportStore()
    with pytest.raises(StateCorrupt):
        await store.put(KEY, TOKEN, report)
    assert store.blobs == {}


def test_report_blob_names_are_scoped() -> None:
    with pytest.raises(ValueError):
        report_blob_name("../x", TOKEN)
    with pytest.raises(ValueError):
        report_blob_name(KEY, "zz")


# --- azure adapters (no network) -----------------------------------------------------


class _Cred:
    async def get_token(self, *_a: object, **_k: object) -> object:  # pragma: no cover
        raise AssertionError("no network in unit tests")

    async def close(self) -> None:
        return None


class _NoNetwork(AsyncHttpTransport):
    async def __aenter__(self) -> _NoNetwork:
        return self

    async def __aexit__(self, *_a: object) -> None:
        return None

    async def open(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def send(self, request: Any, **kwargs: Any) -> Any:  # pragma: no cover
        raise ServiceRequestError("no network in unit tests")


async def test_azure_adapters_validate_endpoints() -> None:
    cred: Any = _Cred()
    with pytest.raises(ValueError):
        AzureTableEntityStore(
            endpoint="http://x.table.core.windows.net", table_name="incidents", credential=cred
        )
    with pytest.raises(ValueError):
        AzureTableEntityStore(
            endpoint="https://acct.table.core.windows.net", table_name="in-valid", credential=cred
        )
    with pytest.raises(ValueError):
        AzureBlobReportStore(
            account_url="https://evil.example.com", container_name="sre-evidence", credential=cred
        )
    table = AzureTableEntityStore(
        endpoint="https://acct.table.core.windows.net",
        table_name="incidents",
        credential=cred,
        transport=_NoNetwork(),
    )
    blob = AzureBlobReportStore(
        account_url="https://acct.blob.core.windows.net",
        container_name="sre-evidence",
        credential=cred,
        transport=_NoNetwork(),
    )
    with pytest.raises(TransientStateError):  # SDK errors surface only as safe categories
        await table.get(KEY, "incident")
    await table.close()
    await blob.close()


def _http(status: int) -> HttpResponseError:
    exc = HttpResponseError(message="secret detail")
    exc.status_code = status
    return exc


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (ClientAuthenticationError("nope"), StateAccessDenied),
        (ResourceModifiedError("etag"), ConcurrencyConflict),
        (ResourceExistsError("exists"), ConcurrencyConflict),
        (ServiceRequestError("dns"), TransientStateError),
        (_http(412), ConcurrencyConflict),
        (_http(403), StateAccessDenied),
        (_http(429), TransientStateError),
        (_http(503), TransientStateError),
    ],
)
def test_azure_errors_map_to_safe_categories(exc: Exception, expected: type) -> None:
    mapped = map_azure_error(exc)
    assert type(mapped) is expected
    assert "secret" not in str(mapped) and "nope" not in str(mapped)


def test_test_sink_alert_keeps_production_repository_mapping() -> None:
    alert = make_alert(sink=Sink.TEST)
    assert alert.repository == "contoso/shop"
    assert record(fired=alert).fired == alert


def test_lease_expiry_helper() -> None:
    rec = record(lease_owner="a", lease_token=TOKEN, lease_expires_at=T0 + timedelta(seconds=5))
    assert rec.lease_held(T0) and not rec.lease_held(T0 + timedelta(seconds=5))
