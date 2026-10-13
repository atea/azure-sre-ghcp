"""Incident repository: CAS event merge, conditional claims and lease-guarded updates.

Every write is an ETag-conditional replace/create and carries a fresh ``write_id``
so that an ambiguous (timed-out) write can be resolved by reading it back instead
of being retried blindly.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable, Collection, Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final

from azure_sre.contracts import MonitorCondition, NormalizedAlert
from azure_sre.state.entity_store import Create, EntityOp, EntityStore, Replace
from azure_sre.state.errors import (
    ConcurrencyConflict,
    LeaseLost,
    StaleTransition,
    StateCorrupt,
    TransientStateError,
)
from azure_sre.state.records import (
    ACTIVE_FLAG,
    INCIDENT_ROW,
    RECOVERY_ROW,
    IncidentPhase,
    IncidentRecord,
    RecoveryLedger,
    decode_incident,
    decode_recovery,
    encode_incident,
    encode_recovery,
)

__all__ = [
    "FIRED_MISSING_REASON",
    "Clock",
    "EventOutcome",
    "IncidentClaim",
    "IncidentRepository",
    "utc_now",
]

_log = logging.getLogger("azure_sre.state")
_MAX_CONFLICT_RETRIES: Final = 8
FIRED_MISSING_REASON: Final = "fired_missing"

Clock = Callable[[], datetime]
RecordMutation = Callable[[IncidentRecord], IncidentRecord]
LedgerMutation = Callable[[RecoveryLedger | None], RecoveryLedger]


def utc_now() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return uuid.uuid4().hex


def short(key: str) -> str:
    return key[:12]


class EventOutcome(StrEnum):
    CREATED = "created"
    UPDATED = "updated"
    DUPLICATE = "duplicate"


class IncidentRepository:
    def __init__(self, store: EntityStore, *, clock: Clock = utc_now) -> None:
        self._store = store
        self._clock = clock

    @property
    def clock(self) -> Clock:
        return self._clock

    async def load(self, key: str) -> tuple[IncidentRecord, str] | None:
        stored = await self._store.get(key, INCIDENT_ROW)
        if stored is None:
            return None
        return decode_incident(key, stored.properties), stored.etag

    async def load_recovery(self, key: str) -> tuple[RecoveryLedger, str] | None:
        stored = await self._store.get(key, RECOVERY_ROW)
        if stored is None:
            return None
        return decode_recovery(key, stored.properties), stored.etag

    async def list_active(self, limit: int) -> list[IncidentRecord]:
        out: list[IncidentRecord] = []
        for stored in await self._store.query_flagged(INCIDENT_ROW, ACTIVE_FLAG, limit):
            try:
                out.append(decode_incident(stored.partition_key, stored.properties))
            except StateCorrupt:
                _log.error("state.corrupt_record incident=%s", short(stored.partition_key))
        return out

    async def commit(self, key: str, ops: Sequence[EntityOp], write_id: str) -> tuple[str, ...]:
        """Transact; resolve a lost response by reading the rows back by ``write_id``."""
        try:
            return await self._store.transact(key, ops)
        except TransientStateError:
            etags: list[str] = []
            for op in ops:
                stored = await self._store.get(key, op.row_key)
                if stored is None or stored.properties.get("write_id") != write_id:
                    raise
                etags.append(stored.etag)
            _log.info("state.ambiguous_write_resolved incident=%s", short(key))
            return tuple(etags)

    async def record_event(self, alert: NormalizedAlert) -> EventOutcome:
        """Durably merge a Fired or Resolved snapshot; never overwrite an existing one."""
        key = alert.incident_key
        fired = alert.monitor_condition is MonitorCondition.FIRED
        for _ in range(_MAX_CONFLICT_RETRIES):
            loaded = await self.load(key)
            now = self._clock()
            write_id = _new_id()
            if loaded is None:
                record = IncidentRecord(
                    incident_key=key,
                    phase=IncidentPhase.QUEUED if fired else IncidentPhase.PENDING_FIRED,
                    version=1,
                    write_id=write_id,
                    created_at=now,
                    updated_at=now,
                    fired=alert if fired else None,
                    resolved=None if fired else alert,
                )
                try:
                    await self.commit(
                        key, [Create(INCIDENT_ROW, encode_incident(record))], write_id
                    )
                except ConcurrencyConflict:
                    continue
                return EventOutcome.CREATED
            record, etag = loaded
            changes: dict[str, object] = {}
            if fired:
                if record.fired is None:
                    changes["fired"] = alert
                    if record.phase is IncidentPhase.PENDING_FIRED or (
                        record.phase is IncidentPhase.OPERATOR_REQUIRED
                        and record.operator_reason == FIRED_MISSING_REASON
                    ):
                        changes["phase"] = IncidentPhase.QUEUED
                        changes["operator_reason"] = None
                        changes["next_attempt_at"] = None
                elif record.fired.delivery_id != alert.delivery_id:
                    _log.warning("state.fired_snapshot_conflict incident=%s", short(key))
            elif record.resolved is None:
                changes["resolved"] = alert
            if not changes:
                return EventOutcome.DUPLICATE
            updated = record.evolve(
                **changes, version=record.version + 1, write_id=write_id, updated_at=now
            )
            try:
                await self.commit(
                    key, [Replace(INCIDENT_ROW, encode_incident(updated), etag)], write_id
                )
            except ConcurrencyConflict:
                continue
            return EventOutcome.UPDATED
        raise TransientStateError("contention")

    async def claim(self, key: str, *, owner: str, lease_seconds: float) -> IncidentClaim | None:
        """Conditionally acquire the incident lease. ``None`` if absent or held elsewhere."""
        for _ in range(_MAX_CONFLICT_RETRIES):
            loaded = await self.load(key)
            if loaded is None:
                return None
            record, etag = loaded
            now = self._clock()
            if record.lease_token is not None and record.lease_held(now):
                return None
            token = _new_id()
            write_id = _new_id()
            claimed = record.evolve(
                lease_owner=owner,
                lease_token=token,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                version=record.version + 1,
                write_id=write_id,
                updated_at=now,
            )
            try:
                etags = await self.commit(
                    key, [Replace(INCIDENT_ROW, encode_incident(claimed), etag)], write_id
                )
            except ConcurrencyConflict:
                continue
            return IncidentClaim(self, claimed, etags[0], lease_seconds=lease_seconds)
        return None


_UNLOADED: Final = object()


class IncidentClaim:
    """An owned incident lease. All writes are serialized and ETag-guarded.

    ``lost`` is set as soon as ownership cannot be proven; callers must cancel any
    side-effecting work (investigation, publication) when it fires.
    """

    def __init__(
        self,
        repository: IncidentRepository,
        record: IncidentRecord,
        etag: str,
        *,
        lease_seconds: float,
    ) -> None:
        assert record.lease_token is not None  # noqa: S101 - constructed only after claim
        self._repo = repository
        self._record = record
        self._etag = etag
        self._token: str = record.lease_token
        self._lease_seconds = lease_seconds
        self._lock = asyncio.Lock()
        self._ledger: tuple[RecoveryLedger, str] | object | None = _UNLOADED
        self.lost = asyncio.Event()

    @property
    def record(self) -> IncidentRecord:
        return self._record

    @property
    def key(self) -> str:
        return self._record.incident_key

    @property
    def token(self) -> str:
        return self._token

    def remaining_seconds(self) -> float:
        expires = self._record.lease_expires_at
        if expires is None:
            return 0.0
        return (expires - self._repo.clock()).total_seconds()

    async def recovery_ledger(self) -> RecoveryLedger | None:
        async with self._lock:
            loaded = await self._load_ledger()
            return None if loaded is None else loaded[0]

    async def _load_ledger(self) -> tuple[RecoveryLedger, str] | None:
        if self._ledger is _UNLOADED:
            self._ledger = await self._repo.load_recovery(self.key)
        assert self._ledger is None or isinstance(self._ledger, tuple)  # noqa: S101
        return self._ledger

    async def _refresh(self) -> None:
        loaded = await self._repo.load(self.key)
        if loaded is None or loaded[0].lease_token != self._token:
            self.lost.set()
            raise LeaseLost()
        self._record, self._etag = loaded
        self._ledger = _UNLOADED

    async def renew(self) -> None:
        await self.update(lambda r: r)

    async def release(self) -> None:
        """Clear the lease (best effort for the caller; raises ``LeaseLost`` if not ours)."""
        await self.update(lambda r: r, require_live=False, release=True)

    async def update(
        self,
        mutate: RecordMutation,
        *,
        expect: Collection[IncidentPhase] | None = None,
        require_live: bool = True,
        recovery: LedgerMutation | None = None,
        release: bool = False,
    ) -> IncidentRecord:
        """Apply ``mutate`` to the freshest owned record and CAS it (plus optional ledger).

        ``require_live`` refuses to write once the local lease has expired or was
        lost; pass ``False`` only to record facts (e.g. an observed publication)
        whose CAS still proves no other owner intervened.
        """
        async with self._lock:
            if require_live and (self.lost.is_set() or self.remaining_seconds() <= 0):
                self.lost.set()
                raise LeaseLost()
            for _ in range(_MAX_CONFLICT_RETRIES):
                base = self._record
                if expect is not None and base.phase not in expect:
                    raise StaleTransition()
                now = self._repo.clock()
                write_id = _new_id()
                lease: dict[str, object]
                if release:
                    lease = {"lease_owner": None, "lease_token": None, "lease_expires_at": None}
                else:
                    lease = {
                        "lease_owner": base.lease_owner,
                        "lease_token": self._token,
                        "lease_expires_at": now + timedelta(seconds=self._lease_seconds),
                    }
                updated = mutate(base).evolve(
                    **lease, version=base.version + 1, write_id=write_id, updated_at=now
                )
                ops: list[EntityOp] = [Replace(INCIDENT_ROW, encode_incident(updated), self._etag)]
                new_ledger: RecoveryLedger | None = None
                if recovery is not None:
                    current = await self._load_ledger()
                    new_ledger = recovery(None if current is None else current[0]).evolve(
                        version=(0 if current is None else current[0].version) + 1,
                        write_id=write_id,
                        updated_at=now,
                    )
                    encoded = encode_recovery(new_ledger)
                    ops.append(
                        Create(RECOVERY_ROW, encoded)
                        if current is None
                        else Replace(RECOVERY_ROW, encoded, current[1])
                    )
                try:
                    etags = await self._repo.commit(self.key, ops, write_id)
                except ConcurrencyConflict:
                    await self._refresh()
                    continue
                self._record, self._etag = updated, etags[0]
                if new_ledger is not None:
                    self._ledger = (new_ledger, etags[1])
                return updated
            raise TransientStateError("contention")
