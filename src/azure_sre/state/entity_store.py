"""Partition-scoped, ETag-guarded entity storage.

``EntityStore`` is the narrow surface the incident repository needs: point read,
an atomic same-partition transaction of create/replace operations with ETag
preconditions, and a bounded flag query used by the reconciler. Values are flat
scalars because Azure Tables cannot store nested maps; structured data is
serialized intentionally by the record layer.

``InMemoryEntityStore`` is a realistic CAS fixture: every successful write
changes the ETag, preconditions are checked atomically across a transaction, and
fault injection can simulate throttling or ambiguous (applied-but-failed) writes.
"""

from __future__ import annotations

import asyncio
import itertools
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Protocol

from azure_sre.state.errors import ConcurrencyConflict, StateTooLarge, TransientStateError

__all__ = [
    "MAX_STRING_PROPERTY_CHARS",
    "MAX_TRANSACTION_OPS",
    "Create",
    "EntityOp",
    "EntityStore",
    "InMemoryEntityStore",
    "Replace",
    "Scalar",
    "StoredEntity",
    "check_properties",
]

Scalar = str | int | bool

# Azure Tables limit string properties to 64 KiB (UTF-16), i.e. 32K characters.
MAX_STRING_PROPERTY_CHARS: Final = 32_000
MAX_TRANSACTION_OPS: Final = 100
_MAX_INT32: Final = 2**31 - 1
_NAME_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_KEY_RE: Final = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_RESERVED: Final = frozenset({"PartitionKey", "RowKey", "Timestamp", "etag"})


@dataclass(frozen=True)
class StoredEntity:
    partition_key: str
    row_key: str
    properties: Mapping[str, Scalar]
    etag: str


@dataclass(frozen=True)
class Create:
    row_key: str
    properties: Mapping[str, Scalar]


@dataclass(frozen=True)
class Replace:
    row_key: str
    properties: Mapping[str, Scalar]
    etag: str


EntityOp = Create | Replace


def check_properties(properties: Mapping[str, Scalar]) -> None:
    """Reject property names/values that Azure Tables cannot store faithfully."""
    for name, value in properties.items():
        if name in _RESERVED or not _NAME_RE.match(name):
            raise StateTooLarge("invalid_property_name")
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            if not -_MAX_INT32 - 1 <= value <= _MAX_INT32:
                raise StateTooLarge("int_out_of_range")
        elif isinstance(value, str):
            if len(value) > MAX_STRING_PROPERTY_CHARS:
                raise StateTooLarge()
        else:
            raise StateTooLarge("unsupported_property_type")


def _check_key(key: str) -> None:
    if not _KEY_RE.match(key):
        raise StateTooLarge("invalid_key")


def _check_ops(partition_key: str, ops: Sequence[EntityOp]) -> None:
    _check_key(partition_key)
    if not ops or len(ops) > MAX_TRANSACTION_OPS:
        raise StateTooLarge("invalid_transaction_size")
    rows = [op.row_key for op in ops]
    if len(rows) != len(set(rows)):
        raise StateTooLarge("duplicate_transaction_row")
    for op in ops:
        _check_key(op.row_key)
        check_properties(op.properties)


class EntityStore(Protocol):
    async def get(self, partition_key: str, row_key: str) -> StoredEntity | None:
        """Point read. ``None`` when absent."""
        ...

    async def transact(self, partition_key: str, ops: Sequence[EntityOp]) -> tuple[str, ...]:
        """Atomically apply all ops or none; return new ETags in op order.

        Raises ``ConcurrencyConflict`` when any create finds an existing row or any
        replace's ETag no longer matches; ``TransientStateError`` when the outcome
        is unknown.
        """
        ...

    async def query_flagged(self, row_key: str, flag: str, limit: int) -> list[StoredEntity]:
        """Return up to ``limit`` entities with this row key whose boolean ``flag`` is true."""
        ...

    async def close(self) -> None: ...


Fault = Callable[[str, Sequence[EntityOp]], Awaitable[None] | None]


@dataclass
class InMemoryEntityStore:
    """Thread-unsafe, asyncio-safe CAS store for tests and local runs.

    ``faults`` is a queue of callables invoked before each transaction. A fault
    may raise to fail the call before it applies. ``ambiguous_next`` applies the
    next transaction and then raises ``TransientStateError`` (lost response).
    """

    faults: list[Fault] = field(default_factory=list)
    ambiguous_next: int = 0
    transact_calls: int = 0
    _rows: dict[tuple[str, str], tuple[dict[str, Scalar], str]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _counter: itertools.count[int] = field(default_factory=lambda: itertools.count(1))

    def _etag(self) -> str:
        return f'W/"{next(self._counter)}"'

    async def get(self, partition_key: str, row_key: str) -> StoredEntity | None:
        async with self._lock:
            row = self._rows.get((partition_key, row_key))
            if row is None:
                return None
            props, etag = row
            return StoredEntity(partition_key, row_key, MappingProxyType(dict(props)), etag)

    async def transact(self, partition_key: str, ops: Sequence[EntityOp]) -> tuple[str, ...]:
        _check_ops(partition_key, ops)
        self.transact_calls += 1
        if self.faults:
            fault = self.faults.pop(0)
            result = fault(partition_key, ops)
            if result is not None:
                await result
        async with self._lock:
            for op in ops:
                current = self._rows.get((partition_key, op.row_key))
                if isinstance(op, Create):
                    if current is not None:
                        raise ConcurrencyConflict()
                elif current is None or current[1] != op.etag:
                    raise ConcurrencyConflict()
            etags: list[str] = []
            for op in ops:
                etag = self._etag()
                self._rows[(partition_key, op.row_key)] = (dict(op.properties), etag)
                etags.append(etag)
            if self.ambiguous_next > 0:
                self.ambiguous_next -= 1
                raise TransientStateError()
            return tuple(etags)

    async def query_flagged(self, row_key: str, flag: str, limit: int) -> list[StoredEntity]:
        async with self._lock:
            out: list[StoredEntity] = []
            for (pk, rk), (props, etag) in sorted(self._rows.items()):
                if rk == row_key and props.get(flag) is True:
                    out.append(StoredEntity(pk, rk, MappingProxyType(dict(props)), etag))
                    if len(out) >= limit:
                        break
            return out

    async def close(self) -> None:
        return None

    def raw(self, partition_key: str, row_key: str) -> dict[str, Scalar] | None:
        """Test helper: a copy of the stored properties."""
        row = self._rows.get((partition_key, row_key))
        return None if row is None else dict(row[0])
