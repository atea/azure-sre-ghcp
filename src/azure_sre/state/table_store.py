"""Azure Table Storage implementation of ``EntityStore`` (ETag CAS, managed identity only).

The caller supplies an ``AsyncTokenCredential`` (the worker factory passes a
``ManagedIdentityCredential``). No connection strings or shared keys are accepted.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, Final

from azure.core import MatchConditions
from azure.core.credentials_async import AsyncTokenCredential
from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ResourceExistsError,
    ResourceModifiedError,
    ResourceNotFoundError,
    ServiceRequestError,
    ServiceResponseError,
)
from azure.core.pipeline.transport import AsyncHttpTransport
from azure.data.tables import TableEntity, TableTransactionError, UpdateMode
from azure.data.tables.aio import TableClient

from azure_sre.state.entity_store import (
    Create,
    EntityOp,
    Replace,
    Scalar,
    StoredEntity,
    _check_ops,
)
from azure_sre.state.errors import (
    ConcurrencyConflict,
    StateAccessDenied,
    StateCorrupt,
    StateError,
    TransientStateError,
)

__all__ = ["AzureTableEntityStore", "map_azure_error"]

_TABLE_ENDPOINT_RE: Final = re.compile(
    r"^https://[a-z0-9]{3,24}\.table\.core\.(?:windows\.net|usgovcloudapi\.net|chinacloudapi\.cn)/?$"
)
_TABLE_NAME_RE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9]{2,62}$")
_FLAG_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_CONFLICT_CODES: Final = frozenset(
    {
        "ConditionNotMet",
        "UpdateConditionNotSatisfied",
        "EntityAlreadyExists",
        "EntityNotFound",
        "ResourceNotFound",
    }
)
_TRANSIENT_STATUS: Final = frozenset({408, 429, 500, 502, 503, 504})


def map_azure_error(exc: BaseException) -> StateError:
    """Translate an Azure SDK error into a safe state error (no message propagation)."""
    if isinstance(exc, ClientAuthenticationError):
        return StateAccessDenied()
    if isinstance(exc, ResourceModifiedError | ResourceExistsError | ResourceNotFoundError):
        return ConcurrencyConflict()
    if isinstance(exc, ServiceRequestError | ServiceResponseError):
        return TransientStateError()
    if isinstance(exc, HttpResponseError):
        raw_code = getattr(exc, "error_code", None)
        code = str(getattr(raw_code, "value", raw_code) or "")
        status = exc.status_code or 0
        if isinstance(exc, TableTransactionError) and code in _CONFLICT_CODES:
            return ConcurrencyConflict()
        if status in (404, 409, 412):
            return ConcurrencyConflict()
        if status in (401, 403):
            return StateAccessDenied()
        if status in _TRANSIENT_STATUS:
            return TransientStateError()
        return StateError("http_error")
    return TransientStateError()


def _entity(partition_key: str, row_key: str, properties: Mapping[str, Scalar]) -> dict[str, Any]:
    body: dict[str, Any] = dict(properties)
    body["PartitionKey"] = partition_key
    body["RowKey"] = row_key
    return body


def _stored(entity: TableEntity) -> StoredEntity:
    props: dict[str, Scalar] = {}
    for key, value in entity.items():
        if key in ("PartitionKey", "RowKey"):
            continue
        if not isinstance(value, str | int | bool):
            raise StateCorrupt("unsupported_stored_type")
        props[key] = value
    etag = entity.metadata.get("etag")
    if not isinstance(etag, str) or not etag:
        raise StateCorrupt("missing_etag")
    return StoredEntity(
        str(entity["PartitionKey"]), str(entity["RowKey"]), MappingProxyType(props), etag
    )


def _etag_of(metadata: Mapping[str, Any]) -> str:
    etag = metadata.get("etag")
    if not isinstance(etag, str) or not etag:
        raise TransientStateError()
    return etag


class AzureTableEntityStore:
    def __init__(
        self,
        *,
        endpoint: str,
        table_name: str,
        credential: AsyncTokenCredential,
        transport: AsyncHttpTransport[Any, Any] | None = None,
    ) -> None:
        if not _TABLE_ENDPOINT_RE.match(endpoint):
            raise ValueError("table endpoint must be an https Azure Table endpoint")
        if not _TABLE_NAME_RE.match(table_name):
            raise ValueError("invalid table name")
        self._client = TableClient(
            endpoint=endpoint.rstrip("/"),
            table_name=table_name,
            credential=credential,
            **_transport_kwargs(transport),
        )

    async def get(self, partition_key: str, row_key: str) -> StoredEntity | None:
        try:
            entity = await self._client.get_entity(partition_key=partition_key, row_key=row_key)
        except ResourceNotFoundError:
            return None
        except Exception as exc:  # noqa: BLE001 - mapped to safe category
            raise map_azure_error(exc) from None
        return _stored(entity)

    async def transact(self, partition_key: str, ops: Sequence[EntityOp]) -> tuple[str, ...]:
        _check_ops(partition_key, ops)
        try:
            if len(ops) == 1:
                return (await self._single(partition_key, ops[0]),)
            batch: list[tuple[str, dict[str, Any]] | tuple[str, dict[str, Any], dict[str, Any]]]
            batch = []
            for op in ops:
                body = _entity(partition_key, op.row_key, op.properties)
                if isinstance(op, Create):
                    batch.append(("create", body))
                else:
                    batch.append(
                        (
                            "update",
                            body,
                            {
                                "mode": UpdateMode.REPLACE,
                                "etag": op.etag,
                                "match_condition": MatchConditions.IfNotModified,
                            },
                        )
                    )
            results = await self._client.submit_transaction(batch)
        except StateError:
            raise
        except Exception as exc:  # noqa: BLE001 - mapped to safe category
            raise map_azure_error(exc) from None
        if len(results) != len(ops):
            raise TransientStateError()
        return tuple(_etag_of(r) for r in results)

    async def _single(self, partition_key: str, op: EntityOp) -> str:
        body = _entity(partition_key, op.row_key, op.properties)
        if isinstance(op, Create):
            return _etag_of(await self._client.create_entity(entity=body))
        assert isinstance(op, Replace)  # noqa: S101 - type narrowing
        metadata = await self._client.update_entity(
            entity=body,
            mode=UpdateMode.REPLACE,
            etag=op.etag,
            match_condition=MatchConditions.IfNotModified,
        )
        return _etag_of(metadata)

    async def query_flagged(self, row_key: str, flag: str, limit: int) -> list[StoredEntity]:
        if not _FLAG_RE.match(flag) or limit < 1:
            raise ValueError("invalid flag query")
        out: list[StoredEntity] = []
        try:
            pages = self._client.query_entities(
                query_filter=f"RowKey eq @rk and {flag} eq true",
                parameters={"rk": row_key},
                results_per_page=min(limit, 1000),
            )
            async for entity in pages:
                out.append(_stored(entity))
                if len(out) >= limit:
                    break
        except StateError:
            raise
        except Exception as exc:  # noqa: BLE001 - mapped to safe category
            raise map_azure_error(exc) from None
        return out

    async def close(self) -> None:
        await self._client.close()


def _transport_kwargs(transport: AsyncHttpTransport[Any, Any] | None) -> dict[str, Any]:
    return {} if transport is None else {"transport": transport}
