"""Sanitized investigation-report persistence (private Blob Storage).

Reports are validated ``InvestigationReport`` documents, re-validated on read and
verified by SHA-256 against the durable incident record. Each investigation
attempt writes a new immutable blob (``reports/<incident>/<attempt>.json``,
``overwrite=False``); the incident record references exactly one. ``find`` lets a
later owner adopt a report persisted by an attempt that lost its claim before it
could record it, instead of re-running a completed investigation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from azure.core.credentials_async import AsyncTokenCredential
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.core.pipeline.transport import AsyncHttpTransport
from azure.storage.blob import ContentSettings
from azure.storage.blob.aio import ContainerClient
from pydantic import ValidationError

from azure_sre.contracts import ContractError, InvestigationReport
from azure_sre.state.errors import (
    ReportUnavailable,
    StateCorrupt,
    StateError,
    StateTooLarge,
    TransientStateError,
)
from azure_sre.state.table_store import map_azure_error

__all__ = [
    "MAX_REPORT_BYTES",
    "AzureBlobReportStore",
    "InMemoryReportStore",
    "ReportRef",
    "ReportStore",
    "assert_sanitized",
    "report_blob_name",
    "serialize_report",
]

MAX_REPORT_BYTES: Final = 256 * 1024
_MAX_FIND: Final = 32
_KEY_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE: Final = re.compile(r"^[0-9a-f]{32}$")
_BLOB_ENDPOINT_RE: Final = re.compile(
    r"^https://[a-z0-9]{3,24}\.blob\.core\.(?:windows\.net|usgovcloudapi\.net|chinacloudapi\.cn)/?$"
)
_CONTAINER_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,62}$")
# Defense in depth: evidence is redacted upstream, but credential shapes must never persist.
_CREDENTIAL_RE: Final = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?<![A-Za-z0-9])(?:ghp_|ghs_|gho_|ghu_|ghr_|github_pat_)[A-Za-z0-9_]{8,}"
    r"|(?i:AccountKey=|SharedAccessKey=|sig=[A-Za-z0-9%]{16,})"
    r"|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)


@dataclass(frozen=True)
class ReportRef:
    name: str
    sha256: str
    status: str


def report_blob_name(incident_key: str, attempt_token: str) -> str:
    if not _KEY_RE.match(incident_key) or not _TOKEN_RE.match(attempt_token):
        raise ValueError("invalid report blob identity")
    return f"reports/{incident_key}/{attempt_token}.json"


def assert_sanitized(text: str) -> None:
    if _CREDENTIAL_RE.search(text):
        raise StateCorrupt("credential_shape_in_report")


def serialize_report(report: InvestigationReport) -> bytes:
    """Re-validate, sanitize-check and size-check a report; return its canonical bytes."""
    try:
        validated = InvestigationReport.model_validate_json(report.model_dump_json())
    except (ValidationError, ContractError):
        raise StateCorrupt("invalid_report") from None
    text = validated.model_dump_json()
    assert_sanitized(text)
    data = text.encode("utf-8")
    if len(data) > MAX_REPORT_BYTES:
        raise StateTooLarge("report_too_large")
    return data


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse(data: bytes, incident_key: str) -> InvestigationReport:
    if len(data) > MAX_REPORT_BYTES:
        raise ReportUnavailable("report_too_large")
    try:
        report = InvestigationReport.model_validate_json(data)
    except (ValidationError, ContractError):
        raise ReportUnavailable("report_invalid") from None
    if report.incident_key != incident_key:
        raise ReportUnavailable("report_incident_mismatch")
    return report


def _verify(ref: ReportRef, data: bytes, incident_key: str) -> InvestigationReport:
    if not ref.name.startswith(f"reports/{incident_key}/"):
        raise ReportUnavailable("report_outside_incident")
    if _sha(data) != ref.sha256:
        raise ReportUnavailable("report_digest_mismatch")
    return _parse(data, incident_key)


class ReportStore(Protocol):
    async def put(
        self, incident_key: str, attempt_token: str, report: InvestigationReport
    ) -> ReportRef: ...

    async def get(self, ref: ReportRef, incident_key: str) -> InvestigationReport:
        """Return the verified report or raise ``ReportUnavailable``/``TransientStateError``."""
        ...

    async def find(self, incident_key: str) -> ReportRef | None:
        """Return a valid previously persisted report for the incident, if any."""
        ...

    async def close(self) -> None: ...


@dataclass
class InMemoryReportStore:
    blobs: dict[str, bytes] = field(default_factory=dict)
    fail_puts: int = 0
    put_calls: int = 0

    async def put(
        self, incident_key: str, attempt_token: str, report: InvestigationReport
    ) -> ReportRef:
        self.put_calls += 1
        if report.incident_key != incident_key:
            raise StateCorrupt("report_incident_mismatch")
        name = report_blob_name(incident_key, attempt_token)
        data = serialize_report(report)
        if self.fail_puts > 0:
            self.fail_puts -= 1
            raise TransientStateError()
        existing = self.blobs.get(name)
        if existing is not None and existing != data:
            raise StateCorrupt("report_blob_conflict")
        self.blobs[name] = data
        return ReportRef(name, _sha(data), report.status)

    async def get(self, ref: ReportRef, incident_key: str) -> InvestigationReport:
        data = self.blobs.get(ref.name)
        if data is None:
            raise ReportUnavailable("report_missing")
        return _verify(ref, data, incident_key)

    async def find(self, incident_key: str) -> ReportRef | None:
        prefix = f"reports/{incident_key}/"
        for name in sorted(n for n in self.blobs if n.startswith(prefix))[:_MAX_FIND]:
            data = self.blobs[name]
            try:
                report = _parse(data, incident_key)
            except ReportUnavailable:
                continue
            return ReportRef(name, _sha(data), report.status)
        return None

    async def close(self) -> None:
        return None


class AzureBlobReportStore:
    """Private container, managed-identity credential, immutable per-attempt blobs."""

    def __init__(
        self,
        *,
        account_url: str,
        container_name: str,
        credential: AsyncTokenCredential,
        transport: AsyncHttpTransport[Any, Any] | None = None,
    ) -> None:
        if not _BLOB_ENDPOINT_RE.match(account_url):
            raise ValueError("blob endpoint must be an https Azure Blob endpoint")
        if not _CONTAINER_RE.match(container_name):
            raise ValueError("invalid container name")
        self._container = ContainerClient(
            account_url=account_url.rstrip("/"),
            container_name=container_name,
            credential=credential,
            **_transport_kwargs(transport),
        )

    async def put(
        self, incident_key: str, attempt_token: str, report: InvestigationReport
    ) -> ReportRef:
        if report.incident_key != incident_key:
            raise StateCorrupt("report_incident_mismatch")
        name = report_blob_name(incident_key, attempt_token)
        data = serialize_report(report)
        digest = _sha(data)
        try:
            await self._container.upload_blob(
                name,
                data,
                overwrite=False,
                content_settings=ContentSettings(content_type="application/json"),
                metadata={"sha256": digest, "schema": "1"},
            )
        except ResourceExistsError:
            # A retried upload whose first response was lost: accept identical content only.
            existing = await self._read(name)
            if _sha(existing) != digest:
                raise StateCorrupt("report_blob_conflict") from None
        except StateError:
            raise
        except Exception as exc:  # noqa: BLE001 - mapped to safe category
            raise map_azure_error(exc) from None
        return ReportRef(name, digest, report.status)

    async def _read(self, name: str) -> bytes:
        try:
            downloader = await self._container.download_blob(name)
            if downloader.size > MAX_REPORT_BYTES:
                raise ReportUnavailable("report_too_large")
            return await downloader.readall()
        except ResourceNotFoundError:
            raise ReportUnavailable("report_missing") from None
        except StateError:
            raise
        except Exception as exc:  # noqa: BLE001 - mapped to safe category
            raise map_azure_error(exc) from None

    async def get(self, ref: ReportRef, incident_key: str) -> InvestigationReport:
        return _verify(ref, await self._read(ref.name), incident_key)

    async def find(self, incident_key: str) -> ReportRef | None:
        if not _KEY_RE.match(incident_key):
            raise ValueError("invalid incident key")
        names: list[str] = []
        try:
            async for blob in self._container.list_blobs(
                name_starts_with=f"reports/{incident_key}/"
            ):
                names.append(str(blob.name))
                if len(names) >= _MAX_FIND:
                    break
        except Exception as exc:  # noqa: BLE001 - mapped to safe category
            raise map_azure_error(exc) from None
        for name in sorted(names):
            try:
                data = await self._read(name)
                report = _parse(data, incident_key)
            except ReportUnavailable:
                continue
            return ReportRef(name, _sha(data), report.status)
        return None

    async def close(self) -> None:
        await self._container.close()


def _transport_kwargs(transport: AsyncHttpTransport[Any, Any] | None) -> dict[str, Any]:
    return {} if transport is None else {"transport": transport}
