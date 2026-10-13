"""Stable interfaces between the durable worker and the investigation/publisher packages.

The worker owns ordering, durability, ownership and retries. Implementations:

* ``Investigator.run(alert)`` returns a validated ``InvestigationReport`` for the
  Fired snapshot. It must honor ``asyncio`` cancellation promptly. It may raise
  ``InvestigationDeferred`` for retryable conditions (e.g. rate limits); any other
  exception is treated as a retryable ``sdk_error``. When attempts are exhausted the
  worker publishes a host-built partial report instead of inventing a diagnosis.
* ``Publisher`` performs exactly one remote operation per call and reports what it
  *knows*: ``PUBLISHED`` (verified), ``ABSENT`` (definitely not written / not found)
  or ``UNCERTAIN``. It never decides retries. Any raised exception from
  ``publish``/``recover`` is treated as ``UNCERTAIN``; the worker then only calls
  ``reconcile``/``reconcile_recovery`` until the ambiguity resolves.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Final, Protocol, Self

from pydantic import Field, StringConstraints, model_validator

from azure_sre.contracts import (
    ContractError,
    InvestigationReport,
    MonitorCondition,
    NormalizedAlert,
    PartialCategory,
    PublicationRecord,
    Sink,
    StrictModel,
)

__all__ = [
    "MAX_RETRY_AFTER_SECONDS",
    "InvestigationDeferred",
    "Investigator",
    "PublicationStatus",
    "PublishRequest",
    "PublishResult",
    "Publisher",
    "RecoveryRequest",
    "RecoveryResult",
]

MAX_RETRY_AFTER_SECONDS: Final = 3600.0
_SAFE_CODE: Final = r"^[a-z][a-z0-9_]{0,63}$"
_REPOSITORY: Final = r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$"
_SAFE_CODE_RE: Final = re.compile(_SAFE_CODE)

SafeReason = Annotated[str, StringConstraints(pattern=_SAFE_CODE)]
RetryAfter = Annotated[float, Field(ge=0, le=MAX_RETRY_AFTER_SECONDS)]


class InvestigationDeferred(Exception):
    """Retryable investigation condition. ``category`` and ``reason`` are safe codes."""

    def __init__(
        self,
        category: PartialCategory | str,
        *,
        reason: str = "deferred",
        retry_after_seconds: float | None = None,
    ) -> None:
        if not _SAFE_CODE_RE.match(reason):
            reason = "deferred"
        if retry_after_seconds is not None:
            retry_after_seconds = min(max(float(retry_after_seconds), 0.0), MAX_RETRY_AFTER_SECONDS)
        self.category = PartialCategory(category)
        self.reason = reason
        self.retry_after_seconds = retry_after_seconds
        super().__init__(self.reason)


class Investigator(Protocol):
    async def run(self, alert: NormalizedAlert) -> InvestigationReport:
        """Investigate the Fired snapshot's historical window; return a validated report."""
        ...


class PublicationStatus(StrEnum):
    PUBLISHED = "published"
    ABSENT = "absent"
    UNCERTAIN = "uncertain"


class PublishRequest(StrictModel):
    """Host-owned publication intent. ``repository`` is chosen by the host, not the model."""

    alert: NormalizedAlert
    report: InvestigationReport
    repository: Annotated[str, StringConstraints(pattern=_REPOSITORY)]
    sink: Sink
    marker: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    attempt: Annotated[int, Field(strict=True, ge=1)]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.alert.monitor_condition is not MonitorCondition.FIRED:
            raise ContractError("invalid_publication", "publication uses the Fired snapshot")
        if self.report.incident_key != self.alert.incident_key or self.sink != self.alert.sink:
            raise ContractError("invalid_publication", "report/sink mismatch")
        return self


class PublishResult(StrictModel):
    status: PublicationStatus
    record: PublicationRecord | None = None
    reason: SafeReason | None = None
    retryable: bool = True
    retry_after_seconds: RetryAfter | None = None

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if (self.status is PublicationStatus.PUBLISHED) != (self.record is not None):
            raise ContractError("invalid_publication", "record required exactly when published")
        return self


class RecoveryRequest(StrictModel):
    incident_key: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    resolved: NormalizedAlert
    publication: PublicationRecord
    marker: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    attempt: Annotated[int, Field(strict=True, ge=1)]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if (
            self.resolved.monitor_condition is not MonitorCondition.RESOLVED
            or self.resolved.incident_key != self.incident_key
            or self.publication.incident_key != self.incident_key
        ):
            raise ContractError("invalid_publication", "recovery request mismatch")
        return self


class RecoveryResult(StrictModel):
    status: PublicationStatus
    comment_id: Annotated[int, Field(strict=True, gt=0)] | None = None
    reason: SafeReason | None = None
    retryable: bool = True
    retry_after_seconds: RetryAfter | None = None

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if (self.status is PublicationStatus.PUBLISHED) != (self.comment_id is not None):
            raise ContractError("invalid_publication", "comment_id required exactly when published")
        return self


class Publisher(Protocol):
    async def publish(self, request: PublishRequest) -> PublishResult:
        """Create the issue once. ``ABSENT`` only if the write certainly did not happen."""
        ...

    async def reconcile(self, request: PublishRequest) -> PublishResult:
        """Look up the issue by marker without writing. ``ABSENT`` = confidently not found."""
        ...

    async def recover(self, request: RecoveryRequest) -> RecoveryResult:
        """Add the recovery comment once (never closes the issue)."""
        ...

    async def reconcile_recovery(self, request: RecoveryRequest) -> RecoveryResult:
        """Look up the recovery comment by marker without writing."""
        ...
