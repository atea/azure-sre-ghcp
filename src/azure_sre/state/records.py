"""Durable incident and recovery-ledger records and their flat Table encoding.

One Azure Table partition per incident key holds two rows:

* ``incident`` - lifecycle phase, lease, separately persisted Fired and Resolved
  snapshots, report reference, publication intent/record and retry bookkeeping.
* ``recovery`` - the recovery-comment ledger with its own marker and intent state.

Nested structures (alert snapshots, publication record) are validated contracts
serialized to JSON strings on purpose; Tables cannot hold nested maps.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Final, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from azure_sre.contracts import (
    ContractError,
    MonitorCondition,
    NormalizedAlert,
    PublicationRecord,
)
from azure_sre.state.entity_store import Scalar
from azure_sre.state.errors import StateCorrupt

__all__ = [
    "ACTIVE_FLAG",
    "INCIDENT_ROW",
    "RECOVERY_ROW",
    "TERMINAL_PHASES",
    "IncidentPhase",
    "IncidentRecord",
    "RecoveryLedger",
    "RecoveryState",
    "SafeCode",
    "decode_incident",
    "decode_recovery",
    "encode_incident",
    "encode_recovery",
    "issue_marker",
    "recovery_marker",
]

INCIDENT_ROW: Final = "incident"
RECOVERY_ROW: Final = "recovery"
ACTIVE_FLAG: Final = "active"
_SCHEMA: Final = 1
_KEY_PATTERN: Final = r"^[0-9a-f]{64}$"
_HEX32_PATTERN: Final = r"^[0-9a-f]{32}$"
_OWNER_PATTERN: Final = r"^[A-Za-z0-9_.:-]{1,128}$"
_BLOB_PATTERN: Final = r"^reports/[0-9a-f]{64}/[0-9a-f]{32}\.json$"
_SAFE_CODE_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_IGNORED_STORED: Final = frozenset({"Timestamp"})

SafeCode = Annotated[str, StringConstraints(pattern=_SAFE_CODE_RE.pattern)]
IncidentKey = Annotated[str, StringConstraints(pattern=_KEY_PATTERN)]
Token = Annotated[str, StringConstraints(pattern=_HEX32_PATTERN)]
Count = Annotated[int, Field(strict=True, ge=0, le=1_000_000)]


class IncidentPhase(StrEnum):
    PENDING_FIRED = "pending_fired"
    QUEUED = "queued"
    INVESTIGATING = "investigating"
    REPORT_PERSISTED = "report_persisted"
    PUBLISHING = "publishing"
    PUBLISHED = "published"
    PARTIAL_PUBLISHED = "partial_published"
    RETRYABLE_FAILURE = "retryable_failure"
    PUBLICATION_UNCERTAIN = "publication_uncertain"
    TEST_SINK_SUPPRESSED = "test_sink_suppressed"
    OPERATOR_REQUIRED = "operator_required"


TERMINAL_PHASES: Final = frozenset(
    {
        IncidentPhase.PUBLISHED,
        IncidentPhase.PARTIAL_PUBLISHED,
        IncidentPhase.TEST_SINK_SUPPRESSED,
        IncidentPhase.OPERATOR_REQUIRED,
    }
)


class RecoveryState(StrEnum):
    PENDING = "pending"
    WRITING = "writing"
    COMMENTED = "commented"
    UNCERTAIN = "uncertain"
    OPERATOR_REQUIRED = "operator_required"


class ImprovementState(StrEnum):
    PENDING = "pending"
    WRITING = "writing"
    PUBLISHED = "published"
    UNCERTAIN = "uncertain"
    OPERATOR_REQUIRED = "operator_required"


def issue_marker(key: str) -> str:
    return f"azure-sre:incident:{key}"


def recovery_marker(key: str) -> str:
    return f"azure-sre:recovery:{key}"


def improvement_marker(key: str) -> str:
    return f"azure-sre:improvement:{key}"


_CONFIG: Final = ConfigDict(extra="forbid", frozen=True, validate_assignment=True)


class IncidentRecord(BaseModel):
    model_config = _CONFIG

    schema_version: Literal[1] = _SCHEMA
    incident_key: IncidentKey
    phase: IncidentPhase
    version: Count = 0
    write_id: Token | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    fired: NormalizedAlert | None = None
    resolved: NormalizedAlert | None = None
    lease_owner: Annotated[str, StringConstraints(pattern=_OWNER_PATTERN)] | None = None
    lease_token: Token | None = None
    lease_expires_at: AwareDatetime | None = None
    investigation_attempts: Count = 0
    publish_attempts: Count = 0
    reconcile_attempts: Count = 0
    report_blob: Annotated[str, StringConstraints(pattern=_BLOB_PATTERN)] | None = None
    report_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | None = None
    report_status: Literal["complete", "partial"] | None = None
    publish_marker: str | None = None
    publish_intent_at: AwareDatetime | None = None
    publication: PublicationRecord | None = None
    failure_category: SafeCode | None = None
    next_attempt_at: AwareDatetime | None = None
    recovery_done: bool = False
    recovery_blocked: bool = False
    operator_reason: SafeCode | None = None
    improvement_state: ImprovementState | None = None
    improvement_attempts: Count = 0
    improvement_reconcile_attempts: Count = 0
    improvement_intent_at: AwareDatetime | None = None
    improvement_publication: PublicationRecord | None = None
    improvement_reason: SafeCode | None = None

    @field_validator(
        "created_at",
        "updated_at",
        "lease_expires_at",
        "publish_intent_at",
        "next_attempt_at",
        "improvement_intent_at",
    )
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        key = self.incident_key
        if self.fired is not None and (
            self.fired.incident_key != key
            or self.fired.monitor_condition is not MonitorCondition.FIRED
        ):
            raise ValueError("fired snapshot mismatch")
        if self.resolved is not None and (
            self.resolved.incident_key != key
            or self.resolved.monitor_condition is not MonitorCondition.RESOLVED
        ):
            raise ValueError("resolved snapshot mismatch")
        if self.fired is None and self.resolved is None:
            raise ValueError("record requires an event snapshot")
        if self.fired is None and not (
            self.phase is IncidentPhase.PENDING_FIRED
            or (
                self.phase is IncidentPhase.OPERATOR_REQUIRED
                and self.operator_reason == "fired_missing"
            )
        ):
            raise ValueError("only pending_fired/fired_missing may lack a fired snapshot")
        if (self.lease_token is None) != (self.lease_expires_at is None) or (
            self.lease_token is None
        ) != (self.lease_owner is None):
            raise ValueError("lease fields must be set together")
        if (self.report_blob is None) != (self.report_sha256 is None) or (
            self.report_blob is None
        ) != (self.report_status is None):
            raise ValueError("report fields must be set together")
        if self.report_blob is not None and not self.report_blob.startswith(f"reports/{key}/"):
            raise ValueError("report blob outside incident prefix")
        if self.publish_marker is not None and self.publish_marker != issue_marker(key):
            raise ValueError("unexpected publish marker")
        if self.phase in (
            IncidentPhase.REPORT_PERSISTED,
            IncidentPhase.PUBLISHING,
            IncidentPhase.PUBLICATION_UNCERTAIN,
            IncidentPhase.PUBLISHED,
            IncidentPhase.PARTIAL_PUBLISHED,
        ) and (self.report_blob is None):
            raise ValueError("phase requires a persisted report")
        if self.phase in (IncidentPhase.PUBLISHING, IncidentPhase.PUBLICATION_UNCERTAIN) and (
            self.publish_marker is None or self.publish_intent_at is None
        ):
            raise ValueError("publication phase requires a persisted intent")
        published = self.phase in (IncidentPhase.PUBLISHED, IncidentPhase.PARTIAL_PUBLISHED)
        if published != (self.publication is not None):
            raise ValueError("publication record must exist exactly in published phases")
        if self.publication is not None and (
            self.publication.incident_key != key or self.publication.marker != issue_marker(key)
        ):
            raise ValueError("publication record does not belong to incident")
        if (self.phase is IncidentPhase.OPERATOR_REQUIRED) != (self.operator_reason is not None):
            raise ValueError("operator_reason must be set exactly for operator_required")
        if self.improvement_state is not None and not published:
            raise ValueError("improvement requires a verified incident publication")
        if (self.improvement_state is ImprovementState.PUBLISHED) != (
            self.improvement_publication is not None
        ):
            raise ValueError("improvement publication required exactly when published")
        if self.improvement_state in (ImprovementState.WRITING, ImprovementState.UNCERTAIN):
            if self.improvement_intent_at is None:
                raise ValueError("improvement write requires persisted intent")
        if self.improvement_publication is not None and (
            self.improvement_publication.incident_key != key
            or self.improvement_publication.marker != improvement_marker(key)
            or self.publication is None
            or self.improvement_publication.repository != self.publication.repository
        ):
            raise ValueError("improvement publication mismatch")
        return self

    @property
    def is_active(self) -> bool:
        """Whether the reconciler still has work for this incident."""
        if self.phase not in TERMINAL_PHASES:
            return True
        if self.improvement_state in (
            ImprovementState.PENDING,
            ImprovementState.WRITING,
            ImprovementState.UNCERTAIN,
        ):
            return True
        return (
            self.phase in (IncidentPhase.PUBLISHED, IncidentPhase.PARTIAL_PUBLISHED)
            and self.resolved is not None
            and not self.recovery_done
            and not self.recovery_blocked
        )

    def lease_held(self, now: datetime) -> bool:
        return self.lease_expires_at is not None and self.lease_expires_at > now

    def evolve(self, **changes: Any) -> IncidentRecord:
        """Validated copy (``model_copy`` would skip validation)."""
        data = self.model_dump()
        data.update(changes)
        return IncidentRecord.model_validate(data)


class RecoveryLedger(BaseModel):
    model_config = _CONFIG

    schema_version: Literal[1] = _SCHEMA
    incident_key: IncidentKey
    marker: str
    state: RecoveryState
    attempts: Count = 0
    reconcile_attempts: Count = 0
    intent_at: AwareDatetime | None = None
    comment_id: Annotated[int, Field(strict=True, gt=0)] | None = None
    reason: SafeCode | None = None
    version: Count = 0
    write_id: Token | None = None
    updated_at: AwareDatetime

    @field_validator("intent_at", "updated_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if self.marker != recovery_marker(self.incident_key):
            raise ValueError("unexpected recovery marker")
        if (self.state is RecoveryState.COMMENTED) != (self.comment_id is not None):
            raise ValueError("comment_id must be set exactly when commented")
        if self.state in (RecoveryState.WRITING, RecoveryState.UNCERTAIN) and (
            self.intent_at is None
        ):
            raise ValueError("writing/uncertain recovery requires intent_at")
        return self

    def evolve(self, **changes: Any) -> RecoveryLedger:
        data = self.model_dump()
        data.update(changes)
        return RecoveryLedger.model_validate(data)


# ---------------------------------------------------------------------------
# Flat encoding

_JSON_FIELDS: Final = {"fired": "fired_json", "resolved": "resolved_json"}
_PUBLICATION_FIELD: Final = "publication_json"


def _encode_value(value: Any) -> Scalar | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, bool | int | str):
        return value
    raise StateCorrupt("unencodable_field")


def _json_text(model: BaseModel) -> str:
    return json.dumps(
        model.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def encode_incident(record: IncidentRecord) -> dict[str, Scalar]:
    props: dict[str, Scalar] = {}
    for name in IncidentRecord.model_fields:
        value = getattr(record, name)
        if name in _JSON_FIELDS:
            if value is not None:
                props[_JSON_FIELDS[name]] = _json_text(value)
            continue
        if name in ("publication", "improvement_publication"):
            if value is not None:
                props[f"{name}_json"] = _json_text(value)
            continue
        encoded = _encode_value(value)
        if encoded is not None:
            props[name] = encoded
    props[ACTIVE_FLAG] = record.is_active
    return props


def encode_recovery(ledger: RecoveryLedger) -> dict[str, Scalar]:
    props: dict[str, Scalar] = {}
    for name in RecoveryLedger.model_fields:
        encoded = _encode_value(getattr(ledger, name))
        if encoded is not None:
            props[name] = encoded
    return props


def _load_json(text: Scalar) -> Any:
    if not isinstance(text, str):
        raise StateCorrupt()
    try:
        return json.loads(text)
    except ValueError:
        raise StateCorrupt() from None


def decode_incident(partition_key: str, props: Mapping[str, Scalar]) -> IncidentRecord:
    data: dict[str, Any] = {}
    reverse = {v: k for k, v in _JSON_FIELDS.items()}
    try:
        for name, value in props.items():
            if name in _IGNORED_STORED or name == ACTIVE_FLAG:
                continue
            if name in reverse:
                data[reverse[name]] = NormalizedAlert.model_validate(_load_json(value))
            elif name == _PUBLICATION_FIELD:
                data["publication"] = PublicationRecord.model_validate(_load_json(value))
            elif name == "improvement_publication_json":
                data["improvement_publication"] = PublicationRecord.model_validate(
                    _load_json(value)
                )
            elif name in IncidentRecord.model_fields:
                data[name] = value
            else:
                raise StateCorrupt("unknown_property")
        record = IncidentRecord.model_validate(data)
    except (ValidationError, ContractError):
        raise StateCorrupt() from None
    if record.incident_key != partition_key:
        raise StateCorrupt("partition_mismatch")
    return record


def decode_recovery(partition_key: str, props: Mapping[str, Scalar]) -> RecoveryLedger:
    data = {k: v for k, v in props.items() if k not in _IGNORED_STORED}
    if any(k not in RecoveryLedger.model_fields for k in data):
        raise StateCorrupt("unknown_property")
    try:
        ledger = RecoveryLedger.model_validate(data)
    except (ValidationError, ContractError):
        raise StateCorrupt() from None
    if ledger.incident_key != partition_key:
        raise StateCorrupt("partition_mismatch")
    return ledger
