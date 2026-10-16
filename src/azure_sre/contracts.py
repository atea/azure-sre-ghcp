"""Strict, typed contracts shared by the Azure SRE agent components.

Inputs from Azure Monitor (Common Alert Schema webhooks) and from the model are
untrusted. Everything is validated; anything unknown or ambiguous is rejected.
Routing, scope, sink and authorization are derived only from the reviewed
``ApplicationRegistry`` and host-supplied arguments, never from payload content.

Constructing a ``StrictModel`` subclass with invalid data raises ``ContractError``
(the specific error raised by a validator when available).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
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

__all__ = [
    "ALERT_SCHEMA_ID",
    "HARD_MAX_CLI_CALL_SECONDS",
    "HARD_MAX_CONCURRENCY_PER_REPLICA",
    "HARD_MAX_DIAGNOSTIC_CALLS",
    "HARD_MAX_EVIDENCE_BYTES",
    "HARD_MAX_INVESTIGATION_SECONDS",
    "HARD_MAX_ISSUE_BODY_BYTES",
    "HARD_MAX_ROWS_PER_QUERY",
    "HARD_MAX_WINDOW_AFTER_MINUTES",
    "HARD_MAX_WINDOW_BEFORE_MINUTES",
    "KNOWN_TARGET_TYPES",
    "MAX_ALERT_PAYLOAD_BYTES",
    "MAX_METRIC_NAMES",
    "MAX_MODEL_OUTPUT_BYTES",
    "MAX_TARGETS_PER_ALERT",
    "AlertContextHints",
    "AlertNormalizationError",
    "ApplicationMapping",
    "ApplicationRegistry",
    "ChronologyEntry",
    "CommonAlertData",
    "CommonAlertEssentials",
    "CommonAlertPayload",
    "ContractError",
    "DeveloperAction",
    "DiagnosticWindow",
    "EvidenceBundle",
    "EvidenceError",
    "EvidenceItem",
    "EvidenceProvenance",
    "EvidenceSource",
    "EvidenceStatus",
    "Hypothesis",
    "IncidentStatus",
    "InvestigationReport",
    "JsonScalar",
    "ModelReportDraft",
    "MonitorCondition",
    "NormalizationErrorCode",
    "NormalizedAlert",
    "NormalizedResourceId",
    "NormalizedTarget",
    "Observation",
    "PartialCategory",
    "PublicationRecord",
    "ReportGap",
    "ReportSymptom",
    "ReportValidationError",
    "Severity",
    "SignalType",
    "Sink",
    "StrictModel",
    "TargetKind",
    "delivery_id",
    "incident_key",
    "incident_window",
    "normalize_alert",
    "parse_resource_id",
    "validate_model_output",
]

ALERT_SCHEMA_ID: Final = "azureMonitorCommonAlertSchema"
MAX_ALERT_PAYLOAD_BYTES: Final = 256 * 1024
MAX_MODEL_OUTPUT_BYTES: Final = 256 * 1024
HARD_MAX_INVESTIGATION_SECONDS: Final = 300
HARD_MAX_CLI_CALL_SECONDS: Final = 30
HARD_MAX_DIAGNOSTIC_CALLS: Final = 12
HARD_MAX_CONCURRENCY_PER_REPLICA: Final = 2
HARD_MAX_ROWS_PER_QUERY: Final = 100
HARD_MAX_EVIDENCE_BYTES: Final = 64 * 1024
HARD_MAX_ISSUE_BODY_BYTES: Final = 24 * 1024
HARD_MAX_WINDOW_BEFORE_MINUTES: Final = 60
HARD_MAX_WINDOW_AFTER_MINUTES: Final = 30
MAX_TARGETS_PER_ALERT: Final = 16
MAX_METRIC_NAMES: Final = 10

_MAX_RESOURCE_ID_LENGTH: Final = 1024
_GUID_RE: Final = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_RG_RE: Final = re.compile(r"^[A-Za-z0-9_.()-]{1,90}$")
_NAMESPACE_RE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9.]*$")
_TYPE_RE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_NAME_RE: Final = re.compile(r"^[A-Za-z0-9_.()-]{1,260}$")
_FORBIDDEN_ID_CHARS: Final = re.compile(r"[?#%\s]")
_METRIC_NAME_RE: Final = re.compile(r"^[A-Za-z0-9 _./:-]{1,128}$")
_SAFE_LOC_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_ARM_PREFIX: Final = "/subscriptions/"

_SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"
_EVIDENCE_ID_PATTERN: Final = r"^E[1-9][0-9]{0,2}$"
_REPOSITORY_PATTERN: Final = r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$"

Sha256Hex = Annotated[str, StringConstraints(pattern=_SHA256_PATTERN)]
EvidenceRef = Annotated[str, StringConstraints(pattern=_EVIDENCE_ID_PATTERN)]
Repository = Annotated[str, StringConstraints(pattern=_REPOSITORY_PATTERN)]
ReportText = Annotated[str, StringConstraints(min_length=1, max_length=500)]
JsonScalar = str | int | float | bool | None


class Severity(StrEnum):
    SEV0 = "Sev0"
    SEV1 = "Sev1"
    SEV2 = "Sev2"
    SEV3 = "Sev3"
    SEV4 = "Sev4"


class MonitorCondition(StrEnum):
    FIRED = "Fired"
    RESOLVED = "Resolved"


class SignalType(StrEnum):
    METRIC = "Metric"
    LOG = "Log"
    ACTIVITY_LOG = "Activity Log"


class Sink(StrEnum):
    PRODUCTION = "production"
    TEST = "test"


class TargetKind(StrEnum):
    CONTAINER_APP = "containerApp"
    APP_INSIGHTS_COMPONENT = "appInsightsComponent"
    LOG_ANALYTICS_WORKSPACE = "logAnalyticsWorkspace"


class EvidenceSource(StrEnum):
    CONTAINER_APP_HEALTH = "container_app_health"
    STORAGE_ACCOUNT_CONFIGURATION = "storage_account_configuration"
    CONTAINER_APP_REVISIONS = "container_app_revisions"
    APP_INSIGHTS_EXCEPTIONS = "app_insights_exceptions"
    APP_INSIGHTS_CONFIGURATION = "app_insights_configuration"
    APP_INSIGHTS_OPERATIONS = "app_insights_operations"
    CONTAINER_APP_CONSOLE_LOGS = "container_app_console_logs"
    CONTAINER_APP_CONSOLE_ERRORS = "container_app_console_errors"
    CONTAINER_APP_SYSTEM_LOGS = "container_app_system_logs"
    ACTIVITY_LOG_DEPLOYMENTS = "activity_log_deployments"


class EvidenceStatus(StrEnum):
    OK = "ok"
    ZERO_ROWS = "zero_rows"
    MISSING_TELEMETRY = "missing_telemetry"
    PERMISSION_DENIED = "permission_denied"
    TIMEOUT = "timeout"
    ERROR = "error"


class IncidentStatus(StrEnum):
    QUEUED = "queued"
    INVESTIGATING = "investigating"
    INVESTIGATED = "investigated"
    PUBLISHING = "publishing"
    PUBLISHED = "published"
    PARTIAL_PUBLISHED = "partial_published"
    RETRYABLE_FAILURE = "retryable_failure"
    PUBLICATION_UNCERTAIN = "publication_uncertain"
    DEAD_LETTERED = "dead_lettered"


class PartialCategory(StrEnum):
    TIMEOUT = "timeout"
    SDK_ERROR = "sdk_error"
    INVALID_REPORT = "invalid_report"
    RATE_LIMITED = "rate_limited"
    EVIDENCE_MISSING = "evidence_missing"
    PERMISSION_DENIED = "permission_denied"
    BUDGET_EXHAUSTED = "budget_exhausted"


class NormalizationErrorCode(StrEnum):
    MALFORMED = "malformed"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    NO_TARGETS = "no_targets"
    TOO_MANY_TARGETS = "too_many_targets"
    UNSUPPORTED_RESOURCE_TYPE = "unsupported_resource_type"
    MALFORMED_SCOPE = "malformed_scope"
    UNKNOWN_SCOPE = "unknown_scope"
    MIXED_APPLICATIONS = "mixed_applications"
    CROSS_SUBSCRIPTION = "cross_subscription"
    INVALID_LIFECYCLE = "invalid_lifecycle"


_ERROR_STATUSES: Final = frozenset(
    {
        EvidenceStatus.MISSING_TELEMETRY,
        EvidenceStatus.PERMISSION_DENIED,
        EvidenceStatus.TIMEOUT,
        EvidenceStatus.ERROR,
    }
)

KNOWN_TARGET_TYPES: Final[Mapping[str, TargetKind]] = MappingProxyType(
    {
        "microsoft.app/containerapps": TargetKind.CONTAINER_APP,
        "microsoft.insights/components": TargetKind.APP_INSIGHTS_COMPONENT,
        "microsoft.operationalinsights/workspaces": TargetKind.LOG_ANALYTICS_WORKSPACE,
    }
)


class ContractError(ValueError):
    """A contract was violated. ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = str(code)
        self.message = message


class AlertNormalizationError(ContractError):
    def __init__(self, code: NormalizationErrorCode, message: str) -> None:
        super().__init__(NormalizationErrorCode(code).value, message)


class ReportValidationError(ContractError):
    def __init__(self, problems: Iterable[str], code: str = "invalid_report") -> None:
        self.problems: tuple[str, ...] = tuple(problems) or ("invalid report",)
        super().__init__(code, "; ".join(self.problems))


def _find_contract_error(exc: ValidationError) -> ContractError | None:
    for err in exc.errors():
        inner = err.get("ctx", {}).get("error")
        if isinstance(inner, ContractError):
            return inner
    return None


def _safe_loc(loc: Iterable[int | str]) -> str:
    parts = [str(p) if isinstance(p, int) or _SAFE_LOC_RE.match(p) else "<key>" for p in loc]
    return ".".join(parts) or "<root>"


def _describe(exc: ValidationError, limit: int = 20) -> list[str]:
    return [f"{_safe_loc(e['loc'])}: {e['msg']}" for e in exc.errors()[:limit]]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError as exc:
            inner = _find_contract_error(exc)
            if inner is not None:
                raise inner from exc
            raise ContractError(
                "invalid_contract", f"{type(self).__name__}: " + "; ".join(_describe(exc))
            ) from exc


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ContractError("invalid_contract", "datetime must be timezone-aware")
    return value.astimezone(UTC)


def _normalize_guid(value: str, what: str) -> str:
    if not _GUID_RE.match(value):
        raise ContractError("invalid_contract", f"{what} must be a GUID")
    return value.lower()


def _canonical_alert_id(alert_id: str) -> str:
    if alert_id.lower().startswith(_ARM_PREFIX):
        return alert_id.lower()
    return alert_id


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# ARM resource ids


class NormalizedResourceId(StrictModel):
    canonical: str
    subscription_id: str
    resource_group: str
    provider: str
    resource_type: str
    name: str

    @property
    def type_key(self) -> str:
        return f"{self.provider}/{self.resource_type}"

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        expected = (
            f"/subscriptions/{self.subscription_id}/resourcegroups/{self.resource_group}"
            f"/providers/{self.provider}/{self.resource_type}/{self.name}"
        )
        if self.canonical != expected or expected != expected.lower():
            raise ContractError(
                NormalizationErrorCode.MALFORMED_SCOPE, "inconsistent normalized resource id"
            )
        return self


def _malformed_scope(reason: str) -> AlertNormalizationError:
    return AlertNormalizationError(
        NormalizationErrorCode.MALFORMED_SCOPE, f"malformed ARM resource id: {reason}"
    )


def parse_resource_id(raw: str) -> NormalizedResourceId:
    """Parse a top-level ARM resource id into its lowercase canonical form."""
    if not isinstance(raw, str):
        raise _malformed_scope("not a string")
    value = raw.strip()
    if value.endswith("/"):
        value = value[:-1]
    if not value or len(value) > _MAX_RESOURCE_ID_LENGTH:
        raise _malformed_scope("empty or too long")
    if _FORBIDDEN_ID_CHARS.search(value):
        raise _malformed_scope("forbidden character")
    if not value.lower().startswith(_ARM_PREFIX):
        raise _malformed_scope("must start with /subscriptions/")
    segments = value[1:].split("/")
    if any(s in ("", ".", "..") for s in segments):
        raise _malformed_scope("empty or relative segment")
    if len(segments) < 8:
        raise _malformed_scope("too few segments")
    if len(segments) > 8:
        if (len(segments) - 8) % 2 == 0:
            raise AlertNormalizationError(
                NormalizationErrorCode.UNSUPPORTED_RESOURCE_TYPE,
                "nested child resources are not supported",
            )
        raise _malformed_scope("unexpected trailing segment")
    kw_sub, sub, kw_rg, rg, kw_prov, namespace, rtype, name = segments
    if (kw_sub.lower(), kw_rg.lower(), kw_prov.lower()) != (
        "subscriptions",
        "resourcegroups",
        "providers",
    ):
        raise _malformed_scope("unexpected keyword segment")
    if not _GUID_RE.match(sub):
        raise _malformed_scope("subscription is not a GUID")
    if not _RG_RE.match(rg) or rg.endswith("."):
        raise _malformed_scope("invalid resource group")
    if not _NAMESPACE_RE.match(namespace) or namespace.endswith("."):
        raise _malformed_scope("invalid provider namespace")
    if not _TYPE_RE.match(rtype):
        raise _malformed_scope("invalid resource type")
    if not _NAME_RE.match(name):
        raise _malformed_scope("invalid resource name")
    sub, rg, namespace, rtype, name = (
        sub.lower(),
        rg.lower(),
        namespace.lower(),
        rtype.lower(),
        name.lower(),
    )
    return NormalizedResourceId(
        canonical=(
            f"/subscriptions/{sub}/resourcegroups/{rg}/providers/{namespace}/{rtype}/{name}"
        ),
        subscription_id=sub,
        resource_group=rg,
        provider=namespace,
        resource_type=rtype,
        name=name,
    )


def _target_kind(resource: NormalizedResourceId) -> TargetKind:
    kind = KNOWN_TARGET_TYPES.get(resource.type_key)
    if kind is None:
        raise AlertNormalizationError(
            NormalizationErrorCode.UNSUPPORTED_RESOURCE_TYPE,
            f"unsupported resource type {resource.type_key}",
        )
    return kind


def _canonical_of_kind(raw: str, expected: TargetKind) -> str:
    resource = parse_resource_id(raw)
    if _target_kind(resource) is not expected:
        raise AlertNormalizationError(
            NormalizationErrorCode.UNSUPPORTED_RESOURCE_TYPE,
            f"resource id must be of kind {expected.value}",
        )
    return resource.canonical


# ---------------------------------------------------------------------------
# Registry


class ApplicationMapping(StrictModel):
    app_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
    environment: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{0,31}$")]
    subscription_id: str
    container_app_id: str
    storage_account_id: str | None = None
    app_insights_component_id: str
    log_analytics_workspace_id: str
    log_analytics_workspace_resource_id: str | None = None
    app_insights_workspace_id: str | None = None
    app_insights_workspace_resource_id: str | None = None
    repository: Repository
    installation_id: Annotated[int, Field(strict=True, gt=0)]

    @field_validator("subscription_id")
    @classmethod
    def _subscription(cls, value: str) -> str:
        return _normalize_guid(value, "subscription_id")

    @field_validator("log_analytics_workspace_id")
    @classmethod
    def _workspace_guid(cls, value: str) -> str:
        return _normalize_guid(value, "log_analytics_workspace_id")

    @field_validator("app_insights_workspace_id")
    @classmethod
    def _ai_workspace_guid(cls, value: str | None) -> str | None:
        return None if value is None else _normalize_guid(value, "app_insights_workspace_id")

    @field_validator("container_app_id")
    @classmethod
    def _container_app(cls, value: str) -> str:
        return _canonical_of_kind(value, TargetKind.CONTAINER_APP)

    @field_validator("storage_account_id")
    @classmethod
    def _storage_account(cls, value: str | None) -> str | None:
        if value is None:
            return None
        resource = parse_resource_id(value)
        if resource.type_key != "microsoft.storage/storageaccounts":
            raise ContractError("invalid_mapping", "dependency must be a storage account")
        if not re.fullmatch(r"[a-z0-9]{3,24}", resource.name):
            raise ContractError("invalid_mapping", "invalid storage account name")
        return resource.canonical

    @field_validator("app_insights_component_id")
    @classmethod
    def _component(cls, value: str) -> str:
        return _canonical_of_kind(value, TargetKind.APP_INSIGHTS_COMPONENT)

    @field_validator("log_analytics_workspace_resource_id", "app_insights_workspace_resource_id")
    @classmethod
    def _workspace_resource(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _canonical_of_kind(value, TargetKind.LOG_ANALYTICS_WORKSPACE)

    @model_validator(mode="after")
    def _same_subscription(self) -> Self:
        if (self.app_insights_workspace_id is None) != (
            self.app_insights_workspace_resource_id is None
        ):
            raise ContractError("invalid_mapping", "App Insights workspace fields must be paired")
        for canonical in (
            *self.arm_ids(),
            *((self.storage_account_id,) if self.storage_account_id else ()),
        ):
            if parse_resource_id(canonical).subscription_id != self.subscription_id:
                raise ContractError(
                    NormalizationErrorCode.CROSS_SUBSCRIPTION,
                    f"mapping {self.app_id}: resource id outside subscription_id",
                )
        return self

    def arm_ids(self) -> tuple[str, ...]:
        ids = [self.container_app_id, self.app_insights_component_id]
        if self.log_analytics_workspace_resource_id is not None:
            ids.append(self.log_analytics_workspace_resource_id)
        if self.app_insights_workspace_resource_id is not None:
            ids.append(self.app_insights_workspace_resource_id)
        return tuple(ids)

    def target_kinds(self) -> dict[str, TargetKind]:
        kinds = {
            self.container_app_id: TargetKind.CONTAINER_APP,
            self.app_insights_component_id: TargetKind.APP_INSIGHTS_COMPONENT,
        }
        if self.log_analytics_workspace_resource_id is not None:
            kinds[self.log_analytics_workspace_resource_id] = TargetKind.LOG_ANALYTICS_WORKSPACE
        return kinds


class ApplicationRegistry(StrictModel):
    schema_version: Literal[1]
    tenant_id: str
    applications: Annotated[tuple[ApplicationMapping, ...], Field(min_length=1)]

    @field_validator("tenant_id")
    @classmethod
    def _tenant(cls, value: str) -> str:
        return _normalize_guid(value, "tenant_id")

    @model_validator(mode="after")
    def _no_conflicts(self) -> Self:
        app_ids: set[str] = set()
        arm_owner: dict[str, str] = {}
        workspace_owner: dict[str, str] = {}
        for mapping in self.applications:
            if mapping.app_id in app_ids:
                raise ContractError(
                    "registry_conflict", f"conflicting mapping: duplicate app_id {mapping.app_id}"
                )
            app_ids.add(mapping.app_id)
            for canonical in mapping.arm_ids():
                owner = arm_owner.setdefault(canonical, mapping.app_id)
                if owner != mapping.app_id:
                    raise ContractError(
                        "registry_conflict",
                        f"conflicting mapping: resource mapped to {owner} and {mapping.app_id}",
                    )
            owner = workspace_owner.setdefault(mapping.log_analytics_workspace_id, mapping.app_id)
            if owner != mapping.app_id:
                raise ContractError(
                    "registry_conflict",
                    f"conflicting mapping: workspace mapped to {owner} and {mapping.app_id}",
                )
        return self

    def fingerprint(self) -> str:
        return _sha256_hex(_canonical_json(self.model_dump(mode="json")))

    def get(self, app_id: str) -> ApplicationMapping | None:
        return next((m for m in self.applications if m.app_id == app_id), None)

    def subscription_ids(self) -> frozenset[str]:
        return frozenset(m.subscription_id for m in self.applications)

    def resolve_target(self, canonical_id: str) -> tuple[ApplicationMapping, TargetKind] | None:
        key = canonical_id.strip().lower()
        for mapping in self.applications:
            kind = mapping.target_kinds().get(key)
            if kind is not None:
                return mapping, kind
        return None


# ---------------------------------------------------------------------------
# Common Alert Schema input (lenient about unknown keys, strict about typed fields)

_CAS_CONFIG: Final = ConfigDict(extra="ignore", frozen=True, str_strip_whitespace=True)


def _match_enum[E: StrEnum](enum: type[E], value: object, what: str) -> E:
    if isinstance(value, str):
        wanted = value.strip().lower()
        for member in enum:
            if member.value.lower() == wanted:
                return member
    raise ValueError(f"unsupported {what}")


class CommonAlertEssentials(BaseModel):
    model_config = _CAS_CONFIG

    alertId: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    alertRule: Annotated[str, StringConstraints(max_length=512)] | None = None
    severity: Severity
    signalType: SignalType
    monitoringService: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    monitorCondition: MonitorCondition
    alertTargetIDs: list[str]
    firedDateTime: AwareDatetime
    resolvedDateTime: AwareDatetime | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, value: object) -> Severity:
        return _match_enum(Severity, value, "severity")

    @field_validator("signalType", mode="before")
    @classmethod
    def _signal_type(cls, value: object) -> SignalType:
        return _match_enum(SignalType, value, "signalType")

    @field_validator("monitorCondition", mode="before")
    @classmethod
    def _monitor_condition(cls, value: object) -> MonitorCondition:
        return _match_enum(MonitorCondition, value, "monitorCondition")

    @field_validator("alertTargetIDs")
    @classmethod
    def _targets(cls, value: list[str]) -> list[str]:
        if not value:
            raise AlertNormalizationError(NormalizationErrorCode.NO_TARGETS, "no alert targets")
        if len(value) > MAX_TARGETS_PER_ALERT:
            raise AlertNormalizationError(
                NormalizationErrorCode.TOO_MANY_TARGETS, "too many alert targets"
            )
        return value

    @field_validator("firedDateTime", "resolvedDateTime")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def _lifecycle(self) -> Self:
        if self.monitorCondition is MonitorCondition.FIRED:
            if self.resolvedDateTime is not None:
                raise AlertNormalizationError(
                    NormalizationErrorCode.INVALID_LIFECYCLE,
                    "fired alert must not carry resolvedDateTime",
                )
        elif self.resolvedDateTime is None:
            raise AlertNormalizationError(
                NormalizationErrorCode.INVALID_LIFECYCLE,
                "resolved alert requires resolvedDateTime",
            )
        elif self.resolvedDateTime < self.firedDateTime:
            raise AlertNormalizationError(
                NormalizationErrorCode.INVALID_LIFECYCLE,
                "resolvedDateTime precedes firedDateTime",
            )
        return self


class CommonAlertData(BaseModel):
    model_config = _CAS_CONFIG

    essentials: CommonAlertEssentials
    alertContext: dict[str, Any] | None = None
    customProperties: dict[str, Any] | None = None


class CommonAlertPayload(BaseModel):
    model_config = _CAS_CONFIG

    schemaId: str
    data: CommonAlertData

    @field_validator("schemaId")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != ALERT_SCHEMA_ID:
            raise AlertNormalizationError(
                NormalizationErrorCode.UNSUPPORTED_SCHEMA, "unsupported alert schemaId"
            )
        return value


# ---------------------------------------------------------------------------
# Normalized output


class DiagnosticWindow(StrictModel):
    start: AwareDatetime
    end: AwareDatetime

    @field_validator("start", "end")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.end <= self.start:
            raise ContractError("invalid_window", "window end must be after start")
        return self


class AlertContextHints(StrictModel):
    window_start: AwareDatetime | None = None
    window_end: AwareDatetime | None = None
    metric_names: Annotated[tuple[str, ...], Field(max_length=MAX_METRIC_NAMES)] = ()
    search_results_embedded: bool = False

    @field_validator("window_start", "window_end")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else value.astimezone(UTC)

    @field_validator("metric_names")
    @classmethod
    def _names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _METRIC_NAME_RE.match(n) for n in value):
            raise ContractError("invalid_contract", "invalid metric name")
        return value

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if (
            self.window_start is not None
            and self.window_end is not None
            and self.window_end < self.window_start
        ):
            raise ContractError("invalid_contract", "context window end precedes start")
        return self


class NormalizedTarget(StrictModel):
    canonical_id: str
    kind: TargetKind

    @model_validator(mode="after")
    def _canonical(self) -> Self:
        resource = parse_resource_id(self.canonical_id)
        if resource.canonical != self.canonical_id or _target_kind(resource) is not self.kind:
            raise ContractError("invalid_contract", "target is not canonical or kind mismatches")
        return self


class NormalizedAlert(StrictModel):
    schema_version: Literal[1] = 1
    sink: Sink
    incident_key: Sha256Hex
    delivery_id: Sha256Hex
    alert_id: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    alert_rule: str | None
    monitor_condition: MonitorCondition
    severity: Severity
    signal_type: SignalType
    monitoring_service: str
    app_id: str
    environment: str
    tenant_id: str
    subscription_id: str
    repository: Repository
    installation_id: Annotated[int, Field(strict=True, gt=0)]
    container_app_id: str
    app_insights_component_id: str
    log_analytics_workspace_id: str
    targets: Annotated[tuple[NormalizedTarget, ...], Field(min_length=1)]
    fired_at: AwareDatetime
    resolved_at: AwareDatetime | None
    context: AlertContextHints
    registry_fingerprint: Sha256Hex

    @field_validator("fired_at", "resolved_at")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if (self.monitor_condition is MonitorCondition.RESOLVED) != (self.resolved_at is not None):
            raise AlertNormalizationError(
                NormalizationErrorCode.INVALID_LIFECYCLE, "resolved_at inconsistent with condition"
            )
        if self.resolved_at is not None and self.resolved_at < self.fired_at:
            raise AlertNormalizationError(
                NormalizationErrorCode.INVALID_LIFECYCLE, "resolved_at precedes fired_at"
            )
        if self.incident_key != incident_key(self.app_id, self.alert_id):
            raise ContractError("invalid_contract", "incident_key mismatch")
        ids = [t.canonical_id for t in self.targets]
        if len(ids) != len(set(ids)):
            raise ContractError("invalid_contract", "duplicate targets")
        return self

    @property
    def condition_time(self) -> datetime:
        return self.resolved_at if self.resolved_at is not None else self.fired_at


def incident_key(app_id: str, alert_id: str) -> str:
    """Stable key shared by the Fired and Resolved notifications of one alert."""
    return _sha256_hex(f"{app_id}\x1f{_canonical_alert_id(alert_id)}")


def delivery_id(
    app_id: str, alert_id: str, condition: MonitorCondition, condition_time: datetime
) -> str:
    """Deterministic id of one lifecycle notification; identical for redeliveries."""
    document = {
        "app_id": app_id,
        "alert_id": _canonical_alert_id(alert_id),
        "condition": MonitorCondition(condition).value,
        "condition_time": _to_utc(condition_time).isoformat(timespec="microseconds"),
    }
    return _sha256_hex(_canonical_json(document))


def _validate_minutes(value: int, upper: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= upper:
        raise ContractError("invalid_window", f"{what} must be an integer in [0, {upper}]")
    return value


def incident_window(
    alert: NormalizedAlert, *, before_minutes: int, after_minutes: int
) -> DiagnosticWindow:
    """Onset-anchored window of exactly ``before + after`` minutes.

    Anchored on ``fired_at`` so delayed deliveries and long-lived alerts never widen the
    query; the window is independent of when the alert was processed or resolved.
    """
    before = _validate_minutes(before_minutes, HARD_MAX_WINDOW_BEFORE_MINUTES, "before_minutes")
    after = _validate_minutes(after_minutes, HARD_MAX_WINDOW_AFTER_MINUTES, "after_minutes")
    return DiagnosticWindow(
        start=alert.fired_at - timedelta(minutes=before),
        end=alert.fired_at + timedelta(minutes=after),
    )


def _parse_hint_time(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _has_search_results(context: Mapping[str, Any]) -> bool:
    for key in ("SearchResults", "searchResults"):
        if context.get(key):
            return True
    flag = context.get("IncludedSearchResults")
    if isinstance(flag, bool):
        return flag
    return isinstance(flag, str) and flag.strip().lower() == "true"


def _context_hints(context: Mapping[str, Any] | None) -> AlertContextHints:
    if not context:
        return AlertContextHints()
    condition = context.get("condition")
    condition = condition if isinstance(condition, Mapping) else {}
    start = _parse_hint_time(context.get("windowStartTime", condition.get("windowStartTime")))
    end = _parse_hint_time(context.get("windowEndTime", condition.get("windowEndTime")))
    if start is not None and end is not None and end < start:
        start = end = None
    names: list[str] = []
    criteria = condition.get("allOf")
    if isinstance(criteria, list):
        for criterion in criteria:
            name = criterion.get("metricName") if isinstance(criterion, Mapping) else None
            if (
                isinstance(name, str)
                and _METRIC_NAME_RE.match(name.strip())
                and name.strip() not in names
            ):
                names.append(name.strip())
    return AlertContextHints(
        window_start=start,
        window_end=end,
        metric_names=tuple(names[:MAX_METRIC_NAMES]),
        search_results_embedded=_has_search_results(context),
    )


def _malformed(message: str) -> AlertNormalizationError:
    return AlertNormalizationError(NormalizationErrorCode.MALFORMED, message)


def _too_large() -> AlertNormalizationError:
    return AlertNormalizationError(
        NormalizationErrorCode.PAYLOAD_TOO_LARGE, "alert payload exceeds size limit"
    )


def _load_payload(payload: Mapping[str, Any] | str | bytes) -> Any:
    if isinstance(payload, str | bytes | bytearray):
        try:
            raw = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        except UnicodeError as exc:
            raise _malformed("payload is not valid UTF-8") from exc
        if len(raw) > MAX_ALERT_PAYLOAD_BYTES:
            raise _too_large()
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise _malformed("payload is not valid JSON") from exc
    if isinstance(payload, Mapping):
        try:
            size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise _malformed("payload is not JSON-serializable") from exc
        if size > MAX_ALERT_PAYLOAD_BYTES:
            raise _too_large()
        return payload
    raise _malformed("unsupported payload type")


def normalize_alert(
    payload: Mapping[str, Any] | str | bytes,
    registry: ApplicationRegistry,
    *,
    sink: Sink = Sink.PRODUCTION,
) -> NormalizedAlert:
    """Validate a Common Alert Schema webhook and bind it to exactly one application."""
    resolved_sink = Sink(sink)
    document = _load_payload(payload)
    if not isinstance(document, Mapping):
        raise _malformed("payload must be a JSON object")
    try:
        cas = CommonAlertPayload.model_validate(document)
    except ValidationError as exc:
        inner = _find_contract_error(exc)
        if isinstance(inner, AlertNormalizationError):
            raise inner from exc
        raise _malformed("payload does not match the Common Alert Schema") from exc
    essentials = cas.data.essentials

    resources: dict[str, NormalizedResourceId] = {}
    for raw in essentials.alertTargetIDs:
        resource = parse_resource_id(raw)
        _target_kind(resource)
        resources.setdefault(resource.canonical, resource)

    known_subscriptions = registry.subscription_ids()
    mapping: ApplicationMapping | None = None
    targets: list[NormalizedTarget] = []
    for canonical, resource in resources.items():
        resolved = registry.resolve_target(canonical)
        if resolved is None:
            if resource.subscription_id not in known_subscriptions:
                raise AlertNormalizationError(
                    NormalizationErrorCode.CROSS_SUBSCRIPTION,
                    "alert target is in a subscription not covered by the registry",
                )
            raise AlertNormalizationError(
                NormalizationErrorCode.UNKNOWN_SCOPE, "alert target is not in the registry"
            )
        target_mapping, kind = resolved
        if mapping is not None and mapping.app_id != target_mapping.app_id:
            raise AlertNormalizationError(
                NormalizationErrorCode.MIXED_APPLICATIONS,
                "alert targets resolve to more than one application",
            )
        mapping = target_mapping
        targets.append(NormalizedTarget(canonical_id=canonical, kind=kind))
    if mapping is None:
        raise AlertNormalizationError(NormalizationErrorCode.NO_TARGETS, "no alert targets")

    alert_id = _canonical_alert_id(essentials.alertId)
    condition = essentials.monitorCondition
    condition_time = (
        essentials.resolvedDateTime
        if essentials.resolvedDateTime is not None
        else essentials.firedDateTime
    )
    return NormalizedAlert(
        sink=resolved_sink,
        incident_key=incident_key(mapping.app_id, alert_id),
        delivery_id=delivery_id(mapping.app_id, alert_id, condition, condition_time),
        alert_id=alert_id,
        alert_rule=essentials.alertRule,
        monitor_condition=condition,
        severity=essentials.severity,
        signal_type=essentials.signalType,
        monitoring_service=essentials.monitoringService,
        app_id=mapping.app_id,
        environment=mapping.environment,
        tenant_id=registry.tenant_id,
        subscription_id=mapping.subscription_id,
        repository=mapping.repository,
        installation_id=mapping.installation_id,
        container_app_id=mapping.container_app_id,
        app_insights_component_id=mapping.app_insights_component_id,
        log_analytics_workspace_id=mapping.log_analytics_workspace_id,
        targets=tuple(targets),
        fired_at=essentials.firedDateTime,
        resolved_at=essentials.resolvedDateTime,
        context=_context_hints(cas.data.alertContext),
        registry_fingerprint=registry.fingerprint(),
    )


# ---------------------------------------------------------------------------
# Evidence


class EvidenceProvenance(StrictModel):
    source: EvidenceSource
    template_id: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_.-]{1,64}$")]
    scope_ref: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    window: DiagnosticWindow
    collected_at: AwareDatetime

    @field_validator("collected_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


class EvidenceError(StrictModel):
    category: EvidenceStatus
    message: Annotated[str, StringConstraints(min_length=1, max_length=300)]

    @field_validator("category")
    @classmethod
    def _not_ok(cls, value: EvidenceStatus) -> EvidenceStatus:
        if value is EvidenceStatus.OK:
            raise ContractError("invalid_evidence", "error category must not be ok")
        return value


class EvidenceItem(StrictModel):
    evidence_id: Annotated[str, StringConstraints(pattern=_EVIDENCE_ID_PATTERN)]
    provenance: EvidenceProvenance
    status: EvidenceStatus
    summary: Annotated[str, StringConstraints(max_length=1000)] = ""
    rows: Annotated[
        tuple[dict[str, JsonScalar], ...], Field(max_length=HARD_MAX_ROWS_PER_QUERY)
    ] = ()
    row_count: Annotated[int, Field(strict=True, ge=0)]
    truncated: bool = False
    redacted: Literal[True] = True
    error: EvidenceError | None = None

    @field_validator("rows")
    @classmethod
    def _row_keys(
        cls, value: tuple[dict[str, JsonScalar], ...]
    ) -> tuple[dict[str, JsonScalar], ...]:
        for row in value:
            if any(not key or len(key) > 64 for key in row):
                raise ContractError("invalid_evidence", "row keys must be 1..64 characters")
        return value

    @model_validator(mode="after")
    def _status_rules(self) -> Self:
        def fail(message: str) -> ContractError:
            return ContractError("invalid_evidence", f"{self.evidence_id}: {message}")

        if self.row_count < len(self.rows):
            raise fail("row_count is less than the number of rows")
        if self.status is EvidenceStatus.OK:
            if self.row_count == 0 and not self.summary:
                raise fail("ok evidence needs rows or a summary")
            if self.error is not None:
                raise fail("ok evidence must not carry an error")
        elif self.status is EvidenceStatus.ZERO_ROWS:
            if self.row_count != 0 or self.rows or self.error is not None:
                raise fail("zero_rows evidence must have no rows and no error")
        elif self.status in _ERROR_STATUSES:
            if self.error is None or self.rows:
                raise fail("failed evidence requires an error and no rows")
        return self


class EvidenceBundle(StrictModel):
    incident_key: Sha256Hex
    items: tuple[EvidenceItem, ...] = ()

    @model_validator(mode="after")
    def _bounded(self) -> Self:
        ids = [item.evidence_id for item in self.items]
        if len(ids) != len(set(ids)):
            raise ContractError("invalid_evidence", "evidence ids must be unique")
        if self.byte_size() > HARD_MAX_EVIDENCE_BYTES:
            raise ContractError("evidence_too_large", "evidence bundle exceeds size limit")
        return self

    def get(self, evidence_id: str) -> EvidenceItem | None:
        return next((i for i in self.items if i.evidence_id == evidence_id), None)

    def ids(self) -> frozenset[str]:
        return frozenset(item.evidence_id for item in self.items)

    def byte_size(self) -> int:
        return len(self.model_dump_json().encode("utf-8"))


# ---------------------------------------------------------------------------
# Report

_Refs = Annotated[tuple[EvidenceRef, ...], Field(min_length=1)]
_OptionalRefs = tuple[EvidenceRef, ...]


class ReportSymptom(StrictModel):
    text: ReportText
    evidence_refs: _Refs


class ChronologyEntry(StrictModel):
    at: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    text: ReportText
    evidence_refs: _Refs


class Observation(StrictModel):
    text: ReportText
    evidence_refs: _Refs


class Hypothesis(StrictModel):
    statement: ReportText
    support_refs: _OptionalRefs = ()
    contradiction_refs: _OptionalRefs = ()
    verdict: Literal["supported", "contradicted", "unverified"]

    @model_validator(mode="after")
    def _verdict_refs(self) -> Self:
        if self.verdict == "supported" and not self.support_refs:
            raise ContractError("invalid_report", "supported hypothesis requires support_refs")
        if self.verdict == "contradicted" and not self.contradiction_refs:
            raise ContractError(
                "invalid_report", "contradicted hypothesis requires contradiction_refs"
            )
        return self


class DeveloperAction(StrictModel):
    text: ReportText
    evidence_refs: _OptionalRefs = ()


class ReportGap(StrictModel):
    description: ReportText
    category: PartialCategory
    evidence_refs: _OptionalRefs = ()


class ModelReportDraft(StrictModel):
    status: Literal["complete", "partial"]
    summary: Annotated[str, StringConstraints(min_length=1, max_length=1000)]
    symptoms: tuple[ReportSymptom, ...] = ()
    chronology: tuple[ChronologyEntry, ...] = ()
    observations: tuple[Observation, ...] = ()
    hypotheses: tuple[Hypothesis, ...] = ()
    developer_actions: tuple[DeveloperAction, ...] = ()
    gaps: tuple[ReportGap, ...] = ()

    def ref_groups(self) -> tuple[tuple[str, tuple[str, ...], bool], ...]:
        """Return ``(path, refs, requires_ok_evidence)`` for every reference list."""
        groups: list[tuple[str, tuple[str, ...], bool]] = []
        groups += [(f"symptoms[{i}]", e.evidence_refs, True) for i, e in enumerate(self.symptoms)]
        groups += [
            (f"chronology[{i}]", e.evidence_refs, True) for i, e in enumerate(self.chronology)
        ]
        groups += [
            (f"observations[{i}]", e.evidence_refs, True) for i, e in enumerate(self.observations)
        ]
        for i, h in enumerate(self.hypotheses):
            groups.append(
                (f"hypotheses[{i}].support_refs", h.support_refs, h.verdict != "unverified")
            )
            groups.append(
                (
                    f"hypotheses[{i}].contradiction_refs",
                    h.contradiction_refs,
                    h.verdict == "supported",
                )
            )
        groups += [
            (f"developer_actions[{i}]", e.evidence_refs, False)
            for i, e in enumerate(self.developer_actions)
        ]
        groups += [(f"gaps[{i}]", e.evidence_refs, False) for i, e in enumerate(self.gaps)]
        return tuple(groups)

    def all_refs(self) -> frozenset[str]:
        return frozenset(ref for _, refs, _ in self.ref_groups() for ref in refs)

    @model_validator(mode="after")
    def _complete_rules(self) -> Self:
        if self.status == "complete":
            if self.gaps:
                raise ContractError("invalid_report", "complete report must not declare gaps")
            if not self.observations and not self.symptoms:
                raise ContractError(
                    "invalid_report", "complete report requires at least one observation or symptom"
                )
        return self


class InvestigationReport(StrictModel):
    schema_version: Literal[1]
    incident_key: Sha256Hex
    alert_id: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    app_id: str
    severity: Severity
    sink: Sink
    generated_at: AwareDatetime
    status: Literal["complete", "partial"]
    partial_category: PartialCategory | None = None
    evidence: EvidenceBundle
    draft: ModelReportDraft | None = None
    host_gaps: tuple[ReportGap, ...] = ()

    @field_validator("generated_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _envelope(self) -> Self:
        def fail(message: str) -> ContractError:
            return ContractError("invalid_report", message)

        if self.draft is None:
            if self.status != "partial" or self.partial_category is None:
                raise fail("report without draft must be partial with a partial_category")
        elif self.draft.status != self.status:
            raise fail("report status must match draft status")
        if self.status == "complete":
            if self.partial_category is not None or self.host_gaps:
                raise fail("complete report must not carry partial_category or host_gaps")
        elif self.partial_category is None:
            raise fail("partial report requires partial_category")
        if self.evidence.incident_key != self.incident_key:
            raise fail("evidence incident_key does not match report")
        problems = _reference_problems(self.draft, self.evidence, self.host_gaps)
        if problems:
            raise fail("; ".join(problems))
        return self


def _check_refs(
    path: str,
    refs: Iterable[str],
    evidence: EvidenceBundle,
    problems: list[str],
    *,
    require_ok: bool,
) -> None:
    for ref in refs:
        item = evidence.get(ref)
        if item is None:
            problems.append(f"{path}: unknown evidence id {ref}")
        elif require_ok and item.status is not EvidenceStatus.OK:
            problems.append(f"{path}: {ref} has status {item.status.value} and cannot support it")


def _reference_problems(
    draft: ModelReportDraft | None,
    evidence: EvidenceBundle,
    host_gaps: Iterable[ReportGap] = (),
) -> list[str]:
    """Shared reference check: every ref must exist and supporting refs must be OK evidence."""
    problems: list[str] = []
    if draft is not None:
        for path, refs, require_ok in draft.ref_groups():
            _check_refs(path, refs, evidence, problems, require_ok=require_ok)
    for index, gap in enumerate(host_gaps):
        _check_refs(f"host_gaps[{index}]", gap.evidence_refs, evidence, problems, require_ok=False)
    return problems


def validate_model_output(
    raw: str | Mapping[str, Any], evidence: EvidenceBundle
) -> ModelReportDraft:
    """Validate untrusted model output against the schema and the collected evidence."""
    if isinstance(raw, str):
        if len(raw.encode("utf-8", errors="replace")) > MAX_MODEL_OUTPUT_BYTES:
            raise ReportValidationError(["model output exceeds size limit"])
        try:
            document: Any = json.loads(raw)
        except ValueError as exc:
            raise ReportValidationError(["model output is not valid JSON"]) from exc
    elif isinstance(raw, Mapping):
        try:
            size = len(json.dumps(raw, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ReportValidationError(["model output is not JSON-serializable"]) from exc
        if size > MAX_MODEL_OUTPUT_BYTES:
            raise ReportValidationError(["model output exceeds size limit"])
        document = raw
    else:
        raise ReportValidationError(["unsupported model output type"])
    if not isinstance(document, Mapping):
        raise ReportValidationError(["model output must be a JSON object"])
    try:
        draft = ModelReportDraft.model_validate(document)
    except ValidationError as exc:
        raise ReportValidationError(_describe(exc)) from exc

    problems = _reference_problems(draft, evidence)
    if problems:
        raise ReportValidationError(problems)
    return draft


# ---------------------------------------------------------------------------
# Publication


class PublicationRecord(StrictModel):
    repository: Repository
    issue_number: Annotated[int, Field(strict=True, gt=0)]
    issue_url: str
    incident_key: Sha256Hex
    marker: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    recovery_comment_id: Annotated[int, Field(strict=True, gt=0)] | None = None

    @model_validator(mode="after")
    def _url_matches(self) -> Self:
        expected = f"https://github.com/{self.repository}/issues/{self.issue_number}"
        if self.issue_url.lower() != expected.lower() or not self.issue_url.startswith(
            "https://github.com/"
        ):
            raise ContractError("invalid_publication", "issue_url does not match repository")
        return self
