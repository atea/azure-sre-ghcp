"""Fixed, approved diagnostic templates.

Every CLI argv and KQL string is produced here from validated values only. Model input never
reaches these builders; it can only select a template kind and a bounded operation id.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from azure_sre.contracts import ApplicationMapping, DiagnosticWindow, parse_resource_id

_RESOURCE_ID_RE: Final = re.compile(r"^/[A-Za-z0-9/._()-]{1,900}$")
_NAME_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_OPERATION_ID_RE: Final = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_GUID_RE: Final = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class DiagnosticKind(StrEnum):
    """Closed set of diagnostics the collector can run. Values match ``EvidenceSource``."""

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


class TemplateError(ValueError):
    """Raised when a template input fails validation. Never carries raw model text."""


@dataclass(frozen=True)
class QueryContext:
    mapping: ApplicationMapping
    window: DiagnosticWindow
    operation_id: str | None
    row_limit: int


@dataclass(frozen=True)
class Template:
    kind: DiagnosticKind
    template_id: str
    fields: tuple[str, ...]
    supports_operation_id: bool
    build_argv: Callable[[QueryContext], tuple[str, ...]]


def iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _kql_time_filter(window: DiagnosticWindow) -> str:
    return (
        f"TimeGenerated between (datetime({iso_utc(window.start)}) .. "
        f"datetime({iso_utc(window.end)}))"
    )


def _kql_string(value: str) -> str:
    """Single-quoted KQL literal; only ever called on values that passed strict regexes."""
    if not re.fullmatch(r"[A-Za-z0-9/._()-]{1,900}", value):
        raise TemplateError("unsafe value for KQL literal")
    return f"'{value}'"


def _validate_resource_id(value: str) -> str:
    if not _RESOURCE_ID_RE.fullmatch(value):
        raise TemplateError("resource id has unsupported characters")
    return value


def _validate_name(value: str) -> str:
    if not _NAME_RE.fullmatch(value):
        raise TemplateError("resource name has unsupported characters")
    return value


def _container_app_parts(mapping: ApplicationMapping) -> tuple[str, str, str]:
    resource = parse_resource_id(mapping.container_app_id)
    return (
        _validate_name(resource.name),
        _validate_name(resource.resource_group),
        mapping.subscription_id,
    )


def _workspace_guid(mapping: ApplicationMapping) -> str:
    if not _GUID_RE.fullmatch(mapping.log_analytics_workspace_id):
        raise TemplateError("workspace id must be a GUID")
    return mapping.log_analytics_workspace_id


def _ai_component_id(mapping: ApplicationMapping) -> str:
    return _validate_resource_id(mapping.app_insights_component_id)


def _container_app_id(mapping: ApplicationMapping) -> str:
    return _validate_resource_id(mapping.container_app_id)


def _operation_filter(ctx: QueryContext) -> str:
    if ctx.operation_id is None:
        return ""
    if not _OPERATION_ID_RE.fullmatch(ctx.operation_id):
        raise TemplateError("operation id has unsupported characters")
    return f"| where OperationId == '{ctx.operation_id}'"


def _log_query_argv(ctx: QueryContext, kql: str, *, app_insights: bool = False) -> tuple[str, ...]:
    """``--flag=value`` form so a value can never be parsed as an option."""
    workspace = (
        ctx.mapping.app_insights_workspace_id
        if app_insights and ctx.mapping.app_insights_workspace_id
        else _workspace_guid(ctx.mapping)
    )
    return (
        "az",
        "monitor",
        "log-analytics",
        "query",
        f"--workspace={workspace}",
        f"--analytics-query={kql}",
        f"--timespan={iso_utc(ctx.window.start)}/{iso_utc(ctx.window.end)}",
        "--output=json",
    )


def _health_argv(ctx: QueryContext) -> tuple[str, ...]:
    name, group, subscription = _container_app_parts(ctx.mapping)
    return (
        "az",
        "containerapp",
        "show",
        f"--name={name}",
        f"--resource-group={group}",
        f"--subscription={subscription}",
        "--output=json",
    )


def _revisions_argv(ctx: QueryContext) -> tuple[str, ...]:
    name, group, subscription = _container_app_parts(ctx.mapping)
    return (
        "az",
        "containerapp",
        "revision",
        "list",
        f"--name={name}",
        f"--resource-group={group}",
        f"--subscription={subscription}",
        "--output=json",
    )


def _exceptions_argv(ctx: QueryContext) -> tuple[str, ...]:
    kql = (
        f"AppExceptions | where {_kql_time_filter(ctx.window)} "
        f"| where _ResourceId =~ {_kql_string(_ai_component_id(ctx.mapping))} "
        f"{_operation_filter(ctx)} "
        "| order by TimeGenerated desc "
        "| project TimeGenerated, OperationId, ProblemId, ExceptionType, AppRoleName, OuterMessage "
        f"| take {ctx.row_limit + 1}"
    )
    return _log_query_argv(ctx, kql, app_insights=True)


def _operations_argv(ctx: QueryContext) -> tuple[str, ...]:
    component = _kql_string(_ai_component_id(ctx.mapping))
    time_filter = _kql_time_filter(ctx.window)
    kql = (
        "union isfuzzy=true "
        f"(AppRequests | where {time_filter} | where _ResourceId =~ {component} "
        "| extend ItemType = 'request'), "
        f"(AppDependencies | where {time_filter} | where _ResourceId =~ {component} "
        "| extend ItemType = 'dependency'), "
        f"(AppTraces | where {time_filter} | where _ResourceId =~ {component} "
        "| extend ItemType = 'trace') "
        f"{_operation_filter(ctx)} "
        "| order by TimeGenerated desc "
        "| project TimeGenerated, ItemType, OperationId, Name, Success, ResultCode, "
        "DurationMs, Target, Message, SeverityLevel "
        f"| take {ctx.row_limit + 1}"
    )
    return _log_query_argv(ctx, kql, app_insights=True)


def _ai_configuration_argv(ctx: QueryContext) -> tuple[str, ...]:
    return (
        "az",
        "resource",
        "show",
        f"--ids={_ai_component_id(ctx.mapping)}",
        "--api-version=2020-02-02",
        "--output=json",
    )


def _storage_configuration_argv(ctx: QueryContext) -> tuple[str, ...]:
    if ctx.mapping.storage_account_id is None:
        raise TemplateError("no trusted storage dependency configured")
    return (
        "az",
        "storage",
        "account",
        "show",
        f"--ids={_validate_resource_id(ctx.mapping.storage_account_id)}",
        "--output=json",
    )


def _console_logs_argv(ctx: QueryContext) -> tuple[str, ...]:
    kql = (
        f"ContainerAppConsoleLogs_CL | where {_kql_time_filter(ctx.window)} "
        f"| where {_container_log_scope(ctx.mapping)} "
        "| order by TimeGenerated desc "
        "| project TimeGenerated, RevisionName_s, ContainerName_s, Stream_s, Log_s "
        f"| take {ctx.row_limit + 1}"
    )
    return _log_query_argv(ctx, kql)


def _system_logs_argv(ctx: QueryContext) -> tuple[str, ...]:
    kql = (
        f"ContainerAppSystemLogs_CL | where {_kql_time_filter(ctx.window)} "
        f"| where {_container_log_scope(ctx.mapping)} "
        "| order by TimeGenerated desc "
        "| project TimeGenerated, RevisionName_s, Reason_s, Type_s, Msg_s "
        f"| take {ctx.row_limit + 1}"
    )
    return _log_query_argv(ctx, kql)


def _console_errors_argv(ctx: QueryContext) -> tuple[str, ...]:
    kql = (
        f"ContainerAppConsoleLogs_CL | where {_kql_time_filter(ctx.window)} "
        f"| where {_container_log_scope(ctx.mapping)} "
        "| extend ErrorKind = case("
        "Log_s has 'Failed to resolve', 'dependency_dns', "
        r"""Log_s matches regex '" [5][0-9]{2}( |$)', 'http_5xx', """
        "Log_s has_any ('ERROR', 'CRITICAL', 'Exception', 'Traceback'), 'application_error', '') "
        "| where isnotempty(ErrorKind) "
        "| summarize Occurrences=count(), FirstSeen=min(TimeGenerated), "
        "LastSeen=max(TimeGenerated), Log_s=take_any(substring(Log_s, 0, 1000)) "
        "by ErrorKind, RevisionName_s "
        "| order by Occurrences desc "
        f"| take {ctx.row_limit + 1}"
    )
    return _log_query_argv(ctx, kql)


def _container_log_scope(mapping: ApplicationMapping) -> str:
    name, _, _ = _container_app_parts(mapping)
    resource = _kql_string(_container_app_id(mapping))
    # The registry assigns this workspace to one application. Never fall back for a
    # conflicting resource ID, even when the row advertises the expected app name.
    return (
        f"(_ResourceId =~ {resource} or "
        f"(isempty(_ResourceId) and ContainerAppName_s =~ {_kql_string(name)}))"
    )


def _activity_argv(ctx: QueryContext) -> tuple[str, ...]:
    # --resource-id scopes the read to this one container app; no subscription-wide read.
    return (
        "az",
        "monitor",
        "activity-log",
        "list",
        f"--resource-id={_container_app_id(ctx.mapping)}",
        f"--start-time={iso_utc(ctx.window.start)}",
        f"--end-time={iso_utc(ctx.window.end)}",
        f"--max-events={ctx.row_limit + 1}",
        "--output=json",
    )


TEMPLATES: Final[Mapping[DiagnosticKind, Template]] = {
    DiagnosticKind.STORAGE_ACCOUNT_CONFIGURATION: Template(
        kind=DiagnosticKind.STORAGE_ACCOUNT_CONFIGURATION,
        template_id="storage-configuration-v1",
        fields=("id", "name", "provisioningState", "publicNetworkAccess"),
        supports_operation_id=False,
        build_argv=_storage_configuration_argv,
    ),
    DiagnosticKind.APP_INSIGHTS_CONFIGURATION: Template(
        kind=DiagnosticKind.APP_INSIGHTS_CONFIGURATION,
        template_id="ai-configuration-v1",
        fields=("properties.WorkspaceResourceId",),
        supports_operation_id=False,
        build_argv=_ai_configuration_argv,
    ),
    DiagnosticKind.CONTAINER_APP_HEALTH: Template(
        kind=DiagnosticKind.CONTAINER_APP_HEALTH,
        template_id="aca-health-v1",
        fields=(
            "name",
            "properties.provisioningState",
            "properties.runningStatus",
            "properties.latestReadyRevisionName",
            "properties.latestRevisionName",
        ),
        supports_operation_id=False,
        build_argv=_health_argv,
    ),
    DiagnosticKind.CONTAINER_APP_REVISIONS: Template(
        kind=DiagnosticKind.CONTAINER_APP_REVISIONS,
        template_id="aca-revisions-v1",
        fields=(
            "name",
            "properties.active",
            "properties.createdTime",
            "properties.healthState",
            "properties.provisioningState",
            "properties.runningState",
            "properties.trafficWeight",
            "properties.replicas",
        ),
        supports_operation_id=False,
        build_argv=_revisions_argv,
    ),
    DiagnosticKind.APP_INSIGHTS_EXCEPTIONS: Template(
        kind=DiagnosticKind.APP_INSIGHTS_EXCEPTIONS,
        template_id="ai-exceptions-v1",
        fields=(
            "TimeGenerated",
            "OperationId",
            "ProblemId",
            "ExceptionType",
            "AppRoleName",
            "OuterMessage",
        ),
        supports_operation_id=True,
        build_argv=_exceptions_argv,
    ),
    DiagnosticKind.APP_INSIGHTS_OPERATIONS: Template(
        kind=DiagnosticKind.APP_INSIGHTS_OPERATIONS,
        template_id="ai-operations-v1",
        fields=(
            "TimeGenerated",
            "ItemType",
            "OperationId",
            "Name",
            "Success",
            "ResultCode",
            "DurationMs",
            "Target",
            "Message",
            "SeverityLevel",
        ),
        supports_operation_id=True,
        build_argv=_operations_argv,
    ),
    DiagnosticKind.CONTAINER_APP_CONSOLE_LOGS: Template(
        kind=DiagnosticKind.CONTAINER_APP_CONSOLE_LOGS,
        template_id="aca-console-logs-v2",
        fields=("TimeGenerated", "RevisionName_s", "ContainerName_s", "Stream_s", "Log_s"),
        supports_operation_id=False,
        build_argv=_console_logs_argv,
    ),
    DiagnosticKind.CONTAINER_APP_SYSTEM_LOGS: Template(
        kind=DiagnosticKind.CONTAINER_APP_SYSTEM_LOGS,
        template_id="aca-system-logs-v2",
        fields=("TimeGenerated", "RevisionName_s", "Reason_s", "Type_s", "Msg_s"),
        supports_operation_id=False,
        build_argv=_system_logs_argv,
    ),
    DiagnosticKind.CONTAINER_APP_CONSOLE_ERRORS: Template(
        kind=DiagnosticKind.CONTAINER_APP_CONSOLE_ERRORS,
        template_id="aca-console-errors-v1",
        fields=(
            "ErrorKind",
            "RevisionName_s",
            "Occurrences",
            "FirstSeen",
            "LastSeen",
            "Log_s",
        ),
        supports_operation_id=False,
        build_argv=_console_errors_argv,
    ),
    DiagnosticKind.ACTIVITY_LOG_DEPLOYMENTS: Template(
        kind=DiagnosticKind.ACTIVITY_LOG_DEPLOYMENTS,
        template_id="activity-deployments-v1",
        fields=("eventTimestamp", "operationName.value", "status.value", "level"),
        supports_operation_id=False,
        build_argv=_activity_argv,
    ),
}


def project_row(
    source: Any, fields: Sequence[str]
) -> dict[str, str | int | float | bool | None] | None:
    """Keep only allowlisted scalar fields. Dotted paths read nested JSON objects.

    Returns ``None`` when no allowlisted field is present as a scalar, so a wrong-schema object is
    reported as malformed instead of appearing as a healthy row with every field empty.
    """
    out: dict[str, str | int | float | bool | None] = {}
    if not isinstance(source, Mapping):
        return None
    for field in fields:
        value: Any = source
        present = True
        for part in field.split("."):
            if isinstance(value, Mapping) and part in value:
                value = value[part]
            else:
                present = False
                break
        if present and (value is None or isinstance(value, str | int | float | bool)):
            out[field] = value
    return out or None


def project_storage_setting(
    source: Mapping[str, Any],
    mapping: ApplicationMapping,
) -> dict[str, str | bool]:
    """Extract exactly one approved non-secret setting, never arbitrary env values."""
    properties = source.get("properties")
    if not isinstance(properties, Mapping):
        return {}
    template = properties.get("template")
    if not isinstance(template, Mapping) or not isinstance(template.get("containers"), list):
        return {}
    values: set[str] = set()
    invalid = False
    for container in template["containers"]:
        if not isinstance(container, Mapping) or not isinstance(container.get("env", []), list):
            invalid = True
            continue
        for entry in container.get("env", []):
            if not isinstance(entry, Mapping) or entry.get("name") != "AZURE_STORAGE_ACCOUNT_NAME":
                continue
            value = entry.get("value")
            if (
                entry.get("secretRef")
                or not isinstance(value, str)
                or not re.fullmatch(
                    r"[a-z0-9]{3,24}",
                    value,
                )
            ):
                invalid = True
            else:
                values.add(value)
    out: dict[str, str | bool] = {}
    if invalid or len(values) != 1:
        out["storage.setting_status"] = "invalid_or_ambiguous" if invalid or values else "absent"
        return out
    account = next(iter(values))
    out["storage.configured_account"] = account
    out["storage.setting_status"] = "configured"
    if mapping.storage_account_id is not None:
        expected = parse_resource_id(mapping.storage_account_id).name
        out["storage.expected_account"] = expected
        out["storage.account_matches_registry"] = account == expected
    return out


def project_probe_assessment(source: Mapping[str, Any]) -> dict[str, str | int | bool]:
    """Describe explicit probes without treating a listening port as dependency health."""
    properties = source.get("properties")
    template = properties.get("template") if isinstance(properties, Mapping) else None
    containers = template.get("containers") if isinstance(template, Mapping) else None
    if not isinstance(containers, list) or not containers:
        return {"probes.assessment": "unknown"}
    tcp = http = absent = 0
    for container in containers:
        if not isinstance(container, Mapping):
            return {"probes.assessment": "unknown"}
        probes = container.get("probes", [])
        if not isinstance(probes, list) or any(not isinstance(p, Mapping) for p in probes):
            return {"probes.assessment": "unknown"}
        readiness = [p for p in probes if p.get("type") == "Readiness"]
        if not readiness:
            absent += 1
        for probe in readiness:
            if isinstance(probe.get("httpGet"), Mapping):
                http += 1
            elif isinstance(probe.get("tcpSocket"), Mapping):
                tcp += 1
            else:
                return {"probes.assessment": "unknown"}
    recommend = tcp > 0 or absent > 0
    return {
        "probes.assessment": "review_readiness" if recommend else "http_readiness_configured",
        "probes.tcp_readiness_count": tcp,
        "probes.http_readiness_count": http,
        "probes.containers_without_explicit_readiness": absent,
        "probes.suggest_dependency_readiness": recommend,
    }
