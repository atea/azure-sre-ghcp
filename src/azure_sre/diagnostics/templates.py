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
    CONTAINER_APP_REVISIONS = "container_app_revisions"
    APP_INSIGHTS_EXCEPTIONS = "app_insights_exceptions"
    APP_INSIGHTS_OPERATIONS = "app_insights_operations"
    CONTAINER_APP_CONSOLE_LOGS = "container_app_console_logs"
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


def _log_query_argv(ctx: QueryContext, kql: str) -> tuple[str, ...]:
    """``--flag=value`` form so a value can never be parsed as an option."""
    return (
        "az",
        "monitor",
        "log-analytics",
        "query",
        f"--workspace={_workspace_guid(ctx.mapping)}",
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
    return _log_query_argv(ctx, kql)


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
    return _log_query_argv(ctx, kql)


def _console_logs_argv(ctx: QueryContext) -> tuple[str, ...]:
    kql = (
        f"ContainerAppConsoleLogs_CL | where {_kql_time_filter(ctx.window)} "
        f"| where _ResourceId =~ {_kql_string(_container_app_id(ctx.mapping))} "
        "| order by TimeGenerated desc "
        "| project TimeGenerated, RevisionName_s, ContainerName_s, Stream_s, Log_s "
        f"| take {ctx.row_limit + 1}"
    )
    return _log_query_argv(ctx, kql)


def _system_logs_argv(ctx: QueryContext) -> tuple[str, ...]:
    kql = (
        f"ContainerAppSystemLogs_CL | where {_kql_time_filter(ctx.window)} "
        f"| where _ResourceId =~ {_kql_string(_container_app_id(ctx.mapping))} "
        "| order by TimeGenerated desc "
        "| project TimeGenerated, RevisionName_s, Reason_s, Type_s, Msg_s "
        f"| take {ctx.row_limit + 1}"
    )
    return _log_query_argv(ctx, kql)


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
        template_id="aca-console-logs-v1",
        fields=("TimeGenerated", "RevisionName_s", "ContainerName_s", "Stream_s", "Log_s"),
        supports_operation_id=False,
        build_argv=_console_logs_argv,
    ),
    DiagnosticKind.CONTAINER_APP_SYSTEM_LOGS: Template(
        kind=DiagnosticKind.CONTAINER_APP_SYSTEM_LOGS,
        template_id="aca-system-logs-v1",
        fields=("TimeGenerated", "RevisionName_s", "Reason_s", "Type_s", "Msg_s"),
        supports_operation_id=False,
        build_argv=_system_logs_argv,
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
