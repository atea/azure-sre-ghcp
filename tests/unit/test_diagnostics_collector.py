"""Collector, template scoping, budget, and error-mapping tests (fake runner, no real az)."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from azure_sre import contracts as c
from azure_sre.config import BudgetPolicy
from azure_sre.contracts import EvidenceBundle, EvidenceError, EvidenceItem, EvidenceStatus
from azure_sre.diagnostics import (
    TEMPLATES,
    CommandResult,
    CorrelationSelector,
    DiagnosticKind,
    DiagnosticsCollector,
    DiagnosticsError,
)
from azure_sre.diagnostics.budget import EvidenceBudgetExhausted, bundle_bytes, fit_items

SUB = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RG = "rg-shop"
APP = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.App/containerApps/shop-api"
AI = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Insights/components/shop-ai"
LAW = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
    "Microsoft.OperationalInsights/workspaces/law"
)
WS = "66666666-7777-8888-9999-aaaaaaaaaaaa"
KEY = "a" * 64
NOW = datetime(2026, 10, 13, 6, 30, tzinfo=UTC)
WINDOW = c.DiagnosticWindow(start=NOW - timedelta(minutes=20), end=NOW)


def registry() -> c.ApplicationRegistry:
    return c.ApplicationRegistry(
        schema_version=1,
        tenant_id=TENANT,
        applications=[
            c.ApplicationMapping(
                app_id="shop",
                environment="prod",
                subscription_id=SUB,
                container_app_id=APP,
                app_insights_component_id=AI,
                log_analytics_workspace_id=WS,
                log_analytics_workspace_resource_id=LAW,
                repository="contoso/shop",
                installation_id=42,
            )
        ],
    )


class FakeRunner:
    """Records every argv/env it receives and replays queued results (no subprocess)."""

    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.calls: list[tuple[tuple[str, ...], dict[str, str], float]] = []

    def run(
        self,
        argv: Any,
        *,
        env: Any,
        timeout_seconds: float,
        cancel: threading.Event | None = None,
    ) -> CommandResult:
        self.calls.append((tuple(argv), dict(env), timeout_seconds))
        if self.results:
            return self.results.pop(0)
        return ok([])


def ok(payload: Any) -> CommandResult:
    return CommandResult(
        returncode=0,
        stdout=json.dumps(payload).encode(),
        stderr=b"",
        timed_out=False,
        cancelled=False,
    )


def failed(stderr: bytes) -> CommandResult:
    return CommandResult(returncode=1, stdout=b"", stderr=stderr, timed_out=False, cancelled=False)


def collector(
    runner: FakeRunner, budget: BudgetPolicy | None = None, cancel: threading.Event | None = None
) -> DiagnosticsCollector:
    return DiagnosticsCollector(
        registry=registry(),
        runner=runner,
        env={"PATH": "/usr/bin:/bin", "AZURE_CONFIG_DIR": "/private/worker"},
        budget=budget,
        clock=lambda: NOW,
        cancel=cancel,
    )


def argv_of(runner: FakeRunner, index: int = 0) -> tuple[str, ...]:
    return runner.calls[index][0]


def kql_of(argv: tuple[str, ...]) -> str:
    (value,) = [
        a.removeprefix("--analytics-query=") for a in argv if a.startswith("--analytics-query=")
    ]
    return value


# Scoping ------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(DiagnosticKind))
def test_every_kind_runs_exactly_one_fixed_argv_without_shell(kind: DiagnosticKind) -> None:
    runner = FakeRunner()
    item = collector(runner).collect("shop", kind, WINDOW)
    assert len(runner.calls) == 1
    argv = argv_of(runner)
    assert argv[0] == "az"
    assert all(isinstance(a, str) and "\x00" not in a for a in argv)
    assert item.status is EvidenceStatus.ZERO_ROWS
    assert item.rows == ()
    assert item.error is None


def test_workspace_queries_bind_ai_component_and_workspace_guid() -> None:
    runner = FakeRunner()
    coll = collector(runner)
    for kind in (DiagnosticKind.APP_INSIGHTS_EXCEPTIONS, DiagnosticKind.APP_INSIGHTS_OPERATIONS):
        coll.collect("shop", kind, WINDOW)
    for argv, _, _ in runner.calls:
        assert f"--workspace={WS}" in argv
        kql = kql_of(argv)
        assert f"_resourceid =~ '{AI.lower()}'" in kql.lower()
        assert APP.lower() not in kql.lower()
        assert "--timespan=" in " ".join(argv)


def test_container_log_queries_bind_container_app_not_ai_component() -> None:
    runner = FakeRunner()
    coll = collector(runner)
    for kind in (
        DiagnosticKind.CONTAINER_APP_CONSOLE_LOGS,
        DiagnosticKind.CONTAINER_APP_SYSTEM_LOGS,
    ):
        coll.collect("shop", kind, WINDOW)
    for argv, _, _ in runner.calls:
        kql = kql_of(argv).lower()
        assert APP.lower() in kql
        assert AI.lower() not in kql
        assert "containerappconsolelogs_cl" in kql or "containerappsystemlogs_cl" in kql
        assert "| take 101" in kql
        assert f"--workspace={WS}" in argv
        assert (
            f"(_resourceid =~ '{APP.lower()}' or "
            "(isempty(_resourceid) and containerappname_s =~ 'shop-api'))"
        ) in kql


@pytest.mark.parametrize(
    "kind",
    [DiagnosticKind.CONTAINER_APP_CONSOLE_LOGS, DiagnosticKind.CONTAINER_APP_SYSTEM_LOGS],
)
def test_container_logs_with_empty_resource_id_keep_bounded_redacted_evidence(
    kind: DiagnosticKind,
) -> None:
    runner = FakeRunner(
        ok(
            [
                {
                    "_ResourceId": "",
                    "ContainerAppName_s": "shop-api",
                    "Log_s": "Failed to resolve storage.table.core.windows.net",
                    "Msg_s": "Probe failed",
                    "untrusted": "not evidence",
                }
            ]
        )
    )
    item = collector(runner).collect("shop", kind, WINDOW)
    assert item.status is EvidenceStatus.OK
    assert item.row_count == 1
    assert "_ResourceId" not in item.rows[0]
    assert "untrusted" not in item.rows[0]


def test_activity_log_is_scoped_to_one_resource_not_subscription() -> None:
    runner = FakeRunner()
    collector(runner).collect("shop", DiagnosticKind.ACTIVITY_LOG_DEPLOYMENTS, WINDOW)
    argv = argv_of(runner)
    assert f"--resource-id={APP.lower()}" in argv
    assert not any(a.startswith("--resource-group") for a in argv)


def test_health_and_revisions_use_name_group_and_subscription_only() -> None:
    runner = FakeRunner()
    coll = collector(runner)
    coll.collect("shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW)
    coll.collect("shop", DiagnosticKind.CONTAINER_APP_REVISIONS, WINDOW)
    for argv, _, _ in runner.calls:
        assert "containerapp" in argv
        assert "--name=shop-api" in argv
        assert f"--resource-group={RG}" in argv
        assert not any(a.startswith("--query") or a.startswith("--ids") for a in argv)


@pytest.mark.parametrize(
    "hostile",
    [
        "x' | drop table AppExceptions",
        "--output=none",
        "abc; rm -rf /",
        "$(whoami)",
        "https://evil.example/",
        "a" * 129,
        "",
    ],
)
def test_hostile_operation_ids_are_rejected_before_any_command(hostile: str) -> None:
    runner = FakeRunner()
    with pytest.raises(DiagnosticsError):
        collector(runner).collect(
            "shop",
            DiagnosticKind.APP_INSIGHTS_EXCEPTIONS,
            WINDOW,
            CorrelationSelector(operation_id=hostile),
        )
    assert runner.calls == []


def test_operation_id_is_quoted_only_after_validation() -> None:
    runner = FakeRunner()
    collector(runner).collect(
        "shop",
        DiagnosticKind.APP_INSIGHTS_OPERATIONS,
        WINDOW,
        CorrelationSelector(operation_id="abc-123.x:y"),
    )
    assert "OperationId == 'abc-123.x:y'" in kql_of(argv_of(runner))


def test_selector_not_supported_by_kind_is_rejected() -> None:
    runner = FakeRunner()
    with pytest.raises(DiagnosticsError):
        collector(runner).collect(
            "shop",
            DiagnosticKind.CONTAINER_APP_HEALTH,
            WINDOW,
            CorrelationSelector(operation_id="abc"),
        )
    assert runner.calls == []


def test_unknown_application_and_oversized_window_are_rejected() -> None:
    runner = FakeRunner()
    with pytest.raises(DiagnosticsError):
        collector(runner).collect("other", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW)
    too_long = c.DiagnosticWindow(start=NOW - timedelta(days=1), end=NOW)
    with pytest.raises(DiagnosticsError):
        collector(runner).collect("shop", DiagnosticKind.CONTAINER_APP_HEALTH, too_long)
    assert runner.calls == []


def test_container_app_fields_are_projected_and_extras_dropped() -> None:
    row = {f: "v" for f in TEMPLATES[DiagnosticKind.CONTAINER_APP_HEALTH].fields}
    row["secretEnvValue"] = "should-not-appear"
    runner = FakeRunner(ok(row))
    item = collector(runner).collect("shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW)
    assert item.status is EvidenceStatus.OK
    assert "secretEnvValue" not in json.dumps(item.model_dump(mode="json"))


# Results and error mapping ---------------------------------------------------------------


def test_zero_rows_is_not_reported_as_healthy() -> None:
    item = collector(FakeRunner(ok([]))).collect(
        "shop", DiagnosticKind.APP_INSIGHTS_EXCEPTIONS, WINDOW
    )
    assert item.status is EvidenceStatus.ZERO_ROWS
    assert "not proof of health" in item.summary


def test_rows_are_redacted_recursively() -> None:
    fields = TEMPLATES[DiagnosticKind.APP_INSIGHTS_EXCEPTIONS].fields
    row = {f: "ok" for f in fields}
    row[fields[0]] = "token ghp_" + "A" * 36
    item = collector(FakeRunner(ok([row]))).collect(
        "shop", DiagnosticKind.APP_INSIGHTS_EXCEPTIONS, WINDOW
    )
    dumped = json.dumps(item.model_dump(mode="json"))
    assert "ghp_" + "A" * 36 not in dumped
    assert item.rows[0][fields[0]] != "ok"


def test_row_limit_sets_truncated_and_count() -> None:
    fields = TEMPLATES[DiagnosticKind.APP_INSIGHTS_EXCEPTIONS].fields
    rows = [{f: str(i) for f in fields} for i in range(101)]
    item = collector(FakeRunner(ok(rows))).collect(
        "shop", DiagnosticKind.APP_INSIGHTS_EXCEPTIONS, WINDOW
    )
    assert len(item.rows) == 100
    assert item.row_count == 100
    assert item.truncated is True


def test_timeout_maps_to_timeout_status() -> None:
    result = CommandResult(returncode=None, stdout=b"", stderr=b"", timed_out=True, cancelled=False)
    item = collector(FakeRunner(result)).collect(
        "shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW
    )
    assert item.status is EvidenceStatus.TIMEOUT
    assert item.error is not None


@pytest.mark.parametrize(
    ("stderr", "status"),
    [
        (
            b"(AuthorizationFailed) The client does not have authorization",
            EvidenceStatus.PERMISSION_DENIED,
        ),
        (b"ERROR: Forbidden secret-tenant-xyz", EvidenceStatus.PERMISSION_DENIED),
        (b"ERROR: Failed to resolve table AppExceptions", EvidenceStatus.MISSING_TELEMETRY),
        (b"boom with eyJhbGciOi.payload.sig", EvidenceStatus.ERROR),
    ],
)
def test_stderr_maps_to_fixed_safe_messages(stderr: bytes, status: EvidenceStatus) -> None:
    item = collector(FakeRunner(failed(stderr))).collect(
        "shop", DiagnosticKind.APP_INSIGHTS_EXCEPTIONS, WINDOW
    )
    assert item.status is status
    assert item.error is not None
    assert item.error.category is status
    message = item.error.message
    assert "secret-tenant" not in message
    assert "eyJ" not in message
    assert "boom" not in message


def test_unparseable_stdout_is_error_not_zero_rows() -> None:
    result = CommandResult(
        returncode=0, stdout=b"<html>", stderr=b"", timed_out=False, cancelled=False
    )
    item = collector(FakeRunner(result)).collect(
        "shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW
    )
    assert item.status is EvidenceStatus.ERROR


def test_cancelled_investigation_records_gaps_for_remaining_kinds() -> None:
    cancel = threading.Event()
    cancel.set()
    runner = FakeRunner()
    bundle = collector(runner, cancel=cancel).collect_bundle(
        incident_key=KEY,
        app_id="shop",
        window=WINDOW,
        kinds=[DiagnosticKind.CONTAINER_APP_HEALTH, DiagnosticKind.CONTAINER_APP_REVISIONS],
    )
    assert runner.calls == []
    assert [i.status for i in bundle.items] == [EvidenceStatus.ERROR, EvidenceStatus.ERROR]


def test_call_budget_is_checked_before_any_command() -> None:
    runner = FakeRunner()
    kinds = list(DiagnosticKind)[:3]
    with pytest.raises(DiagnosticsError):
        collector(runner, BudgetPolicy(diagnostic_calls=2)).collect_bundle(
            incident_key=KEY, app_id="shop", window=WINDOW, kinds=kinds
        )
    assert runner.calls == []


def test_per_call_timeout_is_capped_by_cli_budget() -> None:
    runner = FakeRunner()
    collector(runner, BudgetPolicy(cli_call_seconds=7)).collect(
        "shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW
    )
    assert runner.calls[0][2] == 7.0


def test_collected_at_comes_from_injected_clock() -> None:
    item = collector(FakeRunner()).collect("shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW)
    assert item.provenance.collected_at == NOW
    assert item.provenance.scope_ref == "app:shop/env:prod"


# Bundle budget -----------------------------------------------------------------------------


def _rows(count: int, text: str) -> list[dict[str, str]]:
    fields = TEMPLATES[DiagnosticKind.APP_INSIGHTS_EXCEPTIONS].fields
    return [{f: text for f in fields} for _ in range(count)]


def _bundle_for(rows: list[dict[str, str]], evidence_bytes: int) -> EvidenceBundle:
    runner = FakeRunner(ok(rows), ok(rows))
    return collector(runner, BudgetPolicy(evidence_bytes=evidence_bytes)).collect_bundle(
        incident_key=KEY,
        app_id="shop",
        window=WINDOW,
        kinds=[DiagnosticKind.APP_INSIGHTS_EXCEPTIONS, DiagnosticKind.APP_INSIGHTS_OPERATIONS],
    )


def test_bundle_exactly_at_budget_is_not_trimmed() -> None:
    rows = _rows(3, "plain")
    unlimited = _bundle_for(rows, 64 * 1024)
    size = unlimited.byte_size()
    fitted = _bundle_for(rows, size)
    assert fitted.byte_size() == size
    assert all(not i.truncated for i in fitted.items)


def test_bundle_one_byte_over_budget_is_trimmed_and_flagged() -> None:
    rows = _rows(3, "plain")
    size = _bundle_for(rows, 64 * 1024).byte_size()
    trimmed = _bundle_for(rows, size - 1)
    assert trimmed.byte_size() <= size - 1
    assert any(i.truncated for i in trimmed.items)


def test_multibyte_text_is_measured_in_utf8_bytes() -> None:
    rows = _rows(2, "é" * 40)  # 2 bytes per char in UTF-8
    full = _bundle_for(rows, 64 * 1024)
    assert full.byte_size() == len(full.model_dump_json().encode("utf-8"))
    trimmed = _bundle_for(rows, full.byte_size() - 1)
    assert trimmed.byte_size() <= full.byte_size() - 1


def test_fit_items_records_gap_when_no_rows_can_fit() -> None:
    item = EvidenceItem(
        evidence_id="E1",
        provenance=collector(FakeRunner())
        .collect("shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW)
        .provenance,
        status=EvidenceStatus.ZERO_ROWS,
        summary="no rows returned; this is not proof of health " + "x" * 900,
        row_count=0,
    )
    gap = EvidenceItem(
        evidence_id="E1",
        provenance=item.provenance,
        status=EvidenceStatus.ERROR,
        summary="",
        row_count=0,
        truncated=True,
        error=EvidenceError(
            category=EvidenceStatus.ERROR, message="omitted: evidence byte budget exceeded"
        ),
    )
    budget = bundle_bytes(KEY, [gap])
    fitted = fit_items(KEY, [item], max_bytes=budget)
    assert bundle_bytes(KEY, fitted) <= budget
    assert len(fitted) == 1
    assert fitted[0].status is EvidenceStatus.ERROR
    assert fitted[0].evidence_id == "E1"
    assert bundle_bytes(KEY, [gap]) < bundle_bytes(KEY, [item])


def test_fit_items_raises_typed_error_when_even_gap_marker_cannot_fit() -> None:
    item = EvidenceItem(
        evidence_id="E1",
        provenance=collector(FakeRunner())
        .collect("shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW)
        .provenance,
        status=EvidenceStatus.ZERO_ROWS,
        summary="no rows returned; this is not proof of health",
        row_count=0,
    )
    with pytest.raises(EvidenceBudgetExhausted) as excinfo:
        fit_items(KEY, [item], max_bytes=1)
    assert excinfo.value.omitted_evidence_ids == ("E1",)
    assert excinfo.value.fitted == ()


def test_bundle_bytes_measures_oversize_input_without_validation() -> None:
    assert bundle_bytes(KEY, []) > 0
    assert isinstance(bundle_bytes(KEY, []), int)


def test_empty_health_stdout_is_error_not_zero_rows() -> None:
    item = collector(FakeRunner(CommandResult(0, b"", b"", False, False))).collect(
        "shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW
    )
    assert item.status is EvidenceStatus.ERROR
    assert item.rows == ()


def test_wrong_schema_payload_is_error_not_healthy() -> None:
    payload = json.dumps([{"unexpected": 1}]).encode()
    item = collector(FakeRunner(CommandResult(0, payload, b"", False, False))).collect(
        "shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW
    )
    assert item.status is EvidenceStatus.ERROR
    assert item.rows == ()
    assert item.status is not EvidenceStatus.OK


def test_output_limit_is_reported_as_explicit_error_not_truncated_success() -> None:
    result = CommandResult(None, b'[{"a": 1}', b"", False, False, output_limit=True)
    item = collector(FakeRunner(result)).collect(
        "shop", DiagnosticKind.CONTAINER_APP_HEALTH, WINDOW
    )
    assert item.status is EvidenceStatus.ERROR
    assert item.rows == ()
    assert item.error is not None
    assert "capture limit" in item.error.message


def test_project_row_rejects_objects_with_no_recognised_field() -> None:
    from azure_sre.diagnostics.templates import project_row

    assert project_row({"other": 1}, ("runningStatus",)) is None
    assert project_row("not-a-mapping", ("runningStatus",)) is None
    assert project_row({"runningStatus": {"nested": 1}}, ("runningStatus",)) is None
    assert project_row({"runningStatus": "Running", "x": 1}, ("runningStatus",)) == {
        "runningStatus": "Running"
    }
