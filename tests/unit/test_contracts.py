import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from azure_sre import contracts as c
from azure_sre.contracts import NormalizationErrorCode as Code

SUB = "11111111-2222-3333-4444-555555555555"
OTHER_SUB = "99999999-2222-3333-4444-555555555555"
WS = "66666666-7777-8888-9999-aaaaaaaaaaaa"
WS2 = "66666666-7777-8888-9999-bbbbbbbbbbbb"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
RG = "rg-shop"


def arm(provider: str, rtype: str, name: str, sub: str = SUB, rg: str = RG) -> str:
    return f"/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{rtype}/{name}"


APP = arm("Microsoft.App", "containerApps", "shop-api")
AI = arm("Microsoft.Insights", "components", "shop-ai")
LAW = arm("Microsoft.OperationalInsights", "workspaces", "shop-law")
APP2 = arm("Microsoft.App", "containerApps", "billing-api")
AI2 = arm("Microsoft.Insights", "components", "billing-ai")
ALERT_ID = f"/subscriptions/{SUB}/providers/Microsoft.AlertsManagement/alerts/abc-123"
FIRED = "2026-10-13T06:00:00Z"
RESOLVED = "2026-10-13T06:20:00Z"
NOW = datetime(2026, 10, 13, 6, 30, tzinfo=UTC)


def mapping(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "app_id": "shop",
        "environment": "prod",
        "subscription_id": SUB,
        "container_app_id": APP,
        "app_insights_component_id": AI,
        "log_analytics_workspace_id": WS,
        "log_analytics_workspace_resource_id": LAW,
        "repository": "contoso/shop",
        "installation_id": 42,
    }
    base.update(overrides)
    return base


def registry(*mappings: dict[str, Any]) -> c.ApplicationRegistry:
    apps = mappings or (
        mapping(),
        mapping(
            app_id="billing",
            container_app_id=APP2,
            app_insights_component_id=AI2,
            log_analytics_workspace_id=WS2,
            log_analytics_workspace_resource_id=None,
            repository="contoso/billing",
        ),
    )
    return c.ApplicationRegistry(
        schema_version=1,
        tenant_id=TENANT,
        applications=apps,  # type: ignore[arg-type]
    )


def payload(
    targets: list[str] | None = None,
    *,
    condition: str = "Fired",
    resolved: str | None = None,
    severity: str = "Sev2",
    signal: str = "Metric",
    alert_id: str = ALERT_ID,
    context: dict[str, Any] | None = None,
    custom: dict[str, Any] | None = None,
    schema: str = c.ALERT_SCHEMA_ID,
    fired: str = FIRED,
) -> dict[str, Any]:
    essentials: dict[str, Any] = {
        "alertId": alert_id,
        "alertRule": "shop-5xx",
        "severity": severity,
        "signalType": signal,
        "monitoringService": "Platform",
        "monitorCondition": condition,
        "alertTargetIDs": [APP] if targets is None else targets,
        "firedDateTime": fired,
        "originAlertId": "ignored-unknown-field",
    }
    if resolved is not None:
        essentials["resolvedDateTime"] = resolved
    return {
        "schemaId": schema,
        "data": {"essentials": essentials, "alertContext": context, "customProperties": custom},
    }


def expect_code(code: Code, raw: Any, reg: c.ApplicationRegistry | None = None) -> None:
    with pytest.raises(c.AlertNormalizationError) as info:
        c.normalize_alert(raw, reg or registry())
    assert info.value.code == code.value


# --- normalization -----------------------------------------------------------


def test_metric_fired_alert_on_container_app() -> None:
    alert = c.normalize_alert(payload(), registry())
    assert alert.app_id == "shop"
    assert alert.sink is c.Sink.PRODUCTION
    assert alert.signal_type is c.SignalType.METRIC
    assert alert.monitor_condition is c.MonitorCondition.FIRED
    assert alert.severity is c.Severity.SEV2
    assert alert.resolved_at is None
    assert alert.fired_at == datetime(2026, 10, 13, 6, 0, tzinfo=UTC)
    assert alert.targets == (
        c.NormalizedTarget(canonical_id=APP.lower(), kind=c.TargetKind.CONTAINER_APP),
    )
    assert alert.container_app_id == APP.lower()
    assert alert.log_analytics_workspace_id == WS
    assert alert.tenant_id == TENANT
    assert alert.repository == "contoso/shop"
    assert alert.installation_id == 42
    assert alert.registry_fingerprint == registry().fingerprint()
    assert alert.incident_key == c.incident_key("shop", ALERT_ID)


def test_log_fired_alert_on_app_insights_component() -> None:
    alert = c.normalize_alert(payload([AI], signal="Log"), registry())
    assert alert.signal_type is c.SignalType.LOG
    assert alert.targets[0].kind is c.TargetKind.APP_INSIGHTS_COMPONENT


def test_resolved_shares_incident_key_but_not_delivery_id() -> None:
    fired = c.normalize_alert(payload(), registry())
    resolved = c.normalize_alert(payload(condition="Resolved", resolved=RESOLVED), registry())
    assert resolved.monitor_condition is c.MonitorCondition.RESOLVED
    assert resolved.resolved_at == datetime(2026, 10, 13, 6, 20, tzinfo=UTC)
    assert resolved.incident_key == fired.incident_key
    assert resolved.delivery_id != fired.delivery_id


def test_multiple_targets_same_app_accepted_and_deduplicated() -> None:
    alert = c.normalize_alert(payload([APP, AI, APP.upper(), LAW]), registry())
    assert alert.app_id == "shop"
    assert [t.kind for t in alert.targets] == [
        c.TargetKind.CONTAINER_APP,
        c.TargetKind.APP_INSIGHTS_COMPONENT,
        c.TargetKind.LOG_ANALYTICS_WORKSPACE,
    ]


def test_mixed_applications_rejected() -> None:
    expect_code(Code.MIXED_APPLICATIONS, payload([APP, APP2]))


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"condition": "Resolved"}, Code.INVALID_LIFECYCLE),
        ({"condition": "Fired", "resolved": RESOLVED}, Code.INVALID_LIFECYCLE),
        ({"condition": "Resolved", "resolved": "2026-10-13T05:59:59Z"}, Code.INVALID_LIFECYCLE),
    ],
)
def test_lifecycle_violations(kwargs: dict[str, Any], code: Code) -> None:
    expect_code(code, payload(**kwargs))


def test_case_insensitive_enums_are_canonicalized() -> None:
    alert = c.normalize_alert(
        payload(severity="sev3", condition="fired", signal="metric"), registry()
    )
    assert alert.severity == "Sev3"
    assert alert.monitor_condition == "Fired"
    assert alert.signal_type == "Metric"
    log = c.normalize_alert(payload(signal="activity log"), registry())
    assert log.signal_type is c.SignalType.ACTIVITY_LOG


def test_arm_and_alert_id_casing_collapse() -> None:
    upper_target = APP.upper().replace("/PROVIDERS/", "/providers/")
    upper_alert = ALERT_ID.upper()
    lower = c.normalize_alert(payload([APP.lower()], alert_id=ALERT_ID.lower()), registry())
    upper = c.normalize_alert(payload([upper_target], alert_id=upper_alert), registry())
    assert upper.targets == lower.targets
    assert upper.alert_id == lower.alert_id == ALERT_ID.lower()
    assert upper.incident_key == lower.incident_key
    assert upper.delivery_id == lower.delivery_id


def test_non_arm_alert_id_kept_verbatim() -> None:
    alert = c.normalize_alert(payload(alert_id="Custom-ID-1"), registry())
    assert alert.alert_id == "Custom-ID-1"


def test_parse_resource_id_canonicalizes() -> None:
    raw = (
        f"  /SUBSCRIPTIONS/{SUB.upper()}/RESOURCEGROUPS/RG-Shop"
        "/PROVIDERS/Microsoft.App/containerApps/Shop-API/ "
    )
    rid = c.parse_resource_id(raw)
    assert rid.canonical == APP.lower()
    assert rid.subscription_id == SUB
    assert (rid.provider, rid.resource_type, rid.name) == (
        "microsoft.app",
        "containerapps",
        "shop-api",
    )


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (APP + "/extra", Code.MALFORMED_SCOPE),
        (APP + "/revisions/rev1", Code.UNSUPPORTED_RESOURCE_TYPE),
        (APP + "?api-version=1", Code.MALFORMED_SCOPE),
        (APP.replace("shop-api", "shop%2Fapi"), Code.MALFORMED_SCOPE),
        (APP.replace("/rg-shop/", "/../"), Code.MALFORMED_SCOPE),
        (APP.replace("/rg-shop/", "//"), Code.MALFORMED_SCOPE),
        (APP.replace(SUB, "not-a-guid"), Code.MALFORMED_SCOPE),
        (APP.replace("shop-api", "shop api"), Code.MALFORMED_SCOPE),
        (APP.replace("rg-shop", "rg-shop."), Code.MALFORMED_SCOPE),
        (APP + "#frag", Code.MALFORMED_SCOPE),
        ("subscriptions/" + SUB, Code.MALFORMED_SCOPE),
        (f"/subscriptions/{SUB}/resourceGroups/{RG}", Code.MALFORMED_SCOPE),
    ],
)
def test_malformed_arm_ids(raw: str, code: Code) -> None:
    with pytest.raises(c.ContractError) as info:
        c.parse_resource_id(raw)
    assert info.value.code == code.value
    expect_code(code, payload([raw]))


def test_unknown_scope_cross_subscription_and_unsupported_type() -> None:
    expect_code(Code.UNKNOWN_SCOPE, payload([arm("Microsoft.App", "containerApps", "other")]))
    expect_code(Code.CROSS_SUBSCRIPTION, payload([APP.replace(SUB, OTHER_SUB)]))
    vm = arm("Microsoft.Compute", "virtualMachines", "vm1")
    expect_code(Code.UNSUPPORTED_RESOURCE_TYPE, payload([vm]))


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        b"\xff\xfe",
        b"[1, 2]",
        json.dumps({"schemaId": c.ALERT_SCHEMA_ID}),
        payload(fired="2026-10-13T06:00:00"),
        payload(severity="Sev9"),
        payload(signal="Trace"),
        payload(condition="Acknowledged"),
        payload(alert_id=""),
    ],
)
def test_malformed_payloads(raw: Any) -> None:
    expect_code(Code.MALFORMED, raw)


def test_target_count_limits() -> None:
    expect_code(Code.NO_TARGETS, payload([]))
    expect_code(Code.TOO_MANY_TARGETS, payload([APP] * (c.MAX_TARGETS_PER_ALERT + 1)))


def test_schema_id_must_match_exactly() -> None:
    expect_code(Code.UNSUPPORTED_SCHEMA, payload(schema="azureMonitorCommonAlertSchemaV2"))
    expect_code(Code.UNSUPPORTED_SCHEMA, payload(schema="AzureMonitorCommonAlertSchema"))


def test_oversized_payload_rejected_for_bytes_and_mapping() -> None:
    big = payload(custom={"blob": "x" * c.MAX_ALERT_PAYLOAD_BYTES})
    expect_code(Code.PAYLOAD_TOO_LARGE, big)
    expect_code(Code.PAYLOAD_TOO_LARGE, json.dumps(big).encode())


def test_sink_comes_only_from_keyword() -> None:
    raw = payload(custom={"sink": "test", "Sink": "TEST"})
    assert c.normalize_alert(raw, registry()).sink is c.Sink.PRODUCTION
    assert c.normalize_alert(raw, registry(), sink=c.Sink.TEST).sink is c.Sink.TEST


def test_custom_properties_with_urls_or_queries_are_ignored() -> None:
    custom = {"runbook": "https://evil.example/x", "query": "AppRequests | take 1"}
    alert = c.normalize_alert(payload(custom=custom), registry())
    dumped = alert.model_dump_json()
    assert "evil.example" not in dumped
    assert "AppRequests" not in dumped


def test_context_hints_and_embedded_search_results() -> None:
    context = {
        "condition": {
            "windowStartTime": "2026-10-13T05:55:00Z",
            "windowEndTime": "2026-10-13T06:00:00Z",
            "allOf": [{"metricName": "Requests"}, {"metricName": {"x": 1}}, {"metricName": 7}],
        },
        "SearchResults": {"tables": [{"rows": [["secret"]]}]},
    }
    alert = c.normalize_alert(payload(context=context), registry())
    assert alert.context.window_start == datetime(2026, 10, 13, 5, 55, tzinfo=UTC)
    assert alert.context.window_end == datetime(2026, 10, 13, 6, 0, tzinfo=UTC)
    assert alert.context.metric_names == ("Requests",)
    assert alert.context.search_results_embedded is True
    assert "secret" not in alert.model_dump_json()


def test_invalid_context_values_are_ignored() -> None:
    context = {"windowStartTime": 5, "windowEndTime": "2026-10-13T06:00:00", "condition": "x"}
    hints = c.normalize_alert(payload(context=context), registry()).context
    assert (hints.window_start, hints.window_end, hints.metric_names) == (None, None, ())
    assert hints.search_results_embedded is False


def test_delivery_id_deterministic_across_input_forms() -> None:
    raw = payload()
    from_dict = c.normalize_alert(raw, registry())
    again = c.normalize_alert(raw, registry())
    from_str = c.normalize_alert(json.dumps(raw), registry())
    from_bytes = c.normalize_alert(json.dumps(raw).encode(), registry())
    assert from_dict.delivery_id == again.delivery_id == from_str.delivery_id
    assert from_bytes.delivery_id == from_dict.delivery_id
    assert from_dict.delivery_id == c.delivery_id(
        "shop", ALERT_ID, c.MonitorCondition.FIRED, datetime(2026, 10, 13, 6, tzinfo=UTC)
    )


def test_incident_window_is_exact_span_anchored_on_fired() -> None:
    fired = c.normalize_alert(payload(), registry())
    window = c.incident_window(fired, before_minutes=60, after_minutes=30)
    assert window.start == fired.fired_at - timedelta(minutes=60)
    assert window.end == fired.fired_at + timedelta(minutes=30)
    assert window.end - window.start == timedelta(minutes=90)
    for before, after in ((61, 0), (0, 31), (-1, 0), (0, -1)):
        with pytest.raises(c.ContractError):
            c.incident_window(fired, before_minutes=before, after_minutes=after)


def test_delayed_fired_alert_window_is_not_anchored_on_processing_time() -> None:
    # Onset is 06:00Z regardless of when the delivery is processed, so the span stays exact.
    fired = c.normalize_alert(payload(), registry())
    window = c.incident_window(fired, before_minutes=15, after_minutes=5)
    assert window.start == datetime(2026, 10, 13, 5, 45, tzinfo=UTC)
    assert window.end == datetime(2026, 10, 13, 6, 5, tzinfo=UTC)
    assert window.end - window.start == timedelta(minutes=20)


def test_long_lived_resolved_alert_window_span_stays_bounded() -> None:
    resolved = c.normalize_alert(
        payload(condition="Resolved", resolved="2026-10-16T06:00:00Z"), registry()
    )
    window = c.incident_window(resolved, before_minutes=15, after_minutes=5)
    assert window.start == datetime(2026, 10, 13, 5, 45, tzinfo=UTC)
    assert window.end == datetime(2026, 10, 13, 6, 5, tzinfo=UTC)
    assert window.end - window.start == timedelta(minutes=20)


# --- registry ----------------------------------------------------------------


def test_registry_normalizes_ids_and_resolves_targets() -> None:
    reg = registry(mapping(container_app_id=APP.upper().replace("/PROVIDERS/", "/providers/")))
    assert reg.applications[0].container_app_id == APP.lower()
    found = reg.resolve_target(AI.lower())
    assert found is not None
    assert found[0].app_id == "shop"
    assert found[1] is c.TargetKind.APP_INSIGHTS_COMPONENT
    assert reg.resolve_target(APP2.lower()) is None


@pytest.mark.parametrize(
    "apps",
    [
        (
            mapping(),
            mapping(
                app_id="other",
                app_insights_component_id=AI2,
                log_analytics_workspace_id=WS2,
                log_analytics_workspace_resource_id=None,
            ),
        ),
        (
            mapping(),
            mapping(
                container_app_id=APP2,
                app_insights_component_id=AI2,
                log_analytics_workspace_id=WS2,
                log_analytics_workspace_resource_id=None,
            ),
        ),
        (
            mapping(),
            mapping(
                app_id="other",
                container_app_id=APP2,
                app_insights_component_id=AI2,
                log_analytics_workspace_resource_id=None,
            ),
        ),
    ],
)
def test_registry_conflicts_rejected(apps: tuple[dict[str, Any], ...]) -> None:
    with pytest.raises(c.ContractError) as info:
        registry(*apps)
    assert info.value.code == "registry_conflict"


def test_registry_allows_shared_repository() -> None:
    other = mapping(
        app_id="billing",
        container_app_id=APP2,
        app_insights_component_id=AI2,
        log_analytics_workspace_id=WS2,
        log_analytics_workspace_resource_id=None,
    )
    assert len(registry(mapping(), other).applications) == 2


@pytest.mark.parametrize(
    "overrides",
    [
        {"subscription_id": OTHER_SUB},
        {"container_app_id": APP.replace(SUB, OTHER_SUB)},
        {"container_app_id": AI},
        {"repository": "contoso"},
        {"repository": "contoso/shop/extra"},
        {"installation_id": 0},
        {"installation_id": True},
        {"app_id": "Shop"},
        {"log_analytics_workspace_id": "not-a-guid"},
        {"unexpected": 1},
    ],
)
def test_invalid_mappings_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(c.ContractError):
        registry(mapping(**overrides))


def test_mapping_subscription_mismatch_code() -> None:
    with pytest.raises(c.ContractError) as info:
        c.ApplicationMapping(**mapping(subscription_id=OTHER_SUB))
    assert info.value.code == Code.CROSS_SUBSCRIPTION.value


def test_registry_fingerprint_stable_and_sensitive() -> None:
    assert registry().fingerprint() == registry().fingerprint()
    assert len(registry().fingerprint()) == 64
    changed = registry(mapping(environment="staging"))
    assert changed.fingerprint() != registry(mapping()).fingerprint()


# --- evidence ----------------------------------------------------------------

KEY = c.incident_key("shop", ALERT_ID)
WINDOW = c.DiagnosticWindow(start=NOW - timedelta(hours=1), end=NOW)


def item(evidence_id: str = "E1", status: str = "ok", **overrides: Any) -> c.EvidenceItem:
    base: dict[str, Any] = {
        "evidence_id": evidence_id,
        "provenance": c.EvidenceProvenance(
            source=c.EvidenceSource.APP_INSIGHTS_EXCEPTIONS,
            template_id="ai.exceptions.v1",
            scope_ref=AI.lower(),
            window=WINDOW,
            collected_at=NOW,
        ),
        "status": status,
        "rows": ({"type": "NullReferenceException", "count": 3},),
        "row_count": 1,
    }
    if status != "ok":
        base.update(rows=(), row_count=0)
    if status not in ("ok", "zero_rows"):
        base["error"] = c.EvidenceError(category=status, message="query failed")  # type: ignore[arg-type]
    base.update(overrides)
    return c.EvidenceItem(**base)


def bundle(*items: c.EvidenceItem) -> c.EvidenceBundle:
    return c.EvidenceBundle(incident_key=KEY, items=items or (item("E1"), item("E2", "error")))


def test_evidence_items_valid_variants() -> None:
    assert item(summary="3 exceptions", rows=(), row_count=0).status is c.EvidenceStatus.OK
    assert item("E2", "zero_rows").row_count == 0
    assert item("E3", "permission_denied").error is not None
    assert item(truncated=True, row_count=500).truncated


@pytest.mark.parametrize(
    "overrides",
    [
        {"rows": (), "row_count": 0},
        {"row_count": 0},
        {"redacted": False},
        {"evidence_id": "E0"},
        {"evidence_id": "e1"},
        {"rows": ({"": 1},), "row_count": 1},
        {"rows": tuple({"n": i} for i in range(101)), "row_count": 101},
        {"error": {"category": "error", "message": "x"}},
    ],
)
def test_invalid_ok_evidence_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(c.ContractError):
        item(**overrides)


def test_error_statuses_require_error() -> None:
    for status in ("error", "timeout", "permission_denied", "missing_telemetry"):
        with pytest.raises(c.ContractError):
            item(status=status, error=None)
    with pytest.raises(c.ContractError):
        item(status="zero_rows", row_count=2)
    with pytest.raises(c.ContractError):
        c.EvidenceError(category="ok", message="x")  # type: ignore[arg-type]


def test_evidence_bundle_limits() -> None:
    b = bundle()
    assert b.ids() == frozenset({"E1", "E2"})
    assert b.get("E2") is not None and b.get("E9") is None
    assert 0 < b.byte_size() <= c.HARD_MAX_EVIDENCE_BYTES
    with pytest.raises(c.ContractError):
        bundle(item("E1"), item("E1"))
    big_rows = tuple({"message": "x" * 900} for _ in range(100))
    huge = [item(f"E{i}", rows=big_rows, row_count=100) for i in range(1, 3)]
    with pytest.raises(c.ContractError) as info:
        bundle(*huge)
    assert info.value.code == "evidence_too_large"


# --- report ------------------------------------------------------------------


def draft(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "status": "complete",
        "summary": "Exceptions spiked after deployment.",
        "symptoms": [{"text": "5xx increase", "evidence_refs": ["E1"]}],
        "chronology": [{"at": "06:00Z", "text": "Alert fired", "evidence_refs": ["E1"]}],
        "observations": [{"text": "NullReferenceException x3", "evidence_refs": ["E1"]}],
        "hypotheses": [
            {"statement": "Bad release", "support_refs": ["E1"], "verdict": "supported"},
            {"statement": "Infra issue", "support_refs": ["E2"], "verdict": "unverified"},
        ],
        "developer_actions": [{"text": "Check the release", "evidence_refs": ["E2"]}],
    }
    base.update(overrides)
    return base


def test_valid_model_output_accepted_from_str_and_mapping() -> None:
    result = c.validate_model_output(json.dumps(draft()), bundle())
    assert result == c.validate_model_output(draft(), bundle())
    assert result.status == "complete"


def test_partial_report_with_gap_referencing_failed_evidence() -> None:
    gap = {"description": "No logs", "category": "evidence_missing", "evidence_refs": ["E2"]}
    result = c.validate_model_output(draft(status="partial", gaps=[gap]), bundle())
    assert result.gaps[0].category is c.PartialCategory.EVIDENCE_MISSING


@pytest.mark.parametrize(
    "raw",
    [
        "{not json",
        "[]",
        "x" * (c.MAX_MODEL_OUTPUT_BYTES + 1),
        draft(observations=[{"text": "made up", "evidence_refs": ["E99"]}]),
        draft(observations=[{"text": "from failure", "evidence_refs": ["E2"]}]),
        draft(hypotheses=[{"statement": "h", "support_refs": ["E2"], "verdict": "supported"}]),
        draft(hypotheses=[{"statement": "h", "verdict": "supported"}]),
        draft(severity="Sev0"),
        draft(repository="evil/repo"),
        draft(sink="test"),
        draft(gaps=[{"description": "gap", "category": "timeout"}]),
        draft(symptoms=[], observations=[], hypotheses=[]),
        draft(observations=[{"text": "no refs", "evidence_refs": []}]),
    ],
)
def test_invalid_model_output_rejected(raw: Any) -> None:
    with pytest.raises(c.ReportValidationError) as info:
        c.validate_model_output(raw, bundle())
    assert info.value.problems


def test_report_problems_do_not_echo_raw_content() -> None:
    with pytest.raises(c.ReportValidationError) as info:
        c.validate_model_output(draft(**{"ghp_secretvalue/../x": "leak-me"}), bundle())
    assert "leak-me" not in str(info.value)
    assert "ghp_secretvalue" not in str(info.value)


def report(**overrides: Any) -> c.InvestigationReport:
    base: dict[str, Any] = {
        "schema_version": 1,
        "incident_key": KEY,
        "alert_id": ALERT_ID.lower(),
        "app_id": "shop",
        "severity": c.Severity.SEV2,
        "sink": c.Sink.PRODUCTION,
        "generated_at": NOW,
        "status": "complete",
        "evidence": bundle(),
        "draft": c.validate_model_output(draft(), bundle()),
    }
    base.update(overrides)
    return c.InvestigationReport(**base)


def test_investigation_report_envelope() -> None:
    assert report().status == "complete"
    partial = report(draft=None, status="partial", partial_category="timeout")
    assert partial.partial_category is c.PartialCategory.TIMEOUT
    with pytest.raises(c.ContractError):
        report(draft=None)
    with pytest.raises(c.ContractError):
        report(status="partial")
    with pytest.raises(c.ContractError):
        report(partial_category="timeout")
    with pytest.raises(c.ContractError):
        report(evidence=c.EvidenceBundle(incident_key="0" * 64, items=bundle().items))
    with pytest.raises(c.ContractError):
        report(evidence=bundle(item("E2", "error")))
    gap = c.ReportGap(description="d", category=c.PartialCategory.TIMEOUT, evidence_refs=("E7",))
    with pytest.raises(c.ContractError):
        report(draft=None, status="partial", partial_category="timeout", host_gaps=(gap,))


def test_report_status_must_match_draft() -> None:
    with pytest.raises(c.ContractError):
        report(status="partial", partial_category="timeout")


def test_report_rejects_non_ok_supporting_ref_on_direct_draft() -> None:
    with pytest.raises(c.ContractError):
        report(draft=draft(observations=[{"text": "from failure", "evidence_refs": ["E2"]}]))
    with pytest.raises(c.ContractError):
        report(
            draft=draft(
                hypotheses=[{"statement": "h", "support_refs": ["E2"], "verdict": "supported"}]
            )
        )


def test_host_partial_without_draft_accepts_failed_evidence_gap() -> None:
    gap = c.ReportGap(
        description="logs unavailable", category=c.PartialCategory.TIMEOUT, evidence_refs=("E2",)
    )
    host = report(draft=None, status="partial", partial_category="timeout", host_gaps=(gap,))
    assert host.draft is None and host.status == "partial"


@pytest.mark.parametrize(
    "overrides",
    [
        {"symptoms": [], "observations": [], "hypotheses": []},
        {"gaps": [{"description": "gap", "category": "timeout", "evidence_refs": ["E1"]}]},
    ],
)
def test_complete_draft_rules_apply_to_direct_validation(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        c.ModelReportDraft.model_validate(draft(**overrides))


# --- publication -------------------------------------------------------------


def test_publication_record_url_must_match() -> None:
    record = c.PublicationRecord(
        repository="Contoso/Shop",
        issue_number=7,
        issue_url="https://github.com/contoso/shop/issues/7",
        incident_key=KEY,
        marker="azure-sre:abc",
    )
    assert record.issue_number == 7
    for url in (
        "https://github.com/contoso/shop/issues/8",
        "https://github.com/contoso/other/issues/7",
        "http://github.com/contoso/shop/issues/7",
        "https://evil.example/contoso/shop/issues/7",
    ):
        with pytest.raises(c.ContractError):
            c.PublicationRecord(
                repository="contoso/shop",
                issue_number=7,
                issue_url=url,
                incident_key=KEY,
                marker="m",
            )
