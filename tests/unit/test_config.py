import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from azure_sre.config import (
    MAX_CONFIG_BYTES,
    AppConfig,
    BudgetPolicy,
    ConfigError,
    load_config,
    parse_config,
)
from azure_sre.contracts import (
    HARD_MAX_CLI_CALL_SECONDS,
    HARD_MAX_CONCURRENCY_PER_REPLICA,
    HARD_MAX_DIAGNOSTIC_CALLS,
    HARD_MAX_EVIDENCE_BYTES,
    HARD_MAX_INVESTIGATION_SECONDS,
    HARD_MAX_ISSUE_BODY_BYTES,
    HARD_MAX_ROWS_PER_QUERY,
    HARD_MAX_WINDOW_AFTER_MINUTES,
    HARD_MAX_WINDOW_BEFORE_MINUTES,
    MAX_METRIC_NAMES,
    MAX_TARGETS_PER_ALERT,
    ContractError,
    Sink,
)

SUB = "11111111-2222-3333-4444-555555555555"
WS = "66666666-7777-8888-9999-aaaaaaaaaaaa"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CALLER = "5c6d7e8f-1234-4abc-9def-0123456789ab"
NIL = "00000000-0000-0000-0000-000000000000"
RG = "rg-shop"
APP = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.App/containerApps/shop-api"
AI = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Insights/components/shop-ai"
LAW = (
    f"/subscriptions/{SUB}/resourceGroups/{RG}"
    "/providers/Microsoft.OperationalInsights/workspaces/shop-law"
)
EXAMPLE = Path(__file__).resolve().parents[2] / "config.example.json"

BUDGET_LIMITS: dict[str, int] = {
    "investigation_seconds": HARD_MAX_INVESTIGATION_SECONDS,
    "cli_call_seconds": HARD_MAX_CLI_CALL_SECONDS,
    "diagnostic_calls": HARD_MAX_DIAGNOSTIC_CALLS,
    "concurrency_per_replica": HARD_MAX_CONCURRENCY_PER_REPLICA,
    "rows_per_query": HARD_MAX_ROWS_PER_QUERY,
    "evidence_bytes": HARD_MAX_EVIDENCE_BYTES,
    "issue_body_bytes": HARD_MAX_ISSUE_BODY_BYTES,
    "window_before_minutes": HARD_MAX_WINDOW_BEFORE_MINUTES,
    "window_after_minutes": HARD_MAX_WINDOW_AFTER_MINUTES,
    "max_targets": MAX_TARGETS_PER_ALERT,
    "max_metric_names": MAX_METRIC_NAMES,
}


def valid() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "deployed_version": "2026.10.13-1",
        "registry": {
            "schema_version": 1,
            "tenant_id": TENANT,
            "applications": [
                {
                    "app_id": "shop-api",
                    "environment": "prod",
                    "subscription_id": SUB,
                    "container_app_id": APP,
                    "app_insights_component_id": AI,
                    "log_analytics_workspace_id": WS,
                    "log_analytics_workspace_resource_id": LAW,
                    "repository": "contoso/shop-api",
                    "installation_id": 42,
                }
            ],
        },
        "webhook_callers": [{"object_id": CALLER, "sink": "production"}],
        "publisher": {
            "key_vault_uri": "https://kv-sre-prod.vault.azure.net/",
            "secret_name": "github-app-private-key",
        },
    }


def with_budget(**overrides: Any) -> dict[str, Any]:
    data = valid()
    data["budget"] = overrides
    return data


def test_valid_config_parses() -> None:
    result = parse_config(valid())
    assert isinstance(result, AppConfig)
    assert result.deployed_version == "2026.10.13-1"
    assert result.registry.get("shop-api") is not None
    assert result.publisher is not None
    assert result.publisher.secret_name == "github-app-private-key"


def test_webhook_caller_is_normalized_and_mapped_to_sink() -> None:
    data = valid()
    data["webhook_callers"] = [{"object_id": CALLER.upper(), "sink": "test"}]
    result = parse_config(data)
    assert result.webhook_callers[0].object_id == CALLER
    assert result.sink_for_caller(CALLER.upper()) is Sink.TEST
    assert result.sink_for_caller(CALLER) is Sink.TEST


def test_unknown_caller_has_no_sink() -> None:
    result = parse_config(valid())
    assert result.sink_for_caller("00000001-2222-3333-4444-555555555555") is None


def test_publisher_is_optional() -> None:
    data = valid()
    del data["publisher"]
    assert parse_config(data).publisher is None


def test_defaults_match_plan() -> None:
    budget = BudgetPolicy()
    assert budget.model_dump() == {
        "investigation_seconds": 300,
        "cli_call_seconds": 30,
        "diagnostic_calls": 12,
        "concurrency_per_replica": 2,
        "rows_per_query": 100,
        "evidence_bytes": 65536,
        "issue_body_bytes": 24576,
        "window_before_minutes": 15,
        "window_after_minutes": 5,
        "max_targets": 8,
        "max_metric_names": 5,
    }


def test_defaults_are_within_hard_maxima() -> None:
    for name, limit in BUDGET_LIMITS.items():
        default = getattr(BudgetPolicy(), name)
        assert 1 <= default <= limit, name


def test_missing_budget_uses_defaults() -> None:
    assert parse_config(valid()).budget == BudgetPolicy()


@pytest.mark.parametrize("name", sorted(BUDGET_LIMITS))
def test_budget_above_hard_max_rejected(name: str) -> None:
    value = BUDGET_LIMITS[name] + 1
    with pytest.raises(ValidationError):
        BudgetPolicy(**{name: value})
    with pytest.raises(ConfigError):
        parse_config(with_budget(**{name: value}))


@pytest.mark.parametrize("name", sorted(BUDGET_LIMITS))
@pytest.mark.parametrize("value", [0, -1])
def test_budget_zero_or_negative_rejected(name: str, value: int) -> None:
    with pytest.raises(ValidationError):
        BudgetPolicy(**{name: value})
    with pytest.raises(ConfigError):
        parse_config(with_budget(**{name: value}))


@pytest.mark.parametrize("name", sorted(BUDGET_LIMITS))
def test_budget_at_hard_max_accepted(name: str) -> None:
    result = parse_config(with_budget(**{name: BUDGET_LIMITS[name]}))
    assert getattr(result.budget, name) == BUDGET_LIMITS[name]


def test_budget_string_rejected() -> None:
    with pytest.raises(ConfigError):
        parse_config(with_budget(investigation_seconds="120"))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(unexpected=True),
        lambda d: d["budget"].update(unexpected=1),
        lambda d: d["webhook_callers"][0].update(extra="x"),
        lambda d: d["publisher"].update(extra="x"),
        lambda d: d["registry"].update(extra="x"),
    ],
)
def test_extra_fields_rejected(mutate: Any) -> None:
    data = valid()
    data["budget"] = {}
    mutate(data)
    with pytest.raises(ConfigError):
        parse_config(data)


def test_schema_version_must_be_one() -> None:
    data = valid()
    data["schema_version"] = 2
    with pytest.raises(ConfigError):
        parse_config(data)


def test_inline_pem_rejected_without_echoing_it() -> None:
    data = valid()
    data["deployed_version"] = "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBgkqhkiG9w0BAQEF"
    with pytest.raises(ConfigError, match="credential material") as info:
        parse_config(data)
    assert "MIIEvQ" not in str(info.value)


@pytest.mark.parametrize(
    "token",
    [
        "ghp_" + "A" * 36,
        "ghs_" + "b" * 36,
        "github_pat_11ABCDEFG0_abcdefghijklmnop",
        "gho_" + "c" * 36,
        "ghu_" + "d" * 36,
    ],
)
def test_github_tokens_rejected(token: str) -> None:
    data = valid()
    data["registry"]["applications"][0]["repository"] = f"contoso/{token}"
    with pytest.raises(ConfigError, match="credential material"):
        parse_config(data)
    with pytest.raises(ConfigError, match="credential material"):
        parse_config(data, allow_placeholders=True)


@pytest.mark.parametrize("key", ["client_secret", "password", "secret_value", "api_key"])
def test_inline_secret_keys_rejected(key: str) -> None:
    data = valid()
    data["publisher"][key] = "not-a-reference"
    with pytest.raises(ConfigError, match="inline secret values"):
        parse_config(data)


def test_publisher_requires_key_vault_reference() -> None:
    data = valid()
    data["publisher"] = {"key_vault_uri": "https://example.com/", "secret_name": "s"}
    with pytest.raises(ConfigError):
        parse_config(data)


def test_publisher_secret_name_must_be_reference_name() -> None:
    data = valid()
    data["publisher"]["secret_name"] = "bad name/with slash"
    with pytest.raises(ConfigError):
        parse_config(data)


def test_nil_tenant_rejected() -> None:
    data = valid()
    data["registry"]["tenant_id"] = NIL
    with pytest.raises(ConfigError, match="placeholder"):
        parse_config(data)


def test_nil_caller_rejected() -> None:
    data = valid()
    data["webhook_callers"][0]["object_id"] = NIL
    with pytest.raises(ConfigError, match="placeholder"):
        parse_config(data)


def test_nil_guid_rejected_regardless_of_case() -> None:
    data = valid()
    data["webhook_callers"][0]["object_id"] = NIL.upper()
    with pytest.raises(ConfigError, match="placeholder"):
        parse_config(data)


def test_placeholder_rejected_in_strict_mode() -> None:
    data = valid()
    data["registry"]["applications"][0]["repository"] = "REPLACE-ORG/REPLACE-REPO"
    with pytest.raises(ConfigError, match="placeholder"):
        parse_config(data)


def test_placeholder_accepted_with_allow_placeholders() -> None:
    data = valid()
    data["registry"]["applications"][0]["repository"] = "REPLACE-ORG/REPLACE-REPO"
    data["registry"]["tenant_id"] = NIL
    result = parse_config(data, allow_placeholders=True)
    assert result.registry.applications[0].repository == "REPLACE-ORG/REPLACE-REPO"


def test_duplicate_webhook_caller_rejected() -> None:
    data = valid()
    data["webhook_callers"] = [
        {"object_id": CALLER, "sink": "production"},
        {"object_id": CALLER.upper(), "sink": "test"},
    ]
    with pytest.raises(ConfigError, match="duplicate"):
        parse_config(data)


def test_unknown_sink_rejected() -> None:
    data = valid()
    data["webhook_callers"][0]["sink"] = "staging"
    with pytest.raises(ConfigError):
        parse_config(data)


def test_webhook_caller_must_be_guid() -> None:
    data = valid()
    data["webhook_callers"][0]["object_id"] = "not-a-guid"
    with pytest.raises(ConfigError):
        parse_config(data)


def test_webhook_callers_require_at_least_one() -> None:
    data = valid()
    data["webhook_callers"] = []
    with pytest.raises(ConfigError):
        parse_config(data)


def test_registry_conflicts_still_enforced() -> None:
    data = valid()
    data["registry"]["applications"].append(
        {**data["registry"]["applications"][0], "repository": "contoso/other"}
    )
    with pytest.raises(ConfigError, match="duplicate app_id"):
        parse_config(data)


def test_non_mapping_rejected() -> None:
    with pytest.raises(ConfigError):
        parse_config([])  # type: ignore[arg-type]


def test_load_config_from_file(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(valid()), encoding="utf-8")
    result = load_config(path)
    assert result.registry.get("shop-api") is not None
    assert load_config(str(path)).deployed_version == "2026.10.13-1"


def test_load_config_oversized_file_rejected(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1) + json.dumps(valid()).encode())
    with pytest.raises(ConfigError, match="exceeds"):
        load_config(path)


def test_load_config_file_at_limit_is_read(tmp_path: Path) -> None:
    body = json.dumps(valid()).encode()
    path = tmp_path / "edge.json"
    path.write_bytes(body + b" " * (MAX_CONFIG_BYTES - len(body)))
    assert load_config(path).schema_version == 1


def test_load_config_invalid_json_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(path)


def test_load_config_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.json")


def test_load_config_applies_placeholder_rules(tmp_path: Path) -> None:
    path = tmp_path / "placeholder.json"
    data = valid()
    data["registry"]["tenant_id"] = NIL
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)
    assert load_config(path, allow_placeholders=True).schema_version == 1


def test_example_file_validates_with_placeholders() -> None:
    result = load_config(EXAMPLE, allow_placeholders=True)
    assert result.registry.get("shop-api") is not None
    assert result.webhook_callers[0].sink is Sink.PRODUCTION
    assert result.publisher is not None


def test_example_file_rejected_in_strict_mode() -> None:
    with pytest.raises(ConfigError, match="placeholder"):
        load_config(EXAMPLE)


def test_example_file_has_only_documented_keys() -> None:
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert set(data) == {
        "schema_version",
        "deployed_version",
        "budget",
        "registry",
        "webhook_callers",
        "publisher",
    }


def test_contract_error_from_nested_model_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_sre import config as cfg

    def boom(*_args: object, **_kwargs: object) -> None:
        raise ContractError("invalid_report", "secret-looking-value-xyz")

    monkeypatch.setattr(cfg.AppConfig, "model_validate", boom)
    with pytest.raises(ConfigError) as info:
        parse_config(with_budget())
    assert "invalid_report" in str(info.value)
    assert "secret-looking-value" not in str(info.value)
    assert info.value.__cause__ is None
