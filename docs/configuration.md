# Configuration reference

The service reads one JSON document, validated by `azure_sre.config`. The file holds
identifiers and Key Vault references only. Secret material never goes in the file.

Load it with `load_config(path)` or validate a decoded mapping with `parse_config(data)`.
Both reject unknown keys, values outside the limits below, and files over 256 KiB.

## Top-level keys

| Key | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `schema_version` | integer | yes | none | Must be `1`. |
| `deployed_version` | string | yes | none | 1-64 chars of `A-Z a-z 0-9 . _ + -`. |
| `budget` | object | no | see below | Per-investigation limits. |
| `registry` | object | yes | none | Tenant and application mappings. |
| `webhook_callers` | array | yes | none | At least one entry. |
| `publisher` | object | no | none | Key Vault reference for the publisher key. |

## `budget`

Every value must be an integer (no booleans, floats, or strings) from 1 to the hard maximum.
Defaults are used for omitted keys.

| Key | Default | Hard max |
| --- | --- | --- |
| `investigation_seconds` | 300 | 300 |
| `cli_call_seconds` | 30 | 30 |
| `diagnostic_calls` | 12 | 12 |
| `concurrency_per_replica` | 2 | 2 |
| `rows_per_query` | 100 | 100 |
| `evidence_bytes` | 65536 | 65536 |
| `issue_body_bytes` | 24576 | 24576 |
| `window_before_minutes` | 15 | 60 |
| `window_after_minutes` | 5 | 30 |
| `max_targets` | 8 | 16 |
| `max_metric_names` | 5 | 10 |

Hard maximums come from `azure_sre.contracts` and cannot be raised by configuration.

Investigation windows are anchored on the alert onset (`fired_at`): the query span is always exactly `window_before_minutes + window_after_minutes`, regardless of delivery delay or how long a Resolved alert stayed active.

## `registry`

| Key | Type | Notes |
| --- | --- | --- |
| `schema_version` | integer | Must be `1`. |
| `tenant_id` | GUID | Entra tenant. |
| `applications` | array | At least one mapping. `app_id` values must be unique. |

Each application mapping uses the field rules in `azure_sre.contracts.ApplicationMapping`:

- `app_id`, `environment`: names.
- `subscription_id`: GUID. Every ARM resource ID below must sit in this subscription.
- `container_app_id`: `/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.App/containerApps/<name>`.
- `app_insights_component_id`: `.../providers/Microsoft.Insights/components/<name>`.
- `log_analytics_workspace_id`: workspace GUID.
- `log_analytics_workspace_resource_id`: optional `.../providers/Microsoft.OperationalInsights/workspaces/<name>`.
- `app_insights_workspace_id`, `app_insights_workspace_resource_id`: optional pair, the
  workspace GUID and ARM ID receiving this component's App Insights telemetry. Both must
  be provided together. If omitted, AI queries retain the legacy Container Apps workspace
  routing. Baseline `app_insights_configuration` verifies the component's
  `WorkspaceResourceId` against the configured ARM ID (or legacy workspace ARM ID);
  missing or mismatched linkage produces an explicit evidence gap.
  Grant the worker Reader on the component and Log Analytics Reader on its workspace;
  no broader subscription/group grants are needed.
- `repository`: `owner/name`.
- `installation_id`: positive integer, the GitHub App installation.

## `webhook_callers`

Each entry maps an Entra object ID to the sink it may use.

| Key | Type | Notes |
| --- | --- | --- |
| `object_id` | GUID | Stored lowercase. Duplicates are rejected. |
| `sink` | `production` or `test` | Sink for this caller. |

The webhook auth path calls `AppConfig.sink_for_caller(object_id)`. It returns `None` for unknown
callers. Payload fields never influence this mapping.

## `publisher` (optional)

| Key | Type | Notes |
| --- | --- | --- |
| `key_vault_uri` | string | `https://<vault>.vault.azure.net/` (also `usgovcloudapi.net`, `azure.cn`). |
| `secret_name` | string | 1-127 chars of `A-Z a-z 0-9 -`. A reference name, not a value. |

## Secrets

- Only Key Vault references are accepted. Keys named `client_secret`, `password`,
  `secret_value`, `api_key`, `private_key`, `access_token`, `token`, or `secret` are rejected.
- Values that look like PEM blocks (`-----BEGIN`) or GitHub tokens (`ghp_`, `ghs_`, `gho_`,
  `ghu_`, `ghr_`, `github_pat_`) are rejected anywhere in the document.
- Error messages name the location of the problem and never echo the offending value.

## Placeholder rules

Strict loading rejects placeholders:

- any string containing `REPLACE`
- the nil GUID `00000000-0000-0000-0000-000000000000`, including webhook caller IDs

Pass `allow_placeholders=True` to accept them. Use this only for the checked-in example and tests.
Production deployments must load without it.

## Example

`config.example.json` at the repository root is a complete document with placeholder values.
It validates with `allow_placeholders=True` and fails in strict mode:

```python
from azure_sre.config import load_config

load_config("config.example.json", allow_placeholders=True)  # ok
load_config("config.example.json")  # ConfigError: placeholder value
```

## Errors

Invalid input raises `ConfigError`, a subclass of `ValueError`. The message names the failing
location, for example `registry.applications[0].subscription_id`, and gives the reason.
