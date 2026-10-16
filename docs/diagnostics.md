# Diagnostics evidence collection

Bounded, read-only Azure diagnostics that return typed `EvidenceItem` / `EvidenceBundle`
objects from `azure_sre.contracts`. Collection never accepts arbitrary KQL, URLs, CLI flags,
or resource IDs from a model.

## Public interfaces

Package `azure_sre.diagnostics`:

- `DiagnosticsCollector(*, registry, runner, env, budget=None, clock=None, cancel=None)`
  - `collect(app_id, kind, window, selector=None) -> EvidenceItem` (always `E1`)
  - `collect_bundle(*, incident_key, app_id, window, kinds, selector=None) -> EvidenceBundle`
    (ids `E1`, `E2`, ... in call order)
- `DiagnosticKind` (StrEnum): `container_app_health`, `container_app_revisions`,
  `app_insights_exceptions`, `app_insights_operations`, `container_app_console_logs`,
  `container_app_system_logs`, `activity_log_deployments`.
- `CorrelationSelector(operation_id: str | None)`: operation IDs must match
  `^[A-Za-z0-9._:-]{1,128}$`. Only the AI operation tables accept it.
- `DiagnosticsError(ValueError)`: rejected selectors, unknown apps, oversized windows.
- `EvidenceBudgetExhausted(ValueError)`: even the minimum envelopes cannot fit. Carries
  `fitted` and `omitted_evidence_ids` so the host can handle partial results. Evidence is
  never dropped silently.
- `AzureCliSession(root, client_id, extension_dir, runner, az_path="az", identity_env=None)`
  - `initialize()`: host-only `az login --identity --client-id=<guid>
    --allow-no-subscriptions --output=none`, run once under a lock with a 30 s timeout.
  - `worker_env(worker) -> Mapping[str, str]`: private per-worker `AZURE_CONFIG_DIR`
    (mode 0700) seeded with a copy of `azureProfile.json` only. No token cache is copied.
  - `identity_env`: optional host-supplied map. Only `IDENTITY_ENDPOINT`, `IDENTITY_HEADER`,
    `MSI_ENDPOINT`, and `MSI_SECRET` are kept. Endpoints must be http/https with a loopback,
    link-local, or localhost host, at most 512 characters, and free of control characters.
    Values are never logged.
  - `CliSessionError`: invalid identity environment or failed login.
- `SubprocessRunner(max_stdout_bytes=8 MiB, max_stderr_bytes=64 KiB)` / `CommandRunner` /
  `CommandResult`:
  - argv lists only, `shell=False`, `close_fds`, stdin closed, `start_new_session=True`.
  - stdout and stderr are capped while the process runs, not trimmed afterwards. On a cap the
    exact process group is terminated and the result has `output_limit=True`.
  - On timeout, cancel, or cap, only that process group is terminated (SIGTERM, then SIGKILL
    after 2 s). No broad kills.
  - A `PermissionError` on signal is probed. If the group is still alive, `CommandCleanupError`
    is raised and mapped to a categorized `ERROR`.

Module `azure_sre.security.redaction`: `redact_text(str)`, `redact_value(Any)`. Recursive,
depth-limited. Redacts PEM blocks, JWTs, GitHub tokens, bearer tokens, secret key/value pairs,
connection strings, emails, IPv4 and IPv6 addresses.

## Templates

Fixed templates only (`TEMPLATES`). Every KQL query is bound to its resource and time window.

| Kind | Command | Binding |
| --- | --- | --- |
| Container app health | `az containerapp show` | name, resource group |
| Container app revisions | `az containerapp revision list` | name, resource group |
| AI exceptions / operations | `az monitor log-analytics query --workspace <GUID>` | `AppExceptions` / `AppRequests`+`AppDependencies` filtered by AI component `_ResourceId` and time |
| Console / system logs | `az monitor log-analytics query --workspace <GUID>` | `ContainerAppConsoleLogs_CL` / `ContainerAppSystemLogs_CL` filtered by Container App `_ResourceId` and time; empty IDs fall back to trusted `ContainerAppName_s` within the application-owned workspace |
| Deployments | `az monitor activity-log list --resource-id <ARM ID>` | one resource ID, `--start-time` / `--end-time` |

The AI component (`_ResourceId` for AI tables) and the Container App (`_ResourceId` for
container logs) are kept separate. Each query takes at most 101 rows: 100 are kept, and an
extra row marks the result as truncated. The server limit is only a hint, so the host also
truncates.

Container log templates v2 accept an empty `_ResourceId` only when `ContainerAppName_s`
matches the registry application name. Non-empty conflicting IDs are never accepted.
The workspace must be dedicated to this application (as required by registry ownership);
do not configure this fallback against a workspace containing identically named apps from
different Container Apps environments.

## Row projection

The host baseline collects health, `container_app_console_errors`, AI workspace linkage,
then AI exceptions
before opening the model session. The console error template groups DNS resolution failures,
HTTP 5xx access logs and application error lines by error class and revision. Each group
contains a count, first/last timestamp and one sample capped at 1000 characters. Results
use the normal row/byte limits and redaction; zero matches are not proof of health.
This evidence is retained even if inference fails.

`project_row` keeps only allowlisted scalar fields (dotted paths for nested JSON). It returns
`None` when a row has no recognised field. Such payloads are classified as `ERROR`
("unrecognised schema"), never as healthy or zero rows. Empty stdout from a health command is
an `ERROR`, not `ZERO_ROWS`.

## Budgets

Defaults come from `BudgetPolicy`: 300 s total, 30 s per command, 12 calls, 2 concurrent
workers, 100 rows per query, 64 KiB bundle, 24 KiB issue body (UTF-8). The window must fit
`before + after` minutes (default 15 + 5), anchored on the historical `fired_at`.

`fit_items` trims rows from the most-populated item first and marks it `truncated`. An item
left with no rows becomes an `ERROR` gap ("omitted: evidence byte budget exceeded"). If even
the gap envelopes cannot fit, `EvidenceBudgetExhausted` is raised. Zero rows is `ZERO_ROWS`,
never reported as healthy.

## Error categories

Failures map to `EvidenceStatus` with fixed messages. Raw stderr is never returned or
recorded.

- `TIMEOUT`: command exceeded its per-call limit; process group terminated.
- `ERROR`: cancelled, output limit exceeded (explicit, never truncated success), cleanup
  failure, empty or malformed output, or unclassified nonzero exit.
- `PERMISSION_DENIED`: `AuthorizationFailed` / `Forbidden` in stderr.
- `MISSING_TELEMETRY`: `failed to resolve` in stderr (e.g. workspace not found).

## Assumptions (not verified against live Azure)

These need confirmation in the live-gated test. Until then, the live item stays pending.

- CLI flags were checked with `az --help` for 2.88.0 (local) and in the built image for CLI 2.91.
  `az login --client-id` is present in both.
- `az monitor log-analytics query` accepts `--workspace`, `--analytics-query`, `--timespan`,
  `--output`.
- `az monitor activity-log list` accepts `--resource-id`, `--start-time`, `--end-time`,
  `--max-events`, `--output`.
- The `containerapp` commands (`az containerapp show`, `az containerapp revision list`) are
  available in the offline image (`azure-sre-copilot:offline-check`, CLI 2.91, verified by the
  parent with `--help`). No extension download is needed at runtime.
- Columns exist as used: `AppExceptions` (OperationId, OuterMessage, ProblemId, ExceptionType,
  AppRoleName); container logs (RevisionName_s, ContainerName_s, Stream_s, Log_s).
- MI token refresh for workers relies on the passed `IDENTITY_ENDPOINT`/`IDENTITY_HEADER`
  (or `MSI_*`) variables and the copied `azureProfile.json`. No token cache is copied. This
  is unverified. If refresh fails in the live test, the fallback is a per-worker login under
  the same identity environment.

## Tests

- `tests/unit/test_diagnostics_collector.py`: query binding, scope, budgets and exact
  thresholds, multibyte bytes, error mapping, output_limit, empty and malformed output,
  `project_row` rejection, and `fit_items` gap and exhaustion behaviour.
- `tests/unit/test_diagnostics_executor.py`: real subprocess timeout and cancel (grandchild
  termination), stdout and stderr caps, shell metacharacters as argv, CLI login flags,
  identity env allowlist and endpoint validation, and env isolation.
- `tests/unit/test_redaction.py`: secret shapes, recursion, depth guard.
