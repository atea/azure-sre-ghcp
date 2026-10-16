# Copilot instructions

## Project shape

This is a Python 3.13 service packaged with `uv` (`src/azure_sre`). It accepts Azure Monitor
Common Alert Schema webhooks, investigates Container Apps incidents using bounded, read-only
Azure diagnostics, and publishes verified GitHub issues and recovery comments. It does not
remediate Azure resources or close issues.

- `ingress/` authenticates and authorizes the Entra caller before reading and validating the
  request body, then durably enqueues the normalized alert in Service Bus.
- `worker/` consumes and revalidates messages against the current trusted registry.
  `state/` persists incident and recovery state in Azure Table Storage with ETag-guarded
  transitions; reports are stored in Blob Storage.
- `investigation/` coordinates a Copilot SDK session with host-owned diagnostics. `diagnostics/`
  builds commands and KQL from fixed templates and trusted registry values, collects bounded
  evidence, and never executes model-provided commands or queries.
- `github/` renders reports and publishes through the pinned GitHub MCP server. The worker
  persists publication intent first and reconciles uncertain writes by marker rather than
  blindly creating duplicates.
- `security/` owns credential loading, token providers, and redaction. `infra/` contains the
  Bicep deployment; the shared image runs distinct receiver and worker roles.

For behavior and operational constraints, consult the relevant `docs/` references, especially
`configuration.md`, `diagnostics.md`, `worker.md`, `publication.md`, and `integration-gates.md`.

## Build, test, and lint

Install the locked development environment with `uv sync`. Run the main checks:

```bash
uv run ruff check .
uv run mypy
uv run pytest -q -m "not live"
```

Run one test file or one test:

```bash
uv run pytest tests/unit/test_ingress.py -q
uv run pytest tests/unit/test_ingress.py::test_valid_token_enqueues_normalized_alert_and_returns_202 -q
```

The offline SDK runtime and GitHub MCP gates need their pinned binaries prepared first:

```bash
uv run python -m copilot download-runtime
scripts/fetch_github_mcp_server.sh
GITHUB_MCP_SERVER_PATH=$PWD/.work/gms/github-mcp-server uv run pytest -q
```

The smoke checks can also be run directly:

```bash
uv run python -m azure_sre.runtime.smoke offline
export GITHUB_MCP_SERVER_PATH="$PWD/.work/gms/github-mcp-server"
uv run python -m azure_sre.runtime.smoke mcp-tools --binary "$GITHUB_MCP_SERVER_PATH"
```

The smoke command starts its isolated runtime with `COPILOT_SKIP_CLI_DOWNLOAD=1`; download the
pinned runtime before using that skip flag. Live tests are opt-in with `SRE_LIVE_GATES=1` and
require external Azure, tenant, and GitHub setup.

Infrastructure CI validates Bicep separately:

```bash
az bicep lint --file infra/main.bicep
az bicep build --file infra/main.bicep --outfile /tmp/main.json
for parameters in infra/environments/*.bicepparam; do
  az bicep build-params --file "$parameters" --outfile "/tmp/$(basename "$parameters").json"
done
```

## Repository-specific invariants

- Keep credentials out of JSON configuration and environment parameters; configuration stores
  identifiers and Key Vault references. The receiver has no Key Vault credentials. Worker
  inference and GitHub-publisher credentials must use separate secrets, and separate Apps when
  both use App authentication.
- Treat alerts, queue messages, model output, and diagnostic results as untrusted. Validate
  contracts and bind routing/resource fields to the trusted registry; keep caller-to-sink
  authorization outside the payload.
- Diagnostics must remain allowlisted, read-only, and bounded by the host's fixed templates and
  configured hard limits. Do not pass model text into CLI arguments, KQL, URLs, or resource IDs.
  Preserve explicit error, truncation, and partial-evidence outcomes rather than treating missing
  or malformed data as healthy.
- Durable incident changes must use conditional state transitions. Persist remote-write intent
  before publishing; after an ambiguous outcome, reconcile by marker. Test-sink incidents must
  never invoke the publisher, and recovery is a comment rather than issue closure.
- Keep logs and errors safe: use categorized codes and exception types, not raw alert bodies,
  model responses, stderr, credentials, or exception text.
- Tests generally replace Azure, model, and GitHub network boundaries with fakes. The
  acceptance test exercises real in-process components across the full pipeline; it is offline
  and does not replace the opt-in live acceptance gates.
