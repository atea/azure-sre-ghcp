# Azure SRE Copilot

Python 3.13 / uv service under implementation: Azure Monitor secure webhook,
managed-identity diagnostics, bounded GitHub Copilot SDK investigation and
host-controlled GitHub MCP issue publication. No remediation or automatic issue closure.

**Offline source is not deployment acceptance.** Live authentication gates require
the tenant, managed identities, separate inference/publisher GitHub Apps and a
designated test deployment. See [implementation status](docs/implementation-status.md)
and [integration gates](docs/integration-gates.md).

```bash
uv sync
uv run python -m copilot download-runtime      # pinned runtime 1.0.96, checksum-verified
scripts/fetch_github_mcp_server.sh             # github-mcp-server v2.0.2, sha256-verified
uv run python -m azure_sre.runtime.smoke offline
GITHUB_MCP_SERVER_PATH=$PWD/.work/gms/github-mcp-server uv run pytest -q
uv run ruff check . && uv run mypy
```

Reviewed configuration is described in [configuration](docs/configuration.md);
`config.example.json` contains placeholders and is rejected by default at startup.
Use `SRE_CONFIG_PATH` for an approved local file or `SRE_SOURCE_CONFIG_URL` for a
fixed private Azure Blob JSON file accessed with explicit managed identity.
Never put PEM keys or tokens into configuration.

Deployment templates and image build instructions are in
[deployment](docs/deployment.md), including GitHub Actions CI, manual infrastructure
deployment and application build/deploy to Azure using OIDC. Configure the `dev`
GitHub environment and Azure prerequisites there before enabling deployment.
The receiver, worker and application entrypoint
are wired (`python -m azure_sre receiver|worker`); building the image alone does not
prove live service readiness. See [implementation status](docs/implementation-status.md)
for required role settings.
See [onboarding](docs/onboarding.md), [operations](docs/operations.md) and
[data handling](docs/data-handling.md) before enabling real alerts.
