# Azure SRE Copilot

**Alert-driven, read-only incident investigation for Azure Container Apps.**
Azure SRE Copilot accepts Azure Monitor alerts, gathers bounded diagnostics, and
publishes a verified incident report to a trusted GitHub repository. It is built
to make evidence and uncertainty visible—not to make changes to your Azure
resources.

## What it does

```mermaid
flowchart LR
    A[Azure Monitor] -->|Entra-authenticated webhook| B[Receiver]
    B -->|Durable normalized alert| C[Service Bus]
    C --> D[Worker]
    D -->|Allowlisted read-only diagnostics| E[Azure Monitor data]
    D -->|Bounded evidence| F[Copilot investigation]
    D -->|Verified, reconciled write| G[GitHub issue]
    D --> H [Azure Table and Blob Storage]
```

1. The receiver authenticates and authorizes the Entra caller, validates the
   alert against reviewed configuration, then durably queues it.
2. The worker revalidates the message against the current trusted registry and
   gathers bounded, read-only Azure diagnostics.
3. An isolated Copilot SDK session can use only host-provided diagnostic tools.
   The host validates the report, preserves gaps, and renders the issue.
4. The worker persists publication intent before writing. If a result is
   uncertain, it reconciles by marker instead of blindly creating a duplicate.

The publisher never closes issues. Test-sink alerts are investigated and
recorded but never published to GitHub.

## Security and reliability at a glance

- **Trusted routing:** repository, installation, Azure resource scope, and
  caller-to-sink authorization come from reviewed configuration—not alert or
  model content.
- **Read-only diagnostics:** fixed command and KQL templates, bounded time
  windows, row and byte budgets, and explicit error/truncation outcomes.
- **Isolated inference:** the model has no Azure credentials or GitHub write
  tools; its output is validated and redacted before publication.
- **Least-privilege identities:** separate receiver and worker managed
  identities, inference credentials, and publisher GitHub App.
- **Durable processing:** ETag-guarded incident state, persisted reports, and
  marker-based reconciliation for ambiguous GitHub writes.
- **No remediation:** the service does not modify Azure resources or
  automatically close GitHub issues.

## Project status

The offline source, runtime-policy checks, publisher integration, Bicep
validation, and in-process pipeline acceptance are implemented. GitHub Actions
CI runs linting, type-checking, offline runtime/MCP gates, tests, and Bicep
validation.

Live authentication, real Azure diagnostics, Container Apps deployment and
scaling, and real GitHub publication remain gated on external tenant,
subscription, identity, credential, and test-repository setup. Offline tests do
not prove live deployment readiness. See [implementation status](docs/implementation-status.md)
and [integration gates](docs/integration-gates.md) for the exact boundary.

## Get started

### Requirements

- Python 3.13
- [uv](https://docs.astral.sh/uv/)
- Git

The pinned Copilot runtime and GitHub MCP server are needed for the offline
runtime and publisher gates. No Azure or GitHub credentials are needed for the
offline checks.

### Install and verify

```bash
uv sync
uv run ruff check .
uv run mypy
uv run pytest -q -m "not live"
```

To prepare and run the pinned offline runtime and MCP checks:

```bash
uv run python -m copilot download-runtime
scripts/fetch_github_mcp_server.sh
uv run python -m azure_sre.runtime.smoke offline
export GITHUB_MCP_SERVER_PATH=$PWD/.work/gms/github-mcp-server
uv run python -m azure_sre.runtime.smoke mcp-tools \
  --binary "$GITHUB_MCP_SERVER_PATH"
uv run pytest -q
```

The full test command excludes opt-in live tests by default. Live gates require
separate setup and must only target a dedicated test org, repository, and
non-production Azure subscription. Do not enable them against production.

## Configuration and deployment

Configuration is strict JSON containing identifiers and Key Vault references;
it does not accept credentials or secret values. The checked-in
`config.example.json` contains placeholders and is intentionally rejected by
default. Review [configuration](docs/configuration.md) before preparing an
approved configuration.

The deployment uses one image for two Azure Container Apps: an HTTPS receiver
and a worker with no ingress. Bicep and GitHub Actions deployment workflows are
provided, but deployment requires existing Azure prerequisites and external
identity setup. Follow the [deployment guide](docs/deployment.md) and
[onboarding runbook](docs/onboarding.md); do not treat a successful offline
build or CI run as live acceptance.

## Documentation

| Guide | What it covers |
|---|---|
| [Onboarding](docs/onboarding.md) | Scope approval, prerequisites, pilot, and offboarding |
| [Configuration](docs/configuration.md) | Registry schema, budgets, validation, and secret references |
| [Deployment](docs/deployment.md) | Azure topology, identities, Bicep, image, and CI/CD |
| [Ingress](docs/ingress.md) | Secure webhook authentication, validation, and durable enqueue |
| [Diagnostics](docs/diagnostics.md) | Read-only templates, evidence limits, and error handling |
| [Investigation](docs/investigation.md) | Copilot SDK isolation, report validation, and partial outcomes |
| [Worker](docs/worker.md) | Queue processing, durable state, retries, and reconciliation |
| [Publication](docs/publication.md) | GitHub issue rendering, verification, and uncertain-write handling |
| [Operations](docs/operations.md) | Identity boundaries, rotation, incident handling, and sign-off |
| [Data handling](docs/data-handling.md) | Data flows, redaction, disclosure, and retention |
| [Integration gates](docs/integration-gates.md) | Pinned components and offline/live acceptance gates |
| [Offline acceptance](docs/offline-acceptance.md) | End-to-end offline scenarios and their limitations |
| [Implementation status](docs/implementation-status.md) | Completed source milestones and production blockers |

## Technology

Python 3.13 · FastAPI · Azure Service Bus · Azure Table and Blob Storage ·
Azure Monitor · GitHub Copilot SDK · GitHub MCP server · Bicep
