# Deployment

Status: offline-implemented and offline-validated only. No Azure deployment has been run, and no live gate is passed. Live gates L3 and L6 in `docs/integration-gates.md` remain open.

## Topology

- One container image runs two Container Apps:
  - **receiver**: external HTTPS ingress on port 8080 (`allowInsecure: false`), command `python -m azure_sre receiver`. Liveness `/healthz`, readiness `/readyz`. It only enqueues to Service Bus.
  - **worker**: no ingress, command `python -m azure_sre worker`, scaled by a KEDA `azure-servicebus` rule on the queue. `minReplicas=1` keeps durable reconcilers running.
- Each app has its own user-assigned managed identity (UAMI) (`infra/modules/rbac.bicep`).
- Container Apps environment API `Microsoft.App/*@2025-01-01`. This is the first stable API that accepts `identity` on the custom scale rule, so no BCP037 suppression is needed.
- Service Bus Standard queue `sre-incidents`: dead-letter on expiration, max delivery count 10, lock 1 minute, 14-day TTL, duplicate detection.
- Storage account (ZRS, public blob access off, shared key off, OAuth default) with private containers `sre-config` (reviewed source registry) and `sre-evidence` (worker evidence), plus table `sreState`.
- Log Analytics (30-day retention) and workspace-based Application Insights.

## Identities and RBAC (least privilege)

| Identity | Role | Scope |
|---|---|---|
| receiver | AcrPull | ACR |
| receiver | Azure Service Bus Data Sender | queue `sre-incidents` |
| receiver | Storage Blob Data Reader | `sre-config` container |
| worker | AcrPull | ACR |
| worker | Azure Service Bus Data Receiver | queue `sre-incidents` |
| worker | Storage Table Data Contributor | `sreState` table |
| worker | Storage Blob Data Reader | `sre-config` container |
| worker | Storage Blob Data Contributor | `sre-evidence` container |
| worker | Key Vault Secrets User | whole vault (Key Vault RBAC cannot scope to one secret) |
| worker | Reader (opt-in) | each Container App named in `diagnosticContainerAppNames` |
| worker | Log Analytics Reader (opt-in) | workspace named in `diagnosticsWorkspaceName` |

- The **receiver holds no Key Vault role and no Key Vault reference**, so it has no inference or publisher credentials.
- No role is granted at subscription or resource-group scope. Reader is never granted at subscription scope.
- The worker's Key Vault access is the only path to secret values. Secrets are loaded at runtime through the Key Vault SDK, not injected as environment variables. Container Apps `secrets` are not used.

## Environment contract (non-secret)

Set by `infra/main.bicep`. The app must read these exact names.

| Variable | Receiver | Worker | Value |
|---|---|---|---|
| `SRE_ROLE` | yes | yes | `receiver` / `worker` |
| `SRE_PORT` | yes | no | `8080` |
| `AZURE_CLIENT_ID` | yes | yes | the role's UAMI client ID |
| `AZURE_SERVICEBUS_NAMESPACE` | yes | yes | Service Bus FQDN |
| `AZURE_SERVICEBUS_QUEUE_NAME` | yes | yes | `sre-incidents` |
| `SRE_SOURCE_CONFIG_URL` | yes | yes | `https://<account>.blob.core.windows.net/sre-config/sources.json` |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | yes | yes | workspace-based App Insights |
| `AZURE_STORAGE_TABLE_URL` | no | yes | table endpoint |
| `SRE_STATE_TABLE_NAME` | no | yes | `sreState` |
| `AZURE_STORAGE_BLOB_URL` | no | yes | blob endpoint |
| `SRE_EVIDENCE_CONTAINER_NAME` | no | yes | `sre-evidence` |
| `AZURE_KEY_VAULT_URL` | no | yes | vault URI (secret values loaded via SDK) |

The KEDA scaler `namespace` metadata is the Service Bus namespace **name** (`sb-<prefix>`), not the FQDN. The SDK env `AZURE_SERVICEBUS_NAMESPACE` remains the FQDN.

Non-secret role configuration (such as allowed targets) is read from `sources.json` in `sre-config`, which both roles read through their UAMI. Nothing secret is placed in that file.

## Prerequisites (out of band, not created by this template)

- Existing Azure Container Registry in the same resource group (`acrName`). Apps pull with their UAMI (`AcrPull`).
- Existing Key Vault in the same resource group (`keyVaultName`). Secret names and values are supplied out of band. The template writes no secret values and references no secrets.
- Existing Container Apps in the same resource group, if the worker needs diagnostics: list them in `diagnosticContainerAppNames`. The worker receives Reader on each one. Leave it empty to grant nothing.
- Existing Log Analytics workspace, only if approved: set `diagnosticsWorkspaceName`. Leave it empty to grant nothing.
- Reviewed `sources.json` uploaded to the `sre-config` container before the apps start.
- Image pushed to ACR. The Dockerfile builds `linux/amd64` only (the pinned GitHub MCP server asset is amd64).

## Build

```sh
docker build --platform linux/amd64 -t <acr>.azurecr.io/azure-sre-copilot:<version> .
```

The image is non-root (UID/GID 65532). It bakes in:
- Python 3.13 runtime and the locked app environment (`uv sync --frozen`).
- Copilot CLI runtime (predownloaded via `copilot download-runtime`; `COPILOT_SKIP_CLI_DOWNLOAD=1`, so nothing downloads at incident time).
- GitHub MCP server v2.0.2, SHA-256 verified by `scripts/fetch_github_mcp_server.sh`.
- Azure CLI 2.91.0 in `/opt/az`, with the `log-analytics` extension 1.0.0b3 in `/opt/az-ext`. The extension wheel is checked against a pinned SHA-256.

Runtime env is isolated: `AZURE_CONFIG_DIR=/var/lib/sre/azure`, `HOME=/var/lib/sre/home`, both owned by the runtime user.

## Deploy (when live prerequisites exist)

```sh
az group create -n <rg> -l <location>
az deployment group create -g <rg> -f infra/main.bicep -p infra/environments/dev.bicepparam \
  -p image=<acr>.azurecr.io/azure-sre-copilot:<version>
```

Edit `infra/environments/dev.bicepparam` placeholders first: resource/image inputs,
webhook audience/caller/role, inference auth (`inferenceAuthMode`: `pat` by default
with `inferencePatSecretName`, or `app` with the inference App ID, installation and PEM
secret name, distinct from the publisher App), publisher App ID, bot login and approved model.
Diagnostic workspace and named Container Apps must be explicitly approved.
Publisher PEM reference belongs in the reviewed `sources.json`; secret values never
belong in Bicep parameters.

## Validation done offline

- `az bicep lint --file infra/main.bicep` and `az bicep build --file infra/main.bicep` pass with no warnings (Bicep 0.39.26).
- `az bicep build-params --file infra/environments/dev.bicepparam` passes.
- `docker build --platform linux/amd64` passed on the previous Dockerfile. The Dockerfile is unchanged in the fix round.
- Not run: `az deployment group validate` (needs login and an existing resource group), `hadolint` (not installed), any runtime test of `python -m azure_sre` (entrypoint is wired by the app team), and any check that the app binds 8080 or serves `/healthz` and `/readyz` (app contract pending).

## Known limitations and tradeoffs

- **Storage public network access is Enabled** by default because there is no VNet or private endpoint yet. Blob public access and shared keys are off, and RBAC is the only auth path. Set `storagePublicNetworkAccess=Disabled` only after private endpoints exist.
- **Key Vault RBAC cannot be scoped to individual secrets.** The worker holds `Key Vault Secrets User` on the whole vault. The receiver holds none.
- **Log Analytics shared key passes through ARM.** The Container Apps environment needs the workspace key (`listKeys`), so it appears in the deployment, not in the repo. Remediate with a managed-identity-based log destination when available.
- **Worker minReplicas=1** keeps durable reconcilers running but costs money while idle. Max replicas (3) is the fan-out budget; raise it deliberately.
- **Retention:** Log Analytics 30 days; Service Bus dead-letters persist until handled (message TTL 14 days).
- **Image base** `python:3.13-slim-bookworm` is not digest-pinned yet. Pin it before production.
- **Contracts pending from the app team:** port 8080 binding, `/healthz` and `/readyz` handlers, `SRE_PORT`, the env names above, and the `python -m azure_sre receiver|worker` entrypoint. Any mismatch must be fixed in the app or in `main.bicep` before deployment.
- **KEDA scaler identity** is declared through the `2025-01-01` API. Whether KEDA needs `Azure Service Bus Data Receiver` for the scaler is unverified and must be confirmed in the live gate.
- **No CI workflow** is included; the repository has no connected Git remote.
