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

## GitHub Actions

Three workflows are provided:

| Workflow | Trigger | Behavior |
|---|---|---|
| `ci.yml` — Application CI | Pull requests, pushes to `main`, manual, reusable by CD | Frozen Python 3.13 dependencies, Ruff, mypy, unit/integration/acceptance tests excluding live gates, mandatory pinned runtime/MCP smoke gates, offline Bicep lint/build and parameter compilation. No Azure credentials. |
| `infra-deploy.yml` — Infrastructure deployment | Manual, on `main` only | Compiles `infra/environments/dev.bicepparam`, rejects placeholders, overrides the image with a required digest, validates against Azure and runs what-if. `apply=false` is preview-only; `apply=true` then applies the same parameters. |
| `cd.yml` — Application build and deployment | Application/build/test/workflow changes on `main`, or manual on `main` | Requires reusable CI, builds/pushes one `linux/amd64` image to ACR, runs offline gates inside the image, and updates receiver and worker to the same immutable digest. Waits for healthy running revisions and checks receiver `/readyz` over HTTPS. Manual `deploy=false` publishes a bootstrap image without updating apps. |

The deployment workflows use the **`dev` GitHub environment** and a shared
non-cancelling concurrency group so infrastructure and application rollouts do
not overlap. GitHub concurrency is not a FIFO queue: a newer pending run can
replace an older pending run. CD updates images only; infrastructure and RBAC
remain owned by Bicep. Infrastructure applies also set both app images, so use
the currently deployed digest for routine infrastructure changes to avoid
rolling back the application.

### GitHub environment and Azure permissions

Create the `dev` environment, restrict deployment branches to `main`, and
configure required reviewers as appropriate. Set these **environment secrets**
(deployment settings, not runtime application secrets):

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID` | Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |
| `AZURE_INFRA_CLIENT_ID` | Client ID of the infrastructure deployment identity |
| `AZURE_APP_CLIENT_ID` | Client ID of the application build/deploy identity |
| `AZURE_RESOURCE_GROUP` | Existing target resource group |

Set these **environment variables**:

| Variable | Value |
|---|---|
| `AZURE_ACR_NAME` | Existing ACR name, matching `acrName` in the Bicep parameters |
| `AZURE_RECEIVER_APP_NAME` | Required only for application deployment: `ca-<namePrefix>-recv` (for the sample prefix: `ca-sredev-recv`) |
| `AZURE_WORKER_APP_NAME` | Required only for application deployment: `ca-<namePrefix>-wrk` (for the sample prefix: `ca-sredev-wrk`) |

Give each deployment identity a GitHub OIDC federated credential with issuer
`https://token.actions.githubusercontent.com`, audience
`api://AzureADTokenExchange`, and subject
`repo:atea/azure-sre-ghcp:environment:dev`. Both jobs request `id-token: write`;
no Azure client secret, publish profile, ACR password or runtime application
secret is stored in GitHub. Keep the deployment identities separate from the
receiver and worker runtime managed identities.

- Infrastructure identity: `Contributor` on the target resource group plus
  `Role Based Access Control Administrator` scoped to that group (or a suitably
  constrained custom role) to create the template's role assignments. Contributor
  alone cannot assign RBAC. Review/limit the role-assignment authority before
  production.
- Application identity: `AcrPush` on the existing registry and
  `Container Apps Contributor` on each of the two apps. Grant these app-scoped
  roles after the first infrastructure deployment. For an ABAC-enabled ACR, use
  the corresponding repository roles instead of `AcrPush`; runtime image-pull
  permissions must also be reviewed for that registry mode.
- The GitHub-hosted runner needs network access to Azure management endpoints,
  ACR and the receiver HTTPS endpoint. Private deployments need an appropriately
  connected runner.

### First deployment

1. Create the resource group, ACR, Key Vault, deployment identities/federation,
   GitHub environment, secrets and `AZURE_ACR_NAME` variable out of band. Grant
   the application deployment identity `AcrPush` on the registry (or the
   corresponding repository roles for an ABAC-enabled registry).
   Populate Key Vault secrets and
   replace the non-secret placeholders in `infra/environments/dev.bicepparam`.
   The workflow overrides its `image` parameter.
2. Run **Application build and deployment** on `main` with `deploy=false`.
   This builds and verifies the image without requiring existing Container Apps,
   app-name variables, or app-scoped deployment permissions. Copy the published
   image digest from its run summary.
3. Run **Infrastructure deployment** with that digest and `apply=false`.
   Review the what-if output, then rerun with `apply=true` after approval.
   The resource group must already exist; the workflow does not create it.
4. Upload reviewed `sources.json` into the new storage account's `sre-config`
   container using an authorized operator identity. Initial app revisions may
   fail until this configuration exists; the infrastructure workflow does not
   claim application readiness.
5. Set `AZURE_RECEIVER_APP_NAME` and `AZURE_WORKER_APP_NAME` to the newly created
   apps, grant the application deployment identity its app-scoped roles, then
   run CD with `deploy=true`. Subsequent matching pushes to `main` deploy
   automatically after CI and any environment approval.

Until the first infrastructure deployment is complete, use manual `deploy=false`
for image publishing. Automatic CD runs still require the apps and deliberately
fail if deployment prerequisites are missing.

The rollout is sequential, not transactional. If the second app or readiness
check fails, the workflow fails but the first app may already run the new image.
Inspect both revisions and deliberately redeploy the last known good digest to
both apps if needed (the infrastructure workflow can apply that digest with the
reviewed parameters). There is no automatic rollback. Successful CI/CD health
checks do not replace the live authentication/investigation gates in
`docs/integration-gates.md`; live gates are never enabled by these workflows.

## Validation done offline

- `az bicep lint --file infra/main.bicep` and `az bicep build --file infra/main.bicep` pass with no warnings (Bicep 0.39.26).
- `az bicep build-params --file infra/environments/dev.bicepparam` passes.
- `docker build --platform linux/amd64` passed on the previous Dockerfile. The Dockerfile is unchanged in the fix round.
- Not run against Azure: `az deployment group validate` (needs login and an existing resource group), or live checks of port 8080 and `/healthz` and `/readyz`. These handlers and the role entrypoint are wired in the application and covered by offline tests; deployed behavior still requires live acceptance.

## Known limitations and tradeoffs

- **Storage public network access is Enabled** by default because there is no VNet or private endpoint yet. Blob public access and shared keys are off, and RBAC is the only auth path. Set `storagePublicNetworkAccess=Disabled` only after private endpoints exist.
- **Key Vault RBAC cannot be scoped to individual secrets.** The worker holds `Key Vault Secrets User` on the whole vault. The receiver holds none.
- **Log Analytics shared key passes through ARM.** The Container Apps environment needs the workspace key (`listKeys`), so it appears in the deployment, not in the repo. Remediate with a managed-identity-based log destination when available.
- **Worker minReplicas=1** keeps durable reconcilers running but costs money while idle. Max replicas (3) is the fan-out budget; raise it deliberately.
- **Retention:** Log Analytics 30 days; Service Bus dead-letters persist until handled (message TTL 14 days).
- **Image base** `python:3.13-slim-bookworm` is not digest-pinned yet. Pin it before production.
- **Live application acceptance is pending:** port 8080 binding, `/healthz` and `/readyz` handlers, `SRE_PORT`, the environment settings and the `python -m azure_sre receiver|worker` entrypoint are implemented. CI covers them offline; CD checks deployed revision health and receiver readiness, not the complete live alert pipeline.
- **KEDA scaler identity** is declared through the `2025-01-01` API. Whether KEDA needs `Azure Service Bus Data Receiver` for the scaler is unverified and must be confirmed in the live gate.
- **Workflow execution requires environment setup.** The workflows are provided,
  but no Azure resources, OIDC federation or GitHub environment are provisioned
  by adding these files.
