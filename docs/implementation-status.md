# Implementation status

The approved plan is being implemented in source. **Deployment is gated on live
integration acceptance**, not on local tests alone.

The initial offline gate verified the installed Python SDK/runtime, isolated
custom tools, permission denial, disposal, and official MCP tool discovery.
Azure tenant configuration, GitHub App installations and a designated test
deployment are not available here, so live authentication and issue publication
have not been exercised.

## Execution refinement

The plan's dependencies describe *integrated readiness*. To make progress without
pretending that live gates passed, source implementation is tracked separately
under `implement-*` tasks. Contracts and infrastructure scaffolding can proceed
independently after the offline baseline. Ingress, diagnostics and worker source
depend on contracts; investigation and publisher depend on stable worker
protocols and their own inputs. The original live acceptance tasks remain gated.

This permits offline source work only. It does not authorize Azure deployment,
production webhook acceptance, real inference, or GitHub writes with unverified
identity boundaries. No user-token fallback or broad publisher permissions are
allowed. See [integration gates](integration-gates.md) for external prerequisites.

## Source milestones

- Python dependency lock and offline SDK/MCP integration baseline are verified.
- Inference token suppliers are selected by `SRE_INFERENCE_AUTH_MODE`. The default is
  `pat`, a vault-stored fine-grained PAT. `app` mints an installation token. Both have
  caching, forced refresh and approved-host checks. Live inference with a PAT and live
  token renewal are still unverified.
- Bicep templates compile. Receiver has no Key Vault credentials; worker diagnostic
  Reader grants are explicit per Container App and approved workspace.
- The amd64 image built locally as non-root with preinstalled runtime, MCP and CLI.
  Both role entrypoints are wired. The actual isolated SDK runtime/tool-denial smoke
  executes successfully as the image's non-root user without downloads.
- Storage requires Entra RBAC and denies anonymous/shared-key access. Network access
  remains public until private endpoints and egress are designed; it is not private
  endpoint-isolated.
- Live Container Apps KEDA managed-identity scaling, monitored-resource access and
  all four authentication boundaries remain deployment gates.

Receiver source now authenticates signed tenant-specific Entra tokens, authorizes
caller/role, caps and normalizes Common Alert Schema, and sends durably before
returning `202`. The receiver role is wired via `python -m azure_sre receiver`.
Supply `SRE_WEBHOOK_AUDIENCE`, `SRE_MONITOR_APP_ID`, `SRE_WEBHOOK_ROLE` and explicit
`AZURE_CLIENT_ID`; Bicep maps these reviewed trust settings. JWKS refresh and sender
readiness corrections are complete.

Receiver review corrections are complete. Diagnostics now bounds process output
during capture, signals only its owned process group on timeout/cancellation, and
returns explicit failures for malformed schema/output limits. Evidence fitting
reports omitted evidence rather than silently losing provenance. Pinned image
Azure CLI 2.91.0 exposes `containerapp show`, `containerapp revision list` and
`login --client-id` without incident-time extension installation. Real managed
identity login and telemetry queries remain unverified.

The durable worker source is complete and locally tested: Table ETag claims,
separate Fired/Resolved snapshots, Blob report persistence, queue lock/state lease
renewal, bounded retries and separate recovery-comment intents. Persisted reports
are reused; uncertain writes reconcile without another create. Test-sink events
never invoke the publisher. Async Azure HTTP transport is now declared explicitly.
Worker role wiring binds the actual investigator and publisher adapters.

Bounded Copilot investigator source now implements the pinned SDK backend,
host-owned tool scope, aggregate call/evidence/time budgets, cancellation and
structured report validation with explicit partial outcomes. Host factory wires
the separate inference App token supplier and private Azure CLI environment.
The application-owned MCP publisher verifies issue/comment writes and reconciles
uncertain outcomes using fixed repository, exact marker and configured bot author.
Offline cross-component acceptance passes: Fired/Resolved with deliberately lost
issue/comment responses reconcile to one investigation, one issue and one recovery
comment; early Resolved waits for Fired; internal test sink never publishes; failed
enqueue returns `503`; unknown scope is rejected before queue acceptance.

Final local verification: **553 tests passed, one opt-in live test skipped**.
Lint, formatting, strict package typing, dependency lock and Bicep compilation
pass. The rebuilt non-root image passes actual SDK/tool-policy and MCP discovery
smokes. See [offline acceptance](offline-acceptance.md) for external seams replaced
by fakes; none of these checks substitute for live deployment acceptance.

Worker inference settings depend on `SRE_INFERENCE_AUTH_MODE`. The default `pat` mode
requires `SRE_INFERENCE_PAT_SECRET`. The `app` mode requires `SRE_INFERENCE_APP_ID`
(distinct from `SRE_PUBLISHER_APP_ID`), `SRE_INFERENCE_INSTALLATION_ID` and
`SRE_INFERENCE_KEY_SECRET`. Both modes require `SRE_INFERENCE_VAULT_URL` and an inference
secret separate from the publisher secret. The worker also requires
`SRE_PUBLISHER_BOT_LOGIN`, `SRE_MODEL`, queue/Table/Blob coordinates and explicit
managed identity. Publisher key reference comes from reviewed JSON config.
Misconfigured/missing settings fail startup. No secrets belong in environment
parameters; the host loads named PEM/PAT secrets from Key Vault.

## Remaining production gates

Provide the real tenant/resource identifiers, the inference PAT account (or App) and publisher App installation,
Entra audience/role/caller, approved data fields, private test repository and model
policy/billing. Verify deployed managed-identity CLI refresh, actual telemetry
schema, JWT shape, KEDA scaling/RBAC, latency, App token expiry and real publication
reconciliation. Base image digests, private endpoints/network design, cleanup
retention, DLQ replay tooling and observability alert wiring require production
sign-off. No CI/CD is connected because this is a folder without Git history.
