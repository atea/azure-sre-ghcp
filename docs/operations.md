# Operations runbooks

Status: **offline source only. No deployment or live gate has passed.** Procedures marked
*expected* describe deployment procedures that have not been verified live. Do not run them against
a real environment until the matching gate in [integration gates](integration-gates.md)
is passed and recorded.

## Implementation status at a glance

| Area | Status |
|---|---|
| SDK/runtime policy, deny-by-default permissions, disposal (`azure_sre.runtime.sdk_policy`) | Implemented, offline-tested |
| MCP publisher policy: repository target, allowed tools, create-only/no-close rules (`mcp_policy.validate_call`) | Implemented, offline-tested; host enforcement only |
| GitHub App installation-token provider (`security/github_app.py`) | Implemented; live refresh unverified (gate L2) |
| Bicep scaffold: messaging (DLQ after 10 deliveries, 14-day TTL), storage, monitoring, RBAC, Container Apps | Written, **not deployed** |
| Receiver, registry, worker, state, diagnostics, redaction, investigation, publisher and reconciliation | Implemented and offline-tested; live acceptance pending |

## Command conventions

- Placeholders are written as `<like-this>`. Never paste real tenant, subscription, key or token values into docs, tickets or chat.
- Offline checks that exist today, run from the repository root:

```bash
uv sync
uv run python -m copilot download-runtime
scripts/fetch_github_mcp_server.sh
uv run python -m azure_sre.runtime.smoke offline
GITHUB_MCP_SERVER_PATH=$PWD/.work/gms/github-mcp-server uv run pytest -q
uv run ruff check . && uv run mypy
```

- Live gates are opt-in and must only target a dedicated test org, test repository and non-production subscription (see the gates document). Do not set `SRE_LIVE_GATES=1` against production.
- Azure commands below are read-only unless marked otherwise. Confirm flags with `az <group> <command> --help` for the installed CLI version before use.
- There is no CI pipeline yet. The folder is not a Git repository, so no GitHub Actions workflow runs these checks.

## 1. Approved resource registry and schema preflight (expected)

The registry maps compute resource IDs to tenant, subscription, Application Insights component, Log Analytics workspace GUID, environment, repository and GitHub installation. It is trusted configuration, not model output. See [configuration](configuration.md) for the implemented schema. The MVP uses fixed workspace-based diagnostic templates; actual columns still need live verification.

Before adding a scope:

1. Confirm an owner has approved the application, repository and data classes for the scope.
2. Resolve the workspace GUID and confirm it is the workspace the application logs to (read-only):

   ```bash
   az monitor app-insights component show --app <app-insights-name> --resource-group <rg> --query "{workspace:workspaceResourceId, appId:appId}"
   az monitor log-analytics workspace show --resource-group <rg> --workspace-name <workspace-name> --query customerId -o tsv
   ```

3. Verify the logging schema the approved queries expect (for example, that the exception and trace tables exist and have the expected columns). Use a bounded read-only query, for example:

   ```bash
   az monitor log-analytics query --workspace <workspace-guid> --analytics-query "AppExceptions | where _ResourceId =~ '<approved-app-insights-arm-id>' | take 5 | project TimeGenerated, ExceptionType, AppRoleName" --timespan PT1H
   ```

   Do not paste returned rows into tickets; they may contain personal data.
4. Check that the managed identities that will read the scope have only Reader and Log Analytics Reader on it. KQL filtering is not authorization; scope access with RBAC.
5. Reject the entry if a compute ID maps to more than one application, more than one tenant, or an unknown component. Multiple targets are allowed only if all belong to the same application.

Startup validation rejects mismatches. Treat registry entries as unverified for deployment until the live schema and scope checks pass.

Action-group test identities are mapped to the internal `test` sink. Those events
produce persisted investigations but **no GitHub issues**. For live publication
acceptance, use a separate pilot registry whose production-sink mapping targets
only a designated test repository. Do not repoint a production application mapping
for the pilot.

## 2. Identity boundaries

Four identities must stay separate. Verify each during onboarding and after every change.

| Boundary | Identity | Allowed scope | Must not |
|---|---|---|---|
| Inbound webhook | Entra app registration; app role for the Azure Monitor caller | Receiver validation only | Grant Azure or GitHub access |
| Azure access | Separate receiver and worker user-assigned managed identities | Reader and Log Analytics Reader on approved diagnostic scopes; queue send/config read (receiver), queue receive/state/evidence/named host credentials (worker) | Mutate monitored resources; expose host credentials to model |
| Inference | Copilot Requests GitHub App installation token (`ghs_`) | Copilot model access in the organization | Be a user token or PAT; fall back to stored user login |
| Publication | Publisher GitHub App, selected private repositories, Issues read/write only | Issue create/read/search and comments on approved repos | Access other repos, close issues, or be visible to the model |

Verification checklist (per environment):

- `az login --identity --client-id <uami-client-id>` followed by `az account show` succeeds only inside the worker container, not on operator workstations.
- Confirm the worker identity cannot write to monitored resources. Expected result: an attempted write is denied. Run this only in the test environment, and only against a throwaway test resource that the identity should not be able to change.
- Review actual role assignments: `az role assignment list --assignee <principal-id> --all -o table`.
- Confirm the publisher App installation lists only the approved repositories in GitHub settings.

## 3. Token rotation

### GitHub inference token (Copilot Requests App)

- Installation tokens are short-lived. The provider in `security/github_app.py` mints them from the App key and caches them. Live refresh past expiry is **gate L2 and unverified**.
- Rotation procedure: rotate the App private key in GitHub, store the new PEM in Key Vault under a new version, update the Key Vault reference, restart the worker revision, then confirm a fresh token is minted in logs (sanitized, no token values).
- If refresh fails in a live session, the expected behavior is a bounded failure and a visible partial or retryable outcome, not a stored-user fallback. Do not work around this by adding a PAT.

### Publisher App key

1. Generate a new private key in the publisher GitHub App settings. Do not download it to a shared location.
2. Add it as a new Key Vault secret version. Confirm the worker's Key Vault reference points at the intended version.
3. Restart the worker revision. The publisher writes PEM to a private temporary file and removes it after process disposal; verify this behavior in the deployed image.
4. Revoke the old key in GitHub only after a successful test publication to the test repository.

### Azure and Service Bus

- Managed identities need no secret rotation. Review role assignments on each change instead.
- Service Bus uses managed identity; if a connection string is ever introduced, treat it as a secret requiring rotation and remove it from configuration.

## 4. Emergency ingestion disable and queue pause

Use this when alerts are being misrouted, the worker is publishing wrongly, or a credential may be exposed. The steps below are **expected procedures against the planned infrastructure**. Confirm each flag with `--help` against the deployed template first.

1. **Stop new acceptance.** Remove the receiver's public ingress, or scale the receiver so it stops accepting traffic. The Azure Monitor action group can also be disabled for the affected alert rule. Disabling the action group is preferred during a suspected webhook compromise (verify the flag with `az monitor action-group update --help`):

   ```bash
   az monitor action-group update --name <action-group> --resource-group <rg> --enabled false
   ```

2. **Pause processing.** Stop the worker from receiving while keeping messages durable:

   ```bash
   az servicebus queue update --resource-group <rg> --namespace-name <sb-namespace> --name <queue> --status ReceiveDisabled
   ```

   Messages already queued remain in the queue until the pause is lifted.
3. **Check state without changing it:**

   ```bash
   az servicebus queue show --resource-group <rg> --namespace-name <sb-namespace> --name <queue> --query "countDetails"
   az containerapp revision list --name <worker-app> --resource-group <rg> -o table
   ```

4. **Stop publication if needed.** Scale the worker to zero replicas after its in-flight work is recorded. Verify the exact scaling flags for the installed CLI version before running.
5. Record the time, reason, and who approved the pause in the incident note. Do not include alert payloads or log excerpts.

Resuming: restore the action group, set the queue status back to `Active`, and confirm the worker drains the backlog without creating duplicate issues (see section 6).

The worker durably records intent before publication. A pause does not cancel a write already in flight; reconcile its outcome before resuming.

## 5. Retry and dead-letter (DLQ) triage

Current infrastructure (scaffold): messages expire after 14 days (`P14D`), `maxDeliveryCount` is 10, and expired messages dead-letter. Lock duration is 1 minute, so the worker must renew locks (expected).

Triage steps (read-only first):

```bash
az servicebus queue show --resource-group <rg> --namespace-name <sb-namespace> --name <queue> --query "countDetails.deadLetterMessageCount"
```

For each dead-lettered message, use the sanitized reason code the worker writes to durable state (expected). Do not open raw Service Bus bodies unless approved, because they contain normalized alert fields.

Classify before acting:

| Reason | Action |
|---|---|
| Invalid or unknown scope | Fix the registry only after owner approval; do not replay blindly |
| Transient failure exhausted (Copilot rate limit, GitHub 5xx, CLI timeout) | Replay after the dependency is healthy |
| Publication uncertain | Go to section 6 first. Never replay directly |
| Poison/schema failure | Keep in DLQ, open a defect, do not replay |

Replay rules:

- Replay only after checking durable state for the incident key. A completed or published incident must not be investigated again.
- Confirm the target repository still matches the registry before replay.
- Record each replayed message ID and the outcome. Do not delete DLQ messages until the outcome is recorded.

Replay tooling is **not implemented**. Do not invent a replay script; add a reviewed tool first.

## 6. Publication uncertainty and reconciliation

A timeout or lost response after an issue write does not mean the write failed. The GitHub API may have created the issue.

Rules:

- **Never retry a create blindly.** Doing so can produce duplicate issues.
- Before any action, check the durable publication ledger for the incident key. Expected status: `publication-uncertain`.
- Reconcile with bounded, read-only lookups in the target repository:
  - Search for the hidden incident marker (the marker is embedded in the issue body) using the publisher's search tool, allowing for index delay (search can lag by minutes).
  - Read recent issues and compare titles and markers.
- Outcome paths:
  - Marker found: record the issue number and URL in the ledger. Mark as published. Do not create another issue.
  - Not found after the indexing window: keep `publication-uncertain` and escalate to an operator. Do not guess.
  - Multiple matches: stop. Keep the earliest issue as canonical, record the others, and open a defect. Do not close issues automatically.
- Recovery comments (for early Resolved) use their own marker. Check that marker before posting another comment.
- Closing issues is out of scope. Operators close issues manually in GitHub if a report is wrong.

## 7. Early Resolved handling (expected)

If Azure Monitor sends Resolved before the investigation finishes:

- Keep the investigation, using the historical Fired window for evidence.
- Record the recovery durably. Post at most one recovery comment, deduplicated by marker.
- The issue stays open. Automatic closure is forbidden.

Verify with a real test alert (see acceptance scenario "Early Resolved") before relying on it.

## 8. Investigation failure and partial reports

- Missing logs, denied diagnostics, SDK timeouts, invalid model output and rate limits must produce a visible partial report or a categorized failure. They must never be presented as a healthy or diagnosed result.
- Zero rows is not the same as healthy. Check the gap list in the report before treating the alert as explained.

## 9. Pre-production sign-off checklist

- All live gates L1–L6 in the gates document have passed in the designated test environment, with evidence recorded.
- Retention, data approval and operator list are approved (see [data handling](data-handling.md)).
- Maximum replica count and budgets are set for the environment (investigation 5 min, 12 diagnostic calls, 2 concurrent per replica, 64 KiB evidence, 24 KiB issue body).
- The pilot has produced a real issue in the designated test repository from a real Monitor alert, with duplicate and restart behavior confirmed.
- The repository is connected to its intended GitHub remote before any CI/CD or environment approval is configured.
