# Onboarding runbook

Status: **offline source only; no live gate has passed.** Steps marked *expected* are not
implemented yet. Onboarding an application is allowed only after the owner has approved it
and the prerequisites in [integration gates](integration-gates.md) are met in a test
environment first.

## Scope

One Entra tenant, explicitly onboarded applications and repositories. Initial workloads are
Azure Container Apps with workspace-based Application Insights. Multi-tenant use,
Container Apps Jobs, other workload types and remediation are out of scope.

## Prerequisites (external, not created by this repository)

| Item | Owner | Notes |
|---|---|---|
| Entra app registration (webhook audience) with an application role | Tenant admin | Role assignment is manual; Bicep does not create it |
| Azure Monitor action group with secure webhook enabled | Platform team | Points at the receiver; test sink for test alerts |
| Inference credential: a dedicated service account with a Copilot seat and a fine-grained PAT (Copilot Requests permission only), stored in Key Vault (default `pat` mode). `app` mode needs a Copilot Requests GitHub App installation instead | GitHub org admin and platform team | Copilot enablement and billing must be confirmed. Record the PAT expiry and set an alert; see [operations](operations.md#github-inference-token) |
| Publisher GitHub App, installed on **selected** repositories only, Issues read/write | GitHub org admin | Never grant broader permissions |
| Key Vault secret holding the publisher App PEM | Platform team | Reference only; never paste the key into docs or chat |
| Test repository for pilot issues | Repo owner | Used before any production repository |
| Log Analytics workspace GUID and schema profile for the app | App owner | Verified in step 3 below |
| Operator list and data approval | Service owner | See [data handling](data-handling.md) |

## Steps

### 1. Record the application

Capture, without secrets:

- Application name and owner, environment (test or production)
- Tenant ID and subscription ID (identifiers only)
- Container Apps resource names and resource group
- Application Insights component name and its workspace resource ID
- Target GitHub repository (`owner/repo`) and the publisher App installation ID

Store the reviewed mapping using [configuration](configuration.md). Keep owner
approval and live preflight evidence in the approved change record.

### 2. Confirm the scope is correct

```bash
az containerapp show --name <app> --resource-group <rg> --query "{env:properties.managedEnvironmentId, fqdn:properties.configuration.ingress.fqdn}"
az monitor app-insights component show --app <app-insights-name> --resource-group <rg> --query "{workspace:workspaceResourceId, appId:appId}" -o json
```

Confirm only that the component belongs to the expected application and that its workspace ID matches step 1. Do not retrieve connection strings for this check.

### 3. Verify the logging schema

Run bounded, read-only queries against the workspace. Use the schema profile the owner approved:

```bash
az monitor log-analytics query --workspace <workspace-guid> --analytics-query "AppExceptions | where TimeGenerated > ago(1d) | where _ResourceId =~ '<approved-app-insights-arm-id>' | summarize count() by AppRoleName" --timespan P1D
```

Expected outcomes and what they mean:

- Rows returned: schema and role names match the registry.
- Zero rows: not an error by itself, but it does not prove the schema. Check a known test event before continuing.
- Permission denied: fix RBAC; do not add broader roles to the wrong identity.

Do not paste result rows into tickets. Record only the counts and the query identifiers.

### 4. Check RBAC on the scope

- Worker managed identity: Reader and Log Analytics Reader on the approved scope only.
- Confirm no write role exists:

  ```bash
  az role assignment list --assignee <worker-principal-id> --scope <app-scope> -o table
  ```

- Receiver identity: queue send, image pull and read access to the reviewed config
  container only. It must have no monitored-resource or Key Vault access.

### 5. Confirm the publisher installation

- The publisher App installation lists the target repository and nothing else.
- Labels are not required or applied by the publisher. Create them separately only if operators
  want them for manual triage.
- The test repository is used for the first pilot run. Production repositories follow only after acceptance.

### 6. Register the scope (expected)

Add the entry using the implemented registry/startup validation with:

- Compute resource ID → tenant, subscription, Application Insights component, workspace GUID, schema profile, environment, repository, installation ID.
- Multiple targets are accepted only if they all belong to the same application.

Startup validation must reject unknown, duplicate, cross-tenant or mixed-application targets. If validation is missing, do not enable the scope.

### 7. Pilot with a test alert

1. First trigger an action-group test into the internal test sink; verify persisted
   investigation and no GitHub write. To verify publication, deploy a separate pilot
   registry with a production-sink mapping to a designated **test repository** and
   trigger a real pilot alert, not a production application alert.
2. Confirm the receiver returns `202` only after the message is durably queued. A `503` means the broker was unavailable; that is not acceptance.
3. Confirm the issue lands in the test repository only, with the expected headings and hidden incident marker.
4. Repeat the same alert delivery to confirm duplicates do not create a second investigation or issue.
5. Record the issue URL and results in the change record.

Mock or fixture results are not deployment acceptance.

### 8. Enable for production (after acceptance)

- All live gates pass for the environment.
- Data approval and retention are recorded (see [data handling](data-handling.md)).
- Operators are named and know the procedures in [operations](operations.md).
- The production repository is added to the publisher installation, then the registry entry is enabled.

## Offboarding

1. Disable the action group or alert rule that routes to the receiver for this application.
2. Remove the registry entry (expected) and remove the repository from the publisher App installation.
3. Remove RBAC assignments created for the scope.
4. Decide what happens to existing state and sanitized evidence per the retention policy. Do not delete GitHub issues or comments as part of offboarding without owner approval.
5. Record the offboarding date and approver.

## Verification checklist

- [ ] Owner approval recorded
- [ ] Scope maps to one application, one tenant, one workspace
- [ ] Schema verified with bounded read-only queries
- [ ] Worker identity is read-only on the scope
- [ ] Publisher App is installed only on the target repository
- [ ] Test alert produced one issue in the test repository
- [ ] Duplicate delivery did not create a second issue
- [ ] Data approval and retention recorded
