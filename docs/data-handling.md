# Data handling

Status: **offline source only; no live data flow has been approved or tested.** Several
controls below are *expected* and not implemented yet. This page states what is true today,
what is planned, and what remains unverified. It is not legal or compliance advice.

## What data is involved

| Data | Where it comes from | Where it can go |
|---|---|---|
| Azure Monitor alert payload (Common Alert Schema) | Action group webhook | Durable queue; state store |
| Application logs, exceptions, traces, deployment/platform events | Log Analytics (approved KQL templates only) | Redacted, bounded evidence; model context; report |
| Sanitized investigation report and evidence | Worker | Private Blob Storage; GitHub issue |
| Operational state (incident claim, ledger, issue URL, failure category) | Worker | Azure Table Storage |
| Copilot prompts and model responses | Copilot-hosted model via SDK | Copilot service (see disclosures) |
| Publisher and inference credentials | GitHub Apps / inference PAT, Key Vault | Never stored in report, state, logs or model context |

## Current implementation status

| Control | Status |
|---|---|
| Inference credentials (fine-grained PAT or App installation token) loaded or minted host-side; PAT and App keys not passed to the model | Implemented (`security/pat_provider.py`, `security/github_app.py`, `runtime/sdk_policy`) |
| Publisher child process given an empty environment; key passed as file path | Implemented (`runtime/mcp_policy.github_mcp_stdio_parameters`) |
| Session env rejects `GITHUB_*`, `GH_*`, `AZURE_*`, `IDENTITY_*`, `MSI_*` and secret-like names | Implemented (`build_runtime_env`) |
| Model has no GitHub write tools; publisher calls validated by host (repo, create-only, no close) | Implemented in policy; live proof pending (gate L4) |
| Storage: Blob soft delete 14 days; Log Analytics retention 30 days | Bicep scaffold only, not deployed |
| Service Bus message TTL 14 days; dead-letter after 10 deliveries | Bicep scaffold only, not deployed |
| Redaction of logs and alerts before model context | Implemented, offline-tested; real-data approval remains pending |
| Evidence byte/row limits (64 KiB, 100 rows) | Implemented, UTF-8 byte limits and bounded subprocess capture |
| Sanitized logging of failures (no raw exceptions, headers or telemetry) | Categorized failures implemented; live operational audit pending |
| Retention cleanup for Table rows and Blob content | **Expected, not implemented** |

## Logging rules (apply now to any code added)

- Log categorized, sanitized failure codes (for example `copilot_timeout`, `github_5xx`), not raw exception text. Exception messages can contain tokens, URLs with query strings, or log content.
- Never log request headers, JWTs, installation tokens, PATs, PEM contents, connection strings, or raw Azure Monitor payloads.
- Never log Log Analytics rows. Log counts and query identifiers only.
- Do not add debug prints of model prompts or responses.
- Local developer logs and CI output count as logs. Do not run live gates with verbose logging enabled against real data.

## Evidence minimization

- Collect only the fixed KQL and CLI templates approved for the scope. No arbitrary queries.
- Use bounded UTC windows around the alert, and never widen them to "find more" without a reason.
- Keep at most 100 detailed rows per query and 64 KiB of sanitized evidence per investigation. Truncation must be marked in the report.
- Store evidence references and aggregate counts when full rows are not needed.
- Do not include user identifiers, IP addresses, email addresses, request bodies or query-string values unless the owner approves that field class.

## Redaction limitations

Pattern-based redaction is **not** a guarantee:

- It can miss secrets in unfamiliar formats, split across lines, or encoded (base64, URL-encoded).
- It cannot tell whether a business identifier is personal data.
- Stack traces and custom log messages may contain free-text personal data that no pattern catches.
- Redaction runs before model inference and before publication, but the source telemetry in Log Analytics remains unredacted and is governed by its own access controls.
- Hostile log text can attempt prompt injection. Logs are treated as untrusted data, but that treatment does not remove sensitive content.

Therefore: treat everything in a GitHub issue as **potentially visible to everyone with access to that repository**, and keep field approval narrow.

## Copilot disclosure (approval required)

- Investigation context (redacted evidence, alert fields and prompts) is sent to Copilot-hosted models through the Copilot SDK and runtime.
- Before production, the data owner must approve this disclosure in writing, with the field classes listed in the change record.
- Copilot data retention, training and processing terms are governed by GitHub's Copilot policies and the organization's agreements. **Those terms were not verified in this repository.** Confirm them against the current GitHub Copilot documentation and the organization's contract before approval.
- Organization billing and Copilot enablement are prerequisites (gate L1). Do not use a personal Copilot subscription.

## GitHub disclosure (approval required)

- Published reports are created as issues in the approved private repositories. Anyone with repository access can read them, including future members.
- Issue bodies are capped at 24 KiB and must carry the hidden incident marker and no secrets.
- Comments added by people other than the publisher, and any external references or notifications, are outside the app's control and cannot be deleted by it.
- Deleting an issue requires repository admin rights and is not automated. Deleting a comment requires the author or an admin. Treat published content as effectively permanent.
- GitHub may retain deleted issue content in backups for a period that GitHub does not guarantee to the app. Confirm current GitHub retention terms with the organization.

## Retention

| Store | Configured or expected retention | Complexity and limitations |
|---|---|---|
| Service Bus messages | TTL P14D; dead-letter after 10 deliveries | DLQ messages do not expire automatically. Someone must triage and delete them, and their bodies contain alert data. |
| Azure Table Storage (state) | No platform expiry | Rows persist until a cleanup job or manual deletion removes them. Cleanup is **expected, not implemented**. Partial deletes can leave orphaned ledger entries. |
| Azure Blob Storage (sanitized evidence/reports) | Soft delete 14 days | Soft-deleted blobs remain recoverable for 14 days, so deletion is not immediate. Versions and snapshots, if enabled later, extend this further. |
| Log Analytics (source telemetry) | 30 days (workspace setting) | Sanitized copies in Blob or GitHub do not change source retention. Source telemetry is owned by the application team. |
| Application Insights traces of the worker | Workspace retention | Must stay free of raw alert payloads and tokens (see logging rules). |
| GitHub issues and comments | Indefinite | Only manual deletion by an admin removes them. External issue comments are not controlled by this service. |

Practical implications:

- Deletion requests cover all stores. The procedure must list Table rows, Blob versions and soft-deleted blobs, DLQ messages, GitHub issues and comments, and any workspace copies.
- If a retention period is shorter than the GitHub issue lifetime, the published report must be assumed to outlive the internal copy.
- Offboarding must not delete GitHub content without owner approval.

## Approval record (required before production)

Record in the change record, not in this repository:

- Data classes and fields sent to Copilot and to GitHub
- Redaction rules in force and their known limitations (above)
- Retention periods for each store, and who runs cleanup
- Name and role of the approving data owner, and the date
- Accepted residual risk for free-text personal data in logs

## Unverified items

- Copilot and GitHub retention and training terms for this organization.
- Whether Blob soft delete and the 14-day setting meet the organization's standard.
- Redaction coverage on real application telemetry (not tested against live data).
- Live Service Bus DLQ behavior; Table/Blob retention cleanup remains unimplemented.
