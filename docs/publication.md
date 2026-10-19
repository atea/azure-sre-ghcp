# GitHub publication

Incident issues include host-rendered collected evidence samples even when inference
produces no valid draft. Each sample cites its evidence ID; at most three rows per item
are shown, with bounded text and explicit omission notices. Telemetry remains escaped
and redacted, and the existing UTF-8 issue budget and required Gaps section still apply.
These samples are observations, not an inferred root-cause claim. Provenance includes
categorized diagnostic error messages so linkage/permission gaps remain actionable.

Probe recommendations use the same `publish`/`reconcile` interfaces with a host-owned
`probe_improvement` purpose and a distinct improvement marker. They require positive
health-configuration evidence, are verified by reading the created issue, and never share
the incident's issue number. The fixed title starts with `[suggested improvement]`.
No model controls the repository, marker, purpose, issue template or probe recommendation.

`azure_sre.github.McpPublisher` implements `worker.protocols.Publisher`
(`publish`, `reconcile`, `recover`, `reconcile_recovery`). The publisher is owned by
the application and is **never connected to the model**. It drives the official
`github-mcp-server` **v2.0.2** over stdio, using the `mcp` 2.3 Python client and native
GitHub App authentication.

The worker owns durable intent, retries and backoff. Each publisher call makes at most
**one write**, then verifies it by reading it back.

## Construction

```python
McpPublisher(
    registry=...,              # trusted ApplicationRegistry (repo + installation per app)
    budget=...,                # BudgetPolicy (issue_body_bytes, incident window)
    binary=Path("/abs/github-mcp-server"),
    app_id="123456",           # decimal GitHub App ID
    load_private_key=async_fn, # returns the PEM from Key Vault (fixed secret reference)
    author_login="my-app[bot]",# required: App bot login; reconcile ignores other authors
    operation_timeout_seconds=25, call_timeout_seconds=10, startup_timeout_seconds=10,
    reconcile_page_size=50, reconcile_max_pages=6, comment_max_pages=10,
    reconcile_lookback=timedelta(minutes=5), private_root=None,
)
```

The installation and repository always come from the trusted registry. Requests are
rejected without launching a process, with `ABSENT` and `retryable=False`, when any of
the following is true:

- the sink is not `production` (`test_sink_rejected`);
- the app is unknown;
- the repository or installation does not match the registry;
- `worker.messages.bind_alert` fails, i.e. the tenant, subscription, targets, incident
  key or delivery id do not match (`alert_binding_<reason>`);
- the report's alert, app, incident, severity, sink or evidence incident does not match
  the alert (`report_mismatch`);
- the marker is not the host `issue_marker` / `recovery_marker` (`marker_mismatch`);
- the publication record is not canonical (`publication_mismatch`).

`reconcile` maps rejections to `UNCERTAIN` with `retryable=False` instead, because it
can never prove absence for a request it refuses to inspect.

Before each MCP launch, the host signs a short-lived GitHub App JWT using the App ID
and Key Vault PEM, then calls `GET /repos/{owner}/{repo}/installation` on
`api.github.com`. Discovery is scoped to the trusted repository, not the first
installation of the App. The returned installation must belong to this App, be
unsuspended, and match the registry's `installation_id`. The discovered ID is then
passed to MCP. Discovery performs no issue writes and never falls back to another
installation or user credentials.

Setup errors distinguish `publisher_private_key_invalid`, `repository_installation_not_found`
(App not installed or repository inaccessible), `repository_installation_suspended`,
`repository_installation_mismatch`, `installation_lookup_denied`, and
`installation_lookup_invalid_response`; these require configuration/operator action.
Network errors, rate limits and GitHub server errors give retryable
`installation_lookup_unavailable`. Raw tokens, PEMs and response bodies are not logged.
If an App is reinstalled, review and update the configured installation ID; discovery
does not silently authorize the replacement. Offline tests inject the discovery
boundary; real GitHub authentication remains a live integration gate.

## Process and secret handling

Each operation starts a fresh server process:

1. Create a private directory with mode 0700 (`mkdtemp` under `private_root`).
2. Write the PEM to `app-key.pem` with mode 0600, `O_EXCL` and `O_NOFOLLOW`. Only its
   path is passed, via `--app-private-key-path`.
3. Run the child with an environment that overrides every MCP SDK default:
   - `HOME` and `TMPDIR`/`XDG_*` point inside the private directory, never the user's
     home;
   - `PATH=/usr/bin:/bin`, `SHELL=/bin/false`;
   - no `GITHUB_*` or Azure credentials are inherited.
4. Send child stderr to `/dev/null`, so raw stderr (which may contain token errors) is
   never logged.
5. Inside `startup_timeout_seconds`: `initialize`, require server info
   `github-mcp-server` / `2.0.2`, list tools (paginated), then call
   `check_advertised_tools`. This requires:
   - the exact allowlisted tool set (`PUBLISHER_TOOLS`);
   - the exact `required` sets;
   - the argument types and enum values we use.

   Any drift gives `mcp_schema_mismatch` / `mcp_server_version_mismatch`, which is
   non-retryable, and no tool is called.
6. Every call goes through `validate_call` (allowlist and fixed owner/repo), then a
   required-argument check, then `call_tool`. `CallToolResult.is_error` and
   `TextContent` are parsed as JSON in the shapes captured from v2.0.2:
   `src/azure_sre/github/gms_tools_v2_0_2.json` plus the Go sources.
7. `finally` closes the process and removes the private directory. This also happens on
   cancellation and timeout. Tests snapshot the key while it is live and assert the
   directory is empty afterwards.

## Issue template

The body has a fixed host layout:

- Line 1 is exactly `<!-- azure-sre:incident:<sha256> -->`.
- A NOTE banner always follows: the issue is AI-generated from read-only diagnostics, can
  make mistakes, and its cited evidence should be verified before acting.
- A second banner follows when the report is partial. A conclusive partial report gets an
  IMPORTANT banner, "Likely cause identified; some evidence was unavailable". Otherwise a
  WARNING banner says the findings may be incomplete.
- Then the sections, in order: **Summary**, **AI assessment** (the model's own prose
  opinion, up to six paragraphs, only when present), **Alert** (trusted identity, severity,
  signal, fired time, window, rule, alert id, incident key), **Symptoms**, **Timeline**,
  **Observations**, **Hypotheses** (supported / contradicted / unverified, with evidence
  ids), **Host checks** (deterministic findings with evidence ids), **Gaps**, **Model
  output validation** (only when the host rejected or altered model output), **Collected
  evidence samples**, **Evidence provenance**, **Developer actions** (checkboxes), and a
  footer. Without a model draft, **Host checks** moves up to follow the Summary.
- Optional sections fill the budget in this priority: AI assessment, hypotheses, host
  checks, samples, observations, symptoms, actions, validation notes, timeline, provenance.

All untrusted text is escaped:

- `redact_text` runs, then NFKC normalization.
- Control, format and bidi characters are dropped and newlines are collapsed.
- URL schemes are defanged (`https[:]//`, `www[.]`).
- `@` becomes the full-width `＠`, so no mentions fire.
- `& < >` become HTML entities, and Markdown specials are backslash-escaped.
- Hidden HTML comments, extra markers, false headings, links and images are therefore
  inert.

The final body is redacted again before publication.

**Size budget.** The body is kept within `budget.issue_body_bytes` UTF-8 bytes (24 KiB
hard cap).

- The required skeleton (marker, alert, gaps, summary) is shrunk through tiers.
- Gaps are never dropped: full text, then 120 characters, then per-category counts.
- Optional sections are filled in priority order with an explicit
  `_N more item(s) omitted to fit the <N>-byte size limit._` notice.
- `RenderError` gives `render_failed` (ABSENT, non-retryable).

The title is `[prefix] [SevN] app (env): summary`. The prefix is empty for complete
reports, `[likely cause]` for conclusive partial reports, and `[partial]` otherwise.
Without a model draft, the summary is the first conclusive host finding, then any host
finding, then `investigation incomplete`. The title is at most 256 characters,
redacted, single-line, with angle brackets neutralized.

The recovery comment has marker `azure-sre:recovery:<sha256>` and states that the issue
stays open. The publisher never closes or edits issues.

## Status semantics

| Situation | Status |
|---|---|
| Write sent, read-back verifies number, canonical `/issues/` URL, first-line marker and author | `PUBLISHED` |
| Rejected before any write (validation, setup, key, schema) | `ABSENT` |
| `failed to create …: POST …/repos/o/r/issues[/N/comments]: 401/403/404/410` (not rate limited) | `ABSENT`, non-retryable (`github_auth_denied`, `github_target_not_found`) |
| Write sent, then any other error, timeout, transport loss, cancellation, unparseable or wrong-repo response, or failed read-back | `UNCERTAIN` (never `ABSENT`) |
| Rate limit (`Retry after 1m30s.`) | `UNCERTAIN` `github_rate_limited`, `retry_after_seconds` in [1, 3600], default 60 |
| Reconcile: complete scan (`hasNextPage == false`) with no matching marker | `ABSENT` `not_found` (retryable) |
| Reconcile: page limit reached, unparseable page or read error | `UNCERTAIN` |

gms reformats 422 errors without the `POST` prefix, so they stay `UNCERTAIN`. That is
conservative.

## Reconcile

Reconcile never writes. It calls `list_issues` with `orderBy=CREATED_AT`,
`direction=DESC`, `since = fired_at − 5 min`, both states, and cursors. It reads up to
`reconcile_max_pages × reconcile_page_size` issues.

- **Candidates** are issues whose first body line is the exact marker and whose author
  equals `author_login` (with or without the `[bot]` suffix).
- **Incomplete scan with no candidate:** one `search_issues` (`repo:o/r <incident_key>`)
  is tried. Search lag or a miss never turns into `ABSENT`.
- **Verification:** up to 3 candidates are checked with `issue_read get`. The lowest
  verified number wins, so duplicates resolve deterministically.

`reconcile_recovery` first verifies the issue, then scans `get_comments` in ascending
order (100 per page, up to `comment_max_pages`). The lowest comment id with the marker
and our author wins. A complete scan with no match gives `ABSENT`; an incomplete scan
gives `UNCERTAIN`.

## Verified gms v2.0.2 facts (offline)

- Tools: `issue_write` (`method=create`), `issue_read` (`get`, `get_comments`),
  `list_issues` (GraphQL; returns `issues`, `pageInfo` and `totalCount`),
  `search_issues`, `add_issue_comment`. There are no output schemas.
- Create returns `{"id": "<str>", "url": "<html_url>"}`. A comment returns the same
  shape, with the url ending `#issuecomment-<id>`.
- A garbage PEM makes gms exit at startup. A valid PEM for an unknown App or
  installation logs an installation-token failure and **falls back to unauthenticated**.
  Writes then return 401, which maps to ABSENT `github_auth_denied` (non-retryable).
- `test_publisher_session.py::test_real_server_discovery_matches_fixture` runs the real
  binary with a throwaway key when `GITHUB_MCP_SERVER_PATH` is set.

## Live gate (pending)

Offline publisher coverage is in `tests/unit/test_publisher*.py`. Live gate L4 has
**not** run. It needs:

- the GitHub App ID and bot login (`SRE_PUBLISHER_BOT_LOGIN`);
- an installation on a disposable test repository, registered in the registry;
- the Key Vault PEM secret reference;
- the pinned gms binary.

Until that gate passes, publication is not claimed as working end to end. Labels and
issue updates/closes are deliberately unsupported.
