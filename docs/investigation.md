# Copilot investigation source

`azure_sre.investigation` produces an `InvestigationReport` for one normalized alert. A Copilot model session drafts the report. The host controls every scope, budget, and validation decision.

## Constructors

```python
CopilotInvestigator(
    *,
    registry: ApplicationRegistry,
    collector_factory: Callable[[NormalizedAlert, threading.Event], CollectorLike],
    backend: ModelBackend,
    scratch_root: Path,            # existing directory; per-run TemporaryDirectory(dir=scratch_root), mode 0700
    budget: BudgetPolicy | None = None,
    clock: Callable[[], datetime] | None = None,
)

SdkModelBackend(
    *,
    runtime_path: Path,            # preinstalled Copilot CLI
    extra_env: Mapping[str, str],  # must contain COPILOT_SKIP_CLI_DOWNLOAD
    initial_token_supplier: TokenSupplier,
    refresh_token_supplier: TokenSupplier | None = None,
    model: str | None = None,
)
```

`collector_factory` is called once per run. The parent supplies the CLI diagnostics collector. Each `collect` call is synchronous and standalone, returning `E1`. The investigator renumbers and aggregates evidence.

`run(alert) -> InvestigationReport` raises `AlertRejected` for an unknown app or a stale registry fingerprint. It re-raises `InvestigationDeferred` for rate limits.

## Flow

1. Validate the alert against the registry: app id, all seven resource fields, and the fingerprint.
2. Run baseline host diagnostics (`_BASELINE_KINDS`) before the model is invoked. The prompt
   carries the baseline evidence and its derived `host_findings`, both inside
   `<untrusted_data>`. Its rules tell the model to correlate error rows with configuration
   facts and findings. A DNS failure for a configured dependency is recorded as a supported
   hypothesis when it explains the symptoms, and unrelated gaps (such as App Insights
   linkage) do not downgrade it. The host still decides the final report status.
3. Open an isolated SDK client and session in a private workspace. Tokens come only from the injected host supplier.
4. The model may call one typed tool, `kind` plus a bounded `operation_id`. Scope, app, and time window are fixed by the host. Extra fields are rejected.
5. Every tool call, including baseline and refused calls, counts against the shared budget: 12 calls, 5 minutes overall, 30 s per CLI call, 100 rows per query, 64 KiB of evidence.
6. Model output must be JSON matching `ModelReportDraft`. It is redacted and then validated against the evidence refs.
   `status` is host-owned: it is not in the model's response schema, and any `status` the
   model sends is discarded. The host makes the report `complete` only when there are no
   host or model gaps and the draft has at least one observation, symptom, or hypothesis.
   Otherwise the report is `partial`. Its category is the run's primary failure, else the
   highest-precedence category among host and model gaps, else the first gap's category
   (`EVIDENCE_MISSING` for a draft with no findings). Model gaps therefore
   never cause a supported diagnosis to be rejected.
7. Failures become partial reports with a category: `TIMEOUT`, `SDK_ERROR`, `INVALID_REPORT`, `BUDGET_EXHAUSTED`, `EVIDENCE_MISSING`, or `PERMISSION_DENIED`.
   An `SDK_ERROR` also records a host gap `model session failed during <stage>: <reason>`.
   `stage` is `session_open` or `model_turn`. `reason` is a fixed code:
   `authentication`, `response_schema`, `model_unavailable`, `model_request_rejected`,
   `runtime_unavailable`, or `unclassified`. The code is derived from the exception type and
   message, but the message itself is never stored or logged.
   When the model's reply is rejected, the report records up to 20 `validation_notes`. Each
   note has a fixed `code` (`no_response`, `oversized`, `invalid_json`, `not_object`,
   `schema_violation`, or `evidence_reference`) and a host-written, redacted `detail`
   (a field path plus the validator's message, never raw model text). The worker logs
   `model output rejected: reason=<code> problems=<n> bytes=<n> incident=<prefix>`, and the
   issue renders the notes under **Model output validation**.

   A reply that fails schema or evidence-reference checks is salvaged
   (`investigation/salvage.py`) instead of discarded. The salvaged draft passes the same
   contract and evidence rules:
   - unknown or malformed evidence refs are removed, and texts are cut to their limits;
   - a symptom or observation with no OK evidence becomes an `unverified` hypothesis;
   - a `supported` hypothesis without OK support, or a `contradicted` one without
     contradicting refs, becomes `unverified`, and failed refs are removed from support;
   - chronology entries without a time, text, and OK evidence are dropped, as are items with
     no text; an unknown gap category becomes `evidence_missing`;
   - a missing summary falls back to the leading (preferably supported) finding.
   Each change is recorded as a note: `item_dropped`, `refs_removed`, `downgraded`,
   `truncated`, `summary_replaced`, or `field_ignored`. The worker logs
   `model output salvaged: ...`. Only output with nothing salvageable is rejected as
   `INVALID_REPORT`.

   **AI assessment.** The draft carries an `assessment` field: the model's own opinion in
   prose (up to 3000 characters), with inline evidence ids and speculation labelled as
   such. It needs no structured citations and is not validated against evidence, so the
   issue presents it as AI opinion. It is redacted like all model text and rendered
   escaped, one line per paragraph.

   **Repair turn.** If the first reply was rejected or salvage lost content (`item_dropped`,
   `refs_removed`, `downgraded`, `summary_replaced`), the host sends one follow-up on the
   same session (`stage=repair_turn`). The follow-up lists the host-written notes and the
   OK and failed evidence ids; it never echoes model text. It runs only with at least 15 s
   left and finishes 5 s before the deadline. The corrected reply replaces the original only
   when it loses less content. A failure, timeout, or rate limit during repair keeps the
   original reply and never defers the incident. A `repair_attempted` note records the
   outcome. Repair tool calls share the same budget.
8. The host derives `host_findings` from OK evidence only, with no model involvement
   (`investigation/findings.py`). The codes are:
   - `storage_account_registry_mismatch`: the configured storage account differs from the
     registered `storage_account_id`.
   - `storage_account_dns_failure`: a DNS failure for
     `<configured account>.<blob|table|queue|file|dfs>.core.windows.net`.
   - `dependency_dns_failure`: up to 3 other hosts that failed DNS resolution.
   - `http_5xx_with_dependency_failure`: a revision logged 5xx responses alongside DNS
     failures.
   Values must match strict patterns before they reach finding text. Findings are kept even
   when the model session fails, so a partial report can still name the likely cause.
   `InvestigationReport` rejects findings that cite missing or non-OK evidence.
9. `conclusion` is independent of `status`. A report is `conclusive` when the draft has a
   `supported` hypothesis (whose refs are already validated as OK evidence) or when a
   conclusive finding (`storage_account_dns_failure`, `storage_account_registry_mismatch`)
   exists. A partial report can therefore name a likely cause while still listing
   unrelated gaps. The report validator rejects `conclusive` without such a basis. Stored
   reports without the field load as `inconclusive`.

### SDK contract notes

- The token callback receives the host as an HTTPS origin (`https://github.com`).
  `sdk_policy.is_approved_token_host` accepts only that origin or the bare approved host.
- `expiresIn` must be the token's real remaining lifetime and must exceed 3600 seconds.
  PAT mode reports 8 hours. GitHub App installation tokens live at most one hour, so `app`
  inference mode cannot satisfy this SDK version's preflight check.
- Structured output is strict: `_OUTPUT_SCHEMA` lists every property as required and has no
  `default` keywords. Replies are still validated against `ModelReportDraft`.
- The `smoke live` gate passes the token directly to the client, not through the session
  token provider, so it does not exercise these callback rules.

## Cancellation

Collector calls run in `asyncio.to_thread`. On timeout the host sets a `threading.Event`, then awaits the worker thread so the diagnostics subprocess is terminated before `run` returns. Thread work is never abandoned.

## Security notes

- The alert rule and baseline evidence are wrapped in `<untrusted_data>` with `<`, `>`, and `&` escaped.
- Output is redacted with `redact_value` before validation.
- The SDK environment is built with `build_runtime_env`. Only allowlisted variables are passed. `GH_*`, `GITHUB_*`, `AZURE_*`, and `MSI_*` never leak in.
- The model has no publisher, auth, or MCP tools.
- Cleanup errors from `session.close()` become explicit report gaps.

## Tests

`tests/unit/test_investigation.py` uses fake backend and collector doubles. Run:

```
.venv/bin/python -m pytest tests/unit/test_investigation.py --basetemp=.work/pytest-investigation-<agent>
```

Live SDK and token acceptance tests are gated and not included here.


## Hardening notes

- **Alert validation**: `_validate` calls `worker.messages.bind_alert(alert, registry)`, which checks tenant, delivery id, targets, and fingerprint. A poison result raises `AlertRejected`. A stale fingerprint is rejected rather than silently rebound.
- **Serialized collection**: each run holds an `asyncio.Lock` around charge, collect, and admit. Concurrent SDK tool calls are therefore counted and bounded one at a time. Once the run stops, no new collection starts.
- **Guaranteed drain**: the run's `finally` sets cancellation, then closes the model session. Close errors (including exceptions) become categorized `SDK_ERROR` gaps with no raw text. Worker threads are always awaited afterwards, even if the close is cancelled.
