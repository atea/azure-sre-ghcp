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
2. Run baseline host diagnostics (`_BASELINE_KINDS`) before the model is invoked.
3. Open an isolated SDK client and session in a private workspace. Tokens come only from the injected host supplier.
4. The model may call one typed tool, `kind` plus a bounded `operation_id`. Scope, app, and time window are fixed by the host. Extra fields are rejected.
5. Every tool call, including baseline and refused calls, counts against the shared budget: 12 calls, 5 minutes overall, 30 s per CLI call, 100 rows per query, 64 KiB of evidence.
6. Model output must be JSON matching `ModelReportDraft`. It is redacted and then validated against the evidence refs.
7. Failures become partial reports with a category: `TIMEOUT`, `SDK_ERROR`, `INVALID_REPORT`, `BUDGET_EXHAUSTED`, `EVIDENCE_MISSING`, or `PERMISSION_DENIED`.

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
