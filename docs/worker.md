# Durable worker

The worker consumes normalized alerts from Service Bus. It investigates each incident at most once
(per persisted report) and publishes or reconciles exactly one GitHub issue per incident, plus one
recovery comment. Code: `src/azure_sre/worker/**` (runtime) and `src/azure_sre/state/**` (durable state).

## Entry point

```python
from azure_sre.worker import AzureWorkerEndpoints, WorkerSettings, run_worker

await run_worker(config, endpoints, investigator, publisher,
                 settings=None, handle_signals=True)  # raises WorkerFatalError on fatal stop
```

- `AzureWorkerEndpoints(managed_identity_client_id, service_bus_namespace, queue_name,
  table_endpoint, table_name, blob_endpoint, report_container="sre-evidence")`. The values are
  validated, and connection strings and keys are rejected.
- Credential: only `ManagedIdentityCredential(client_id=...)`. There is no CLI, environment or
  developer fallback.
- `WorkerSettings.from_config(config, **overrides)` binds `concurrency` to
  `budget.concurrency_per_replica` (maximum 2) and `investigation_timeout_seconds` to
  `budget.investigation_seconds + 15`. Overriding either of these raises.

## Injected interfaces (`azure_sre.worker.protocols`)

```python
class Investigator(Protocol):
    async def run(self, alert: NormalizedAlert) -> InvestigationReport: ...
    # Must honour cancellation. May raise InvestigationDeferred(category, reason=, retry_after_seconds=).

class Publisher(Protocol):
    async def publish(self, request: PublishRequest) -> PublishResult: ...
    async def reconcile(self, request: PublishRequest) -> PublishResult: ...       # read-only, by marker
    async def recover(self, request: RecoveryRequest) -> RecoveryResult: ...       # comment once, never close
    async def reconcile_recovery(self, request: RecoveryRequest) -> RecoveryResult: ...
```

`PublicationStatus` has three values:
- `PUBLISHED`: the write is verified, and a `record` or `comment_id` is required.
- `ABSENT`: the write certainly did not happen or was not found. `retryable=False` sends the
  incident to operator.
- `UNCERTAIN`.

Any exception raised by `publish` or `recover` is treated as `UNCERTAIN`. The host chooses the
repository. A `PublishRequest` always carries the **Fired** snapshot, the persisted report, the
`marker` and the `attempt`.

## Message contract

- The queue uses peek-lock with prefetch 0 and `AutoLockRenewer`. A lost lock cancels the handler.
- The body is a single-data AMQP `NormalizedAlert` JSON of at most 64 KiB, and
  **`MessageId` must equal `delivery_id`**.
- At handling time each message is revalidated against the *current trusted registry*:
  - app, tenant and environment
  - subscription, repository, installation and resource IDs
  - targets
  - `incident_key` and `delivery_id`

  Serialized routing fields are never trusted.
- Poison messages are dead-lettered with a safe `PoisonReason` code only. Possible reasons:
  - `invalid_json`
  - `invalid_encoding`
  - `invalid_contract`
  - `missing_message_id`
  - `message_id_mismatch`
  - `unknown_application`
  - `registry_mismatch`
  - `delivery_id_mismatch`
  - `body_too_large`
  - `processing_attempts_exhausted`
- Completing a message means the alert is **durably recorded**, not that it was published.
  - On a lost claim or lock, or a processing error, the message is abandoned after a jittered
    pause.
  - Once `delivery_count >= max_delivery_attempts` (default 8; keep the queue's
    maxDeliveryCount above this), the message is dead-lettered.

## Durable state (Azure Table, ETag CAS)

Each incident has one partition with two rows: `incident` and `recovery` (a separate ledger).
- Every update is a conditional replace or a transaction carrying the previous ETag.
- Nested values are stored as validated JSON strings.
- An ambiguous write is resolved by reading back its `write_id`.

Phases:
- Working phases:
  - `PENDING_FIRED`
  - `QUEUED`
  - `INVESTIGATING`
  - `REPORT_PERSISTED`
  - `PUBLISHING`
  - `PUBLICATION_UNCERTAIN`
  - `RETRYABLE_FAILURE`
- Terminal phases:
  - `PUBLISHED`
  - `PARTIAL_PUBLISHED`
  - `TEST_SINK_SUPPRESSED`
  - `OPERATOR_REQUIRED`

Reports are written to Blob storage at a content-addressed name before the phase advances. Each
report is validated and checked for credential shapes and size before it is written.

## Invariants

1. The Fired and Resolved snapshots are stored separately and never overwritten.
   - An early Resolved creates `PENDING_FIRED`. Nothing is investigated, and no fired time is
     invented, until the Fired arrives.
   - If the Fired has not arrived after `fired_grace_seconds`, the incident moves to
     `OPERATOR_REQUIRED/fired_missing`. A late Fired still re-queues it.
2. All work happens under a conditional lease claim that is renewed every `renew_interval`.
   - If renewal fails or the claim is lost, or the Service Bus lock is lost, the work task is
     cancelled before publication.
   - Results are only committed with the live lease token, so no success is recorded on an
     unowned claim.
3. Once a report is persisted, the incident is never re-investigated. If its blob is
   unavailable, the incident moves to `OPERATOR_REQUIRED/report_unavailable`.
4. A publish intent is persisted (`PUBLISHING`, marker, intent time) **before** `publish()` is
   called.
   - After a crash, timeout, exception or `UNCERTAIN` result, only `reconcile()` is called. There
     is never a blind create.
   - `ABSENT` is accepted only after `not_found_settle_seconds`.
   - If reconciliation exhausts its attempts, the incident moves to
     `OPERATOR_REQUIRED/publication_uncertain`.
5. The recovery comment has its own marker and ledger (`PENDING` → `WRITING` → `COMMENTED`, or
   `UNCERTAIN` → reconcile), so it is written at most once.
6. Investigation attempts are bounded (`max_investigation_attempts`) and retried with jittered
   backoff, honouring `retry_after`.
   - When attempts run out, a host-built partial report is published (`PARTIAL_PUBLISHED`).
   - Invalid or mismatched reports are never published.
7. If the registry changes after enqueue, the incident moves to
   `OPERATOR_REQUIRED/registry_mismatch` (or `recovery_blocked`) rather than being re-routed.
8. `Sink.TEST` alerts keep the production repository mapping, but the worker **never invokes the
   Publisher** for them. They are investigated, their report is persisted, and they end in
   `TEST_SINK_SUPPRESSED` with no GitHub writes.
9. Restarts: a bounded periodic reconciler (`reconcile_interval`, `batch`, `scan`) drives
   incidents that are due — deferred, uncertain or lease-expired — from durable state.
10. Error handling and shutdown:
    - An unexpected handler task error, or `max_consecutive_failures`, stops the host, and `run`
      raises `WorkerFatalError`. Errors are never swallowed.
    - SIGTERM/SIGINT stop intake. In-flight work then has `shutdown_grace_seconds` to finish;
      after that it is cancelled and its messages abandoned.
11. Logs contain only safe codes, short incident hashes and exception type names. They never
    contain raw messages or exception text.

## Operator actions

- `OPERATOR_REQUIRED` rows carry a safe `operator_reason`:
  - `fired_missing`
  - `publication_uncertain`
  - `report_unavailable`
  - `registry_mismatch`
  - a publisher reason
- To resolve one, inspect the GitHub repository for the marker and fix the cause. Then reset the
  row with an ETag-conditional edit. Never delete the `recovery` row.

## Known gaps

- **`aiohttp` is not a declared dependency.** The async Azure SDK clients (Table, Blob,
  Service Bus, Managed Identity) need it at runtime. Add `aiohttp` (or `azure-core[aio]`) to
  `pyproject.toml`. Unit tests inject a no-network transport instead.
- The live Azure path has not been run yet. This is tracked by the `durable-worker` live gate.
