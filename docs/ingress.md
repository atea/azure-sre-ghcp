# Secure webhook ingress

The ingress is the only public entry point. It accepts Azure Monitor secure-webhook alerts, authenticates the calling Entra workload, normalizes the payload against the reviewed registry, and durably enqueues one message to Service Bus. It does not call GitHub, does not run investigations, and does not persist state.

Module: `azure_sre.ingress` (`src/azure_sre/ingress/`).

## Endpoints

| Method | Path | Behaviour |
| --- | --- | --- |
| POST | `/alerts` | Verify bearer token, cap body, normalize, enqueue, then `202`. |
| GET | `/healthz` | Liveness only. Always `200`. Never touches the broker or key set. |
| GET | `/readyz` | `200` only when the sender is open and the JWKS cache has loaded keys. Otherwise `503`. |

Docs, OpenAPI, and redoc are disabled. The integration listens on port 8080.

### `POST /alerts` status codes

| Status | Meaning |
| --- | --- |
| 202 | Message durably accepted by Service Bus. Body `{"status": "accepted"}`. |
| 400 | Body failed JSON parsing or the contract (`normalize_alert`). Body `{"error": "invalid_payload"}`. |
| 401 | Missing, malformed, unsigned, expired, not-yet-valid, wrong issuer, wrong audience, wrong tenant, unknown `kid`, or unsupported algorithm. |
| 403 | Token verified but the caller is not authorized: foreign application, unknown object id, or missing role. |
| 413 | Body larger than `MAX_ALERT_PAYLOAD_BYTES` (256 KiB), declared or streamed. Rejected before the full body is read. |
| 503 | JWKS unavailable, sender not configured, or Service Bus send failed. Body is generic. No broker detail is returned. |

Responses never echo the token, claims, payload, or broker errors. Logs carry only a category code.

## Authentication

Verification order in `EntraTokenVerifier.verify`:

1. Header `alg` must be RS256. `kid` is required.
2. Unverified `tid` must equal the configured tenant. This selects the issuer; it does not grant trust.
3. Issuer is tenant-specific and chosen by `ver`:
   - `2.0`: `https://login.microsoftonline.com/{tid}/v2.0`
   - `1.0`: `https://sts.windows.net/{tid}/`
   - anything else is rejected.
4. Signing key comes from the fixed URL `https://login.microsoftonline.com/{tid}/discovery/v2.0/keys`. The URL is never taken from the token. JWKS policy:
   - Keys are refetched once `jwks_refresh_seconds` (default 3600) have passed since the last successful load.
   - A failed refresh while keys are still within `jwks_max_age_seconds` (default 86400) keeps serving the cached keys and logs a warning with `category=...`.
   - Keys older than `jwks_max_age_seconds` are never used. The request fails with `jwks_stale` or `jwks_unavailable` (503).
   - An unknown `kid` triggers a refetch at most once per `jwks_min_refresh_seconds` (default 300). Repeated unknown kids are rejected as `unknown_kid` without fetching.
5. Signature, `exp`, `nbf`, `iss`, `aud` (required, must equal `audience`), with a configured clock leeway.
6. Authorization:
   - `tid` equals the tenant;
   - `appid` or `azp` (at least one present) equals `expected_caller_app_id`;
   - `oid` maps to a configured webhook caller via `AppConfig.webhook_callers`;
   - `roles` contains `expected_role`.

The sink is `sink_for_caller(oid)`. It is never read from the request body or any payload field.

Azure Monitor's exact token shape (`appid` vs `azp`, `ver`, `roles`) is unverified until the live gate runs. The offline tests use locally generated tokens.

## Body handling and normalization

- The body is read with a streaming cap. Declared `Content-Length` over the cap is rejected immediately. Streamed bytes stop being read once they exceed the cap.
- `normalize_alert(body, config.registry, sink=caller.sink)` validates the Monitor common alert schema, resolves targets against the registry, and produces a `NormalizedAlert`. Any `ContractError` maps to `400`.
- Custom properties, URLs, and queries from the payload are ignored by the contract.

## Durable enqueue

- `ServiceBusAlertSender.send` sends the normalized alert as JSON with `message_id = alert.delivery_id`. The id is deterministic, so redeliveries of the same lifecycle notification share one id.
- The `202` is returned only after the broker accepts the send. A failed send returns `503` and nothing is acknowledged to the caller.
- Each send runs under `send_timeout_seconds` (default 1.5, must be in `(0, 2]`) via `asyncio.timeout`. A timeout returns `503` with `broker_timeout`.
- A timeout is ambiguous: the broker may have accepted the message. The caller gets `503` and redelivers, and the same deterministic id lets duplicate detection drop the copy. This only holds if the queue has duplicate detection enabled. That is a deployment property, not verified offline.
- Broker errors return `503` with `broker_unavailable`. Failed opens return `503` with `broker_open_failed`. Logs record only the category, never the raw SDK message.
- Link state: `open()` enters the SDK client and sender async contexts, which open the AMQP link. `ready()` is true only after that succeeds. Any send failure clears it, and the next send reopens the link.
- Credential: `ManagedIdentityCredential` only, bound to an explicit `client_id` (a GUID, required unless a credential is injected). No `DefaultAzureCredential`, no user credentials, and no implicit system-assigned identity.

## Sink rules (contract for the worker)

- The ingress puts `sink` on the message. The value comes only from the authenticated caller mapping.
- `Sink.TEST` is a flag, not a separate target. **The worker must never call `publisher.publish` for a `TEST` alert.** It persists the tested event and records an outcome without creating a GitHub issue. This applies until a separate, explicit test-repository configuration exists.
- Worker tests must assert that no publisher is invoked for `TEST`.
- The ingress itself enqueues `TEST` alerts like any other. It does not decide the outcome.

## Configuration

`AppConfig` (`config.py`) supplies `registry` and `webhook_callers`. The ingress also needs `IngressSettings`:

| Field | Source |
| --- | --- |
| `tenant_id` | Deployment config (must match the registry tenant). |
| `audience` | Deployment config (the API app id URI). |
| `expected_caller_app_id` | Deployment config (the Monitor caller app). |
| `expected_role` | Deployment config (the app role assigned to the caller). |
| `jwks_refresh_seconds`, `jwks_min_refresh_seconds`, `jwks_max_age_seconds`, `clock_leeway_seconds` | Optional tuning. |

`AppConfig` does not yet carry tenant, audience, caller app id, or role. The entrypoint must build `IngressSettings` from its own deployment settings. This is a gap for the config owner.

## Construction

```python
from azure_sre.ingress import IngressSettings, ServiceBusAlertSender, create_app

app = create_app(
    config,
    ServiceBusAlertSender(namespace, queue_name),   # or any AlertSender
    settings=IngressSettings(tenant_id=..., audience=..., expected_caller_app_id=..., expected_role=...),
)
```

- With neither `settings` nor `verifier`, the app fails closed: `/alerts` returns `503` and `/readyz` reports not ready.
- `settings.tenant_id` must equal `config.registry.tenant_id`. A mismatch raises `ValueError` at construction, both in `create_app` and in `EntraTokenVerifier`.
- `ServiceBusAlertSender(namespace, queue_name, *, client_id=None, credential=None, send_timeout_seconds=1.5)`. Without an injected `credential`, `client_id` is required.
- `/healthz` is liveness only. It never touches the broker or JWKS. `/readyz` is true only when the sender link is open and the JWKS cache holds keys within max age.
- `create_app(..., verifier=...)` accepts any `TokenVerifier` for tests.
- The lifespan opens the sender and performs an initial JWKS load. Failures are logged and tolerated, and readiness stays `503` until both succeed. The sender is closed on shutdown.

## Protocols

- `AlertSender`: `open()`, `send(NormalizedAlert) -> AcceptedMessage`, `ready() -> bool`, `close()`.
- `TokenVerifier`: `verify(token) -> CallerIdentity`, `ready() -> bool`.
- `AcceptedMessage`: `message_id`, `sink`, `incident_key`, `alert_id`.
- `CallerIdentity`: `object_id`, `application_id`, `tenant_id`, `roles`, `sink`.
- Errors: `IngressError` (base, has `.code`), `AuthenticationError`, `AuthorizationError`, `JwksUnavailableError` (`jwks_unavailable`, `jwks_stale`, `jwks_http_error`), `PayloadError`, `SendError` (`broker_open_failed`, `broker_timeout`, `broker_unavailable`).

## Dependencies

- Runtime: FastAPI, PyJWT (with `cryptography`), httpx, `azure-servicebus` and `azure-identity` (aio).
- Azure: Service Bus namespace with queue, managed identity with Azure Service Bus Data Sender on that queue, Microsoft Entra app registration with the expected role.

## Tests

`tests/unit/test_ingress.py` runs fully offline. Tokens are signed with generated RSA keys and verified against a mocked tenant JWKS. Coverage: valid and azp and v1 tokens, TEST caller sink, payload sink ignored, invalid claims, unknown kid, foreign signature, HS256 and none, missing bearer, body caps (declared and streamed), contract errors, deterministic duplicate id, send failure 503, readiness and liveness, fail-closed config, lifespan.

`tests/unit/test_ingress_faults.py` covers the review fixes: JWKS refresh at `jwks_refresh_seconds`, cached keys served on transient failure with a categorized warning, max-age cutoff, unknown-kid throttle, the tenant mismatch `ValueError`, `client_id` required and bound, timeout bound under 2s, not-ready before open, open failure, send timeout 503 with readiness cleared, broker error with reopen on the next send.

Run: `uv run pytest tests/unit/test_ingress.py tests/unit/test_ingress_faults.py`.

## Blockers and open items

- Live gates are not run. The Monitor token shape, the ServiceBus duplicate-detection setting, and whether 1.5s covers a cold AMQP open plus auth are unverified. The startup open mitigates the cold case.
- `AppConfig` lacks tenant, audience, caller app id, and role. The entrypoint must supply `IngressSettings`.
- Registry workspace-GUID uniqueness is stricter in the contracts owner's scope.
- The worker persists `Sink.TEST` investigations with no publisher calls. This is
  an internal test sink, not a test-repository issue-publication path.
