"""Offline tests for the secure webhook ingress. No network, no Azure credentials.

Tokens are signed with locally generated RSA keys and verified against a mocked tenant JWKS.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from azure_sre import contracts as c
from azure_sre.config import AppConfig
from azure_sre.ingress import (
    AcceptedMessage,
    EntraTokenVerifier,
    IngressError,
    IngressSettings,
    SendError,
    create_app,
)
from azure_sre.ingress.jwks import jwks_url

from .test_contracts import APP, TENANT, mapping, payload

AUDIENCE = "api://azure-sre-ingress"
CALLER_APP = "12345678-1234-1234-1234-123456789abc"
CALLER_OID = "abcdefab-1111-2222-3333-444455556666"
TEST_OID = "abcdefab-1111-2222-3333-777788889999"
ROLE = "Alert.Ingest"
KID = "kid-1"
ISSUER_V2 = f"https://login.microsoftonline.com/{TENANT}/v2.0"
URL = jwks_url(TENANT)


def _rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


SIGNING_KEY = _rsa_key()
FOREIGN_KEY = _rsa_key()


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    jwk: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


def _jwks_body(*keys: dict[str, Any]) -> bytes:
    return json.dumps({"keys": list(keys)}).encode()


def _registry_config(*, extra_callers: list[dict[str, Any]] | None = None) -> AppConfig:
    callers = [{"object_id": CALLER_OID, "sink": "production"}]
    callers.append({"object_id": TEST_OID, "sink": "test"})
    callers.extend(extra_callers or [])
    return AppConfig.model_validate(
        {
            "schema_version": 1,
            "deployed_version": "1.0.0",
            "registry": {
                "schema_version": 1,
                "tenant_id": TENANT,
                "applications": [mapping()],
            },
            "webhook_callers": callers,
        }
    )


def _settings(**overrides: Any) -> IngressSettings:
    base: dict[str, Any] = {
        "tenant_id": TENANT,
        "audience": AUDIENCE,
        "expected_caller_app_id": CALLER_APP,
        "expected_role": ROLE,
    }
    base.update(overrides)
    return IngressSettings(**base)


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "aud": AUDIENCE,
        "iss": ISSUER_V2,
        "tid": TENANT,
        "ver": "2.0",
        "appid": CALLER_APP,
        "oid": CALLER_OID,
        "roles": [ROLE],
        "iat": now,
        "nbf": now,
        "exp": now + 600,
    }
    for name, value in overrides.items():
        if value is None:
            base.pop(name, None)
        else:
            base[name] = value
    return base


def _token(
    claims: dict[str, Any] | None = None,
    *,
    key: rsa.RSAPrivateKey = SIGNING_KEY,
    kid: str = KID,
) -> str:
    return jwt.encode(claims or _claims(), key, algorithm="RS256", headers={"kid": kid})


@dataclass
class FakeSender:
    """Records what the receiver would enqueue. Checks trusted fields on every send."""

    fail: bool = False
    sent: list[c.NormalizedAlert] = field(default_factory=list)
    opened: bool = False
    closed: bool = False
    ready_flag: bool = True

    async def open(self) -> None:
        self.opened = True

    async def ready(self) -> bool:
        return self.ready_flag and self.opened

    async def close(self) -> None:
        self.closed = True

    async def send(self, alert: c.NormalizedAlert) -> AcceptedMessage:
        if self.fail:
            raise SendError("broker_unavailable")
        self.sent.append(alert)
        return AcceptedMessage(
            message_id=alert.delivery_id,
            sink=alert.sink,
            incident_key=alert.incident_key,
            alert_id=alert.alert_id,
        )


def _jwks_transport(*keys: dict[str, Any], status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == URL
        return httpx.Response(status, content=_jwks_body(*keys))

    return httpx.MockTransport(handler)


async def _client(
    config: AppConfig,
    sender: FakeSender | None = None,
    *,
    keys: tuple[dict[str, Any], ...] | None = None,
) -> tuple[httpx.AsyncClient, FakeSender, EntraTokenVerifier]:
    sender = sender or FakeSender()
    http = httpx.AsyncClient(transport=_jwks_transport(*(keys or (_jwk(SIGNING_KEY, KID),))))
    verifier = EntraTokenVerifier(config, _settings(), http=http)
    app = create_app(config, sender, verifier=verifier)
    await sender.open()
    await verifier.refresh()
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://ingress")
    return client, sender, verifier


def _body(**overrides: Any) -> bytes:
    return json.dumps(payload(**overrides)).encode()


def _auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}", "content-type": "application/json"}


# --- positive path -----------------------------------------------------------


async def test_valid_token_enqueues_normalized_alert_and_returns_202() -> None:
    client, sender, _ = await _client(_registry_config())
    async with client:
        response = await client.post("/alerts", content=_body(), headers=_auth(_token()))
    assert response.status_code == 202
    assert len(sender.sent) == 1
    alert = sender.sent[0]
    assert alert.sink is c.Sink.PRODUCTION
    assert alert.app_id == "shop"
    assert alert.registry_fingerprint


async def test_duplicate_delivery_yields_same_deterministic_message_id() -> None:
    client, sender, _ = await _client(_registry_config())
    async with client:
        first = await client.post("/alerts", content=_body(), headers=_auth(_token()))
        second = await client.post("/alerts", content=_body(), headers=_auth(_token()))
    assert first.status_code == second.status_code == 202
    assert sender.sent[0].delivery_id == sender.sent[1].delivery_id
    assert sender.sent[0].incident_key == sender.sent[1].incident_key


async def test_test_caller_sink_is_taken_from_authenticated_caller() -> None:
    client, sender, _ = await _client(_registry_config())
    token = _token(_claims(oid=TEST_OID))
    async with client:
        response = await client.post("/alerts", content=_body(), headers=_auth(token))
    assert response.status_code == 202
    assert sender.sent[0].sink is c.Sink.TEST


async def test_sink_in_payload_is_ignored() -> None:
    client, sender, _ = await _client(_registry_config())
    raw = payload(custom={"sink": "test", "Sink": "TEST"})
    async with client:
        response = await client.post(
            "/alerts", content=json.dumps(raw).encode(), headers=_auth(_token())
        )
    assert response.status_code == 202
    assert sender.sent[0].sink is c.Sink.PRODUCTION


async def test_azp_is_accepted_in_place_of_appid() -> None:
    claims = _claims(appid=None, azp=CALLER_APP)
    client, _sender, _ = await _client(_registry_config())
    async with client:
        response = await client.post("/alerts", content=_body(), headers=_auth(_token(claims)))
    assert response.status_code == 202


async def test_v1_token_uses_sts_issuer() -> None:
    issuer = f"https://sts.windows.net/{TENANT}/"
    claims = _claims(ver="1.0", iss=issuer)
    client, _, _ = await _client(_registry_config())
    async with client:
        response = await client.post("/alerts", content=_body(), headers=_auth(_token(claims)))
    assert response.status_code == 202


# --- authentication / authorization denials ----------------------------------


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        (_claims(aud="api://other"), 401),
        (
            _claims(
                iss=f"https://login.microsoftonline.com/{'0' * 8}-0000-0000-0000-000000000000/v2.0"
            ),
            401,
        ),
        (_claims(exp=int(time.time()) - 3600), 401),
        (_claims(nbf=int(time.time()) + 3600), 401),
        (_claims(exp=None), 401),
        (_claims(tid="0" * 8 + "-0000-0000-0000-000000000000"), 401),
        (_claims(ver="3.0"), 401),
        (_claims(appid="ffffffff-ffff-ffff-ffff-ffffffffffff"), 403),
        (_claims(azp="ffffffff-ffff-ffff-ffff-ffffffffffff", appid=None), 403),
        (_claims(appid=None, azp=None), 403),
        (_claims(oid="99999999-9999-9999-9999-999999999999"), 403),
        (_claims(oid=None), 403),
        (_claims(roles=["Other.Role"]), 403),
        (_claims(roles=None), 403),
        (_claims(roles=[1]), 403),
    ],
)
async def test_invalid_claims_are_denied(claims: dict[str, Any], expected: int) -> None:
    client, sender, _ = await _client(_registry_config())
    async with client:
        response = await client.post("/alerts", content=_body(), headers=_auth(_token(claims)))
    assert response.status_code == expected
    assert sender.sent == []


async def test_unknown_kid_is_denied() -> None:
    client, sender, _ = await _client(_registry_config())
    async with client:
        response = await client.post(
            "/alerts", content=_body(), headers=_auth(_token(kid="unknown-kid"))
        )
    assert response.status_code == 401
    assert sender.sent == []


async def test_bad_signature_from_foreign_key_is_denied() -> None:
    client, sender, _ = await _client(_registry_config())
    async with client:
        response = await client.post(
            "/alerts",
            content=_body(),
            headers=_auth(_token(key=FOREIGN_KEY)),
        )
    assert response.status_code == 401
    assert sender.sent == []


async def test_hs256_and_none_algorithms_are_denied() -> None:
    client, sender, _ = await _client(_registry_config())
    hs = jwt.encode(_claims(), "s" * 32, algorithm="HS256", headers={"kid": KID})
    unsigned = jwt.encode(_claims(), key="", algorithm="none", headers={"kid": KID})
    async with client:
        for token in (hs, unsigned):
            response = await client.post("/alerts", content=_body(), headers=_auth(token))
            assert response.status_code == 401
    assert sender.sent == []


async def test_missing_or_malformed_bearer_is_denied_without_reading_body() -> None:
    client, sender, _ = await _client(_registry_config())
    async with client:
        no_auth = await client.post("/alerts", content=_body())
        garbage = await client.post(
            "/alerts", content=_body(), headers={"authorization": "Bearer not-a-jwt"}
        )
    assert no_auth.status_code == 401
    assert garbage.status_code == 401
    assert sender.sent == []


async def test_token_without_kid_is_denied() -> None:
    token = jwt.encode(_claims(), SIGNING_KEY, algorithm="RS256")
    client, _, _ = await _client(_registry_config())
    async with client:
        response = await client.post("/alerts", content=_body(), headers=_auth(token))
    assert response.status_code == 401


# --- body and contract handling ----------------------------------------------


async def test_declared_oversized_body_is_rejected_with_413() -> None:
    client, sender, _ = await _client(_registry_config())
    big = b"{" + b" " * (c.MAX_ALERT_PAYLOAD_BYTES + 1)
    async with client:
        response = await client.post("/alerts", content=big, headers=_auth(_token()))
    assert response.status_code == 413
    assert sender.sent == []


async def test_streamed_oversized_body_is_rejected_without_content_length() -> None:
    client, sender, _ = await _client(_registry_config())
    limit = c.MAX_ALERT_PAYLOAD_BYTES

    async def chunks() -> Any:
        for _ in range(limit // 4096 + 2):
            yield b" " * 4096

    async with client:
        response = await client.post("/alerts", content=chunks(), headers=_auth(_token()))
    assert response.status_code == 413
    assert sender.sent == []


async def test_malformed_json_and_contract_violations_return_400() -> None:
    client, sender, _ = await _client(_registry_config())
    async with client:
        malformed = await client.post("/alerts", content=b"{not json", headers=_auth(_token()))
        violating = await client.post(
            "/alerts",
            content=json.dumps(payload(targets=[])).encode(),
            headers=_auth(_token()),
        )
    assert malformed.status_code == 400
    assert violating.status_code == 400
    assert sender.sent == []


async def test_unknown_scope_is_rejected_by_contract() -> None:
    other = APP.replace("shop-api", "other-api")
    client, sender, _ = await _client(_registry_config())
    async with client:
        response = await client.post(
            "/alerts",
            content=json.dumps(payload(targets=[other])).encode(),
            headers=_auth(_token()),
        )
    assert response.status_code == 400
    assert sender.sent == []


# --- durable send -------------------------------------------------------------


async def test_send_failure_returns_503_and_no_success() -> None:
    client, _sender, _ = await _client(_registry_config(), FakeSender(fail=True))
    async with client:
        response = await client.post("/alerts", content=_body(), headers=_auth(_token()))
    assert response.status_code == 503
    assert response.json() == {"error": "unavailable"}
    assert "broker" not in response.text.lower()


# --- readiness, liveness, configuration ---------------------------------------


async def test_healthz_is_always_ok_and_readyz_requires_sender_and_jwks() -> None:
    client, sender, _verifier = await _client(_registry_config())
    async with client:
        assert (await client.get("/healthz")).status_code == 200
        assert (await client.get("/readyz")).status_code == 200
        sender.ready_flag = False
        assert (await client.get("/healthz")).status_code == 200
        assert (await client.get("/readyz")).status_code == 503


async def test_readyz_fails_when_jwks_never_loaded() -> None:
    config = _registry_config()
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    verifier = EntraTokenVerifier(config, _settings(), http=http)
    sender = FakeSender()
    app = create_app(config, sender, verifier=verifier)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://i")
    async with client:
        await sender.open()
        assert (await client.get("/readyz")).status_code == 503
        response = await client.post("/alerts", content=_body(), headers=_auth(_token()))
    assert response.status_code == 503
    assert sender.sent == []


async def test_unconfigured_app_fails_closed() -> None:
    app = create_app(_registry_config())
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://i")
    async with client:
        assert (await client.get("/readyz")).status_code == 503
        response = await client.post("/alerts", content=_body(), headers=_auth(_token()))
    assert response.status_code == 503


async def test_lifespan_opens_and_closes_sender() -> None:
    config = _registry_config()
    sender = FakeSender()
    app = create_app(config, sender)
    async with app.router.lifespan_context(app):
        assert sender.opened
    assert sender.closed


async def test_jwks_refresh_failure_keeps_fail_closed_state() -> None:
    config = _registry_config()
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"not json"))
    )
    verifier = EntraTokenVerifier(config, _settings(), http=http)
    with pytest.raises(IngressError) as info:
        await verifier.refresh()
    assert info.value.code == "jwks_fetch_failed"


def test_settings_reject_non_guid_and_bad_intervals() -> None:
    with pytest.raises(ValueError):
        _settings(tenant_id="not-a-guid")
    with pytest.raises(ValueError):
        _settings(jwks_min_refresh_seconds=7200, jwks_refresh_seconds=3600)
    with pytest.raises(ValueError):
        _settings(allowed_algorithms=("HS256",))


def test_jwks_url_is_fixed_tenant_endpoint() -> None:
    assert jwks_url(TENANT) == f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"
