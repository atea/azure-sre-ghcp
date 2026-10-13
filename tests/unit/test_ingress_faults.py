"""Fault-path tests for the ingress review fixes: JWKS refresh policy, sender link, timeouts."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, ClassVar

import httpx
import pytest
from azure.core.exceptions import ServiceRequestError

from azure_sre import contracts as c
from azure_sre.ingress import IngressError, SendError
from azure_sre.ingress import servicebus as sb
from azure_sre.ingress.app import create_app
from azure_sre.ingress.auth import EntraTokenVerifier
from azure_sre.ingress.jwks import TenantJwksCache
from azure_sre.ingress.protocols import AuthenticationError, CallerIdentity, JwksUnavailableError
from azure_sre.ingress.servicebus import ServiceBusAlertSender
from tests.unit.test_contracts import TENANT
from tests.unit.test_contracts import payload as contract_payload
from tests.unit.test_ingress import (
    KID,
    SIGNING_KEY,
    URL,
    FakeSender,
    _body,
    _jwk,
    _jwks_body,
    _registry_config,
    _settings,
    _token,
)

CLIENT_ID = "9f8e7d6c-5b4a-4321-8765-0fedcba98765"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class ScriptedTransport:
    """Serves queued responses in order; the last one repeats. Counts fetches."""

    def __init__(self, *responses: httpx.Response | Exception) -> None:
        self._responses = list(responses)
        self.calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert str(request.url) == URL
        self.calls += 1
        item = self._responses[0] if len(self._responses) == 1 else self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(*keys: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, content=_jwks_body(*keys))


def _cache(transport: ScriptedTransport, clock: FakeClock, **overrides: Any) -> TenantJwksCache:
    settings = _settings(
        jwks_refresh_seconds=3600,
        jwks_min_refresh_seconds=300,
        jwks_max_age_seconds=86400,
        **overrides,
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(transport.handler))
    return TenantJwksCache(settings, http=http, clock=clock)


# --- JWKS refresh policy -------------------------------------------------------


async def test_key_is_served_from_cache_until_refresh_interval() -> None:
    clock = FakeClock()
    transport = ScriptedTransport(_ok(_jwk(SIGNING_KEY, KID)))
    cache = _cache(transport, clock)
    await cache.refresh()
    clock.now += 3599
    await cache.key_for(KID)
    assert transport.calls == 1


async def test_refresh_happens_at_refresh_seconds_not_max_age() -> None:
    clock = FakeClock()
    transport = ScriptedTransport(_ok(_jwk(SIGNING_KEY, KID)))
    cache = _cache(transport, clock)
    await cache.refresh()
    clock.now += 3600
    await cache.key_for(KID)
    assert transport.calls == 2


async def test_transient_refresh_failure_keeps_cached_keys_and_logs_category(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = FakeClock()
    transport = ScriptedTransport(_ok(_jwk(SIGNING_KEY, KID)), httpx.Response(503))
    cache = _cache(transport, clock)
    await cache.refresh()
    clock.now += 3600
    with caplog.at_level(logging.WARNING, logger="azure_sre.ingress.jwks"):
        key = await cache.key_for(KID)
    assert key is not None
    assert transport.calls == 2
    assert any("category=jwks_http_error" in r.getMessage() for r in caplog.records)


async def test_cached_keys_are_refused_after_max_age() -> None:
    clock = FakeClock()
    transport = ScriptedTransport(_ok(_jwk(SIGNING_KEY, KID)), httpx.Response(503))
    cache = _cache(transport, clock)
    await cache.refresh()
    clock.now += 86400 + 1
    with pytest.raises(JwksUnavailableError) as info:
        await cache.key_for(KID)
    # A refresh is attempted first; its failure is reported with its own category.
    assert info.value.code == "jwks_http_error"
    assert not cache.ready()


async def test_refresh_is_throttled_for_unknown_kid() -> None:
    clock = FakeClock()
    transport = ScriptedTransport(_ok(_jwk(SIGNING_KEY, KID)))
    cache = _cache(transport, clock)
    await cache.refresh()
    for _ in range(5):
        with pytest.raises(AuthenticationError) as info:
            await cache.key_for("unknown")
        assert info.value.code == "unknown_kid"
    assert transport.calls == 1
    clock.now += 300
    with pytest.raises(AuthenticationError):
        await cache.key_for("unknown")
    assert transport.calls == 2


async def test_initial_key_fetch_failure_is_categorized_unavailable() -> None:
    clock = FakeClock()
    transport = ScriptedTransport(httpx.Response(500))
    cache = _cache(transport, clock)
    with pytest.raises(JwksUnavailableError) as info:
        await cache.key_for(KID)
    assert info.value.code == "jwks_http_error"
    assert not cache.ready()


async def test_ready_tracks_max_age_not_refresh_interval() -> None:
    clock = FakeClock()
    cache = _cache(ScriptedTransport(_ok(_jwk(SIGNING_KEY, KID))), clock)
    await cache.refresh()
    clock.now += 3600 * 5
    assert cache.ready()
    clock.now += 86400
    assert not cache.ready()


# --- verifier tenant and claims with a controllable clock ----------------------


async def test_verifier_uses_injected_clock_for_cached_key() -> None:
    clock = FakeClock()
    transport = ScriptedTransport(_ok(_jwk(SIGNING_KEY, KID)))
    http = httpx.AsyncClient(transport=httpx.MockTransport(transport.handler))
    verifier = EntraTokenVerifier(_registry_config(), _settings(), http=http, clock=clock)
    await verifier.refresh()
    caller = await verifier.verify(_token())
    assert caller.sink.value == "production"
    assert transport.calls == 1


def test_verifier_rejects_tenant_mismatch() -> None:
    other = "11111111-2222-3333-4444-555555555555"
    with pytest.raises(ValueError, match="tenant_id"):
        EntraTokenVerifier(_registry_config(), _settings(tenant_id=other))


def test_app_rejects_tenant_mismatch() -> None:
    other = "11111111-2222-3333-4444-555555555555"
    with pytest.raises(ValueError, match="tenant_id"):
        create_app(_registry_config(), FakeSender(), settings=_settings(tenant_id=other))


# --- sender construction -------------------------------------------------------


def test_sender_requires_client_id_without_injected_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[Any] = []

    class Spy:
        def __init__(self, **kwargs: Any) -> None:
            created.append(kwargs)

    monkeypatch.setattr(sb, "ManagedIdentityCredential", Spy)
    with pytest.raises(ValueError, match="client_id"):
        ServiceBusAlertSender("ns.servicebus.windows.net", "q")
    with pytest.raises(ValueError, match="client_id"):
        ServiceBusAlertSender("ns.servicebus.windows.net", "q", client_id="not-a-guid")
    assert created == []


async def test_sender_binds_explicit_client_id(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[Any] = []

    class Spy:
        def __init__(self, **kwargs: Any) -> None:
            created.append(kwargs)

        async def close(self) -> None:
            return None

    monkeypatch.setattr(sb, "ManagedIdentityCredential", Spy)
    sender = ServiceBusAlertSender("ns.servicebus.windows.net", "q", client_id=CLIENT_ID.upper())
    sender._build_credential()
    assert created == [{"client_id": CLIENT_ID}]


def test_sender_rejects_timeout_above_two_seconds() -> None:
    with pytest.raises(ValueError, match="timeout"):
        ServiceBusAlertSender(
            "ns.servicebus.windows.net", "q", credential=object(), send_timeout_seconds=2.5
        )


# --- sender link lifecycle -----------------------------------------------------


def _normalized() -> c.NormalizedAlert:
    return c.normalize_alert(contract_payload(), _registry_config().registry)


class _Link:
    """Stands in for ServiceBusClient and ServiceBusSender async context managers."""

    fail_enter: bool = False
    send_error: Exception | None = None
    send_delay: float = 0.0
    instances: ClassVar[list[_Link]] = []

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.entered = False
        self.closed = False
        _Link.instances.append(self)

    def get_queue_sender(self, _name: str) -> _Link:
        return self

    async def __aenter__(self) -> _Link:
        if _Link.fail_enter:
            raise ServiceRequestError(message="no route")
        self.entered = True
        return self

    async def close(self) -> None:
        self.closed = True

    async def send_messages(self, _message: Any) -> None:
        if self.send_delay:
            await asyncio.sleep(self.send_delay)
        if _Link.send_error is not None:
            raise _Link.send_error


@pytest.fixture
def link(monkeypatch: pytest.MonkeyPatch) -> type[_Link]:
    _Link.fail_enter = False
    _Link.send_error = None
    _Link.send_delay = 0.0
    _Link.instances = []
    monkeypatch.setattr(sb, "ServiceBusClient", _Link)
    return _Link


def _sender(**kwargs: Any) -> ServiceBusAlertSender:
    return ServiceBusAlertSender(
        "ns.servicebus.windows.net",
        "alerts",
        credential=object(),
        **kwargs,
    )


async def test_not_ready_before_open_and_ready_after_authenticated_link(link: type[_Link]) -> None:
    sender = _sender()
    assert not await sender.ready()
    await sender.open()
    assert await sender.ready()
    assert link.instances[0].entered


async def test_open_failure_maps_to_safe_send_error_and_not_ready(link: type[_Link]) -> None:
    link.fail_enter = True
    sender = _sender()
    with pytest.raises(SendError) as info:
        await sender.open()
    assert info.value.code == "broker_open_failed"
    assert not await sender.ready()
    assert link.instances[0].closed


async def test_send_timeout_maps_to_503_and_clears_ready(link: type[_Link]) -> None:
    sender = _sender(send_timeout_seconds=0.05)
    await sender.open()
    link.send_delay = 5.0
    alert = _normalized()
    with pytest.raises(SendError) as info:
        await sender.send(alert)
    assert info.value.code == "broker_timeout"
    assert not await sender.ready()


async def test_broker_error_clears_ready_and_next_send_reopens(link: type[_Link]) -> None:
    sender = _sender()
    await sender.open()
    link.send_error = ServiceRequestError(message="reset")
    with pytest.raises(SendError) as info:
        await sender.send(_normalized())
    assert info.value.code == "broker_unavailable"
    assert not await sender.ready()

    link.send_error = None
    accepted = await sender.send(_normalized())
    assert accepted.message_id
    assert await sender.ready()


async def test_timeout_in_app_returns_503_without_success(link: type[_Link]) -> None:
    config = _registry_config()
    sender = _sender(send_timeout_seconds=0.05)
    client_app = create_app(config, sender, verifier=_AcceptAll())
    link.send_delay = 5.0
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=client_app), base_url="http://i"
    ) as client:
        async with client_app.router.lifespan_context(client_app):
            response = await client.post(
                "/alerts", content=_body(), headers={"authorization": "Bearer x"}
            )
    assert response.status_code == 503
    assert response.json() == {"error": "unavailable"}


class _AcceptAll:
    async def verify(self, _token: str) -> Any:

        return CallerIdentity(
            object_id="x",
            application_id="y",
            tenant_id=TENANT,
            roles=frozenset(),
            sink=c.Sink.PRODUCTION,
        )

    async def ready(self) -> bool:
        return True

    async def refresh(self) -> None:
        return None


# --- error type sanity ---------------------------------------------------------


def test_send_error_is_an_ingress_error() -> None:
    assert issubclass(SendError, IngressError)
