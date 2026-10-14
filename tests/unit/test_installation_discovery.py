from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from azure_sre.github.mcp_client import (
    McpSetupError,
    discover_repository_installation,
    open_publisher_session,
)
from tests.unit.test_publisher_session import TARGET, session_kwargs
from tests.unit.test_publisher_support import FakeGitHub, entries


@pytest.fixture
def pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


async def test_discovery_signs_app_jwt_and_uses_exact_repository(pem: str) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "https://api.github.com/repos/contoso/shop/installation"
        scheme, token = request.headers["Authorization"].split(" ", 1)
        assert scheme == "Bearer"
        public = serialization.load_pem_private_key(pem.encode(), password=None).public_key()
        claims = jwt.decode(token, public, algorithms=["RS256"])
        assert claims["iss"] == "123456"
        assert 0 < claims["exp"] - claims["iat"] <= 600
        return httpx.Response(200, json={"id": 42, "app_id": 123456, "suspended_at": None})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        assert await discover_repository_installation("123456", pem, TARGET, http=http) == 42


@pytest.mark.parametrize(
    ("status", "headers", "code", "retryable"),
    [
        (401, {}, "installation_lookup_denied", False),
        (403, {}, "installation_lookup_denied", False),
        (403, {"x-ratelimit-remaining": "0"}, "installation_lookup_unavailable", True),
        (403, {"retry-after": "60"}, "installation_lookup_unavailable", True),
        (404, {}, "repository_installation_not_found", False),
        (429, {}, "installation_lookup_unavailable", True),
        (503, {}, "installation_lookup_unavailable", True),
        (302, {"location": "https://example.com/"}, "installation_lookup_denied", False),
    ],
)
async def test_http_failures_are_safe_and_do_not_follow_redirects(
    pem: str, status: int, headers: dict[str, str], code: str, retryable: bool
) -> None:
    calls = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.url.host == "api.github.com"
        return httpx.Response(status, headers=headers, text="sensitive response")

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handle), follow_redirects=True
    ) as http:
        with pytest.raises(McpSetupError) as error:
            await discover_repository_installation("123456", pem, TARGET, http=http)
    assert error.value.code == code and error.value.retryable is retryable
    assert calls == 1
    assert "sensitive" not in str(error.value)


@pytest.mark.parametrize(
    "body",
    [
        [],
        {},
        {"id": True, "app_id": 123456, "suspended_at": None},
        {"id": 0, "app_id": 123456, "suspended_at": None},
        {"id": "42", "app_id": 123456, "suspended_at": None},
        {"id": 42, "app_id": 99, "suspended_at": None},
        {"id": 42, "app_id": "123456", "suspended_at": None},
        {"id": 42, "app_id": 123456},
    ],
)
async def test_invalid_response_rejected(pem: str, body: object) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
    ) as http:
        with pytest.raises(McpSetupError, match="installation_lookup_invalid_response"):
            await discover_repository_installation("123456", pem, TARGET, http=http)


async def test_suspended_installation_rejected(pem: str) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, json={"id": 42, "app_id": 123456, "suspended_at": "2026-10-14"}
            )
        )
    ) as http:
        with pytest.raises(McpSetupError, match="repository_installation_suspended"):
            await discover_repository_installation("123456", pem, TARGET, http=http)


async def test_invalid_key_does_not_make_http_request() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        pytest.fail("Invalid PEM must not send a request")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        with pytest.raises(McpSetupError, match="publisher_private_key_invalid"):
            await discover_repository_installation("123456", "not a key", TARGET, http=http)


async def test_network_failure_is_retryable(pem: str) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sensitive network details", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        with pytest.raises(McpSetupError) as error:
            await discover_repository_installation("123456", pem, TARGET, http=http)
    assert error.value.code == "installation_lookup_unavailable"
    assert error.value.retryable


async def test_non_json_response_rejected(pem: str) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, text="not json"))
    ) as http:
        with pytest.raises(McpSetupError, match="installation_lookup_invalid_response"):
            await discover_repository_installation("123456", pem, TARGET, http=http)


async def test_mismatch_blocks_mcp_startup(tmp_path: Path) -> None:
    gh = FakeGitHub()

    async def resolver(app_id: str, key: str, target: object) -> int:
        return 99

    with pytest.raises(McpSetupError) as error:
        async with open_publisher_session(
            **session_kwargs(gh, tmp_path, installation_resolver=resolver)
        ):
            pytest.fail("Installation mismatch must not open a session")
    assert error.value.code == "repository_installation_mismatch"
    assert not error.value.retryable
    assert gh.sessions == [] and gh.calls == [] and entries(tmp_path) == []
