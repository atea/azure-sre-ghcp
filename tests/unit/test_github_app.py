from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from copilot.generated.rpc import GitHubTokenAcquireReason
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from azure_sre.security.github_app import AppAuthenticationError, InstallationTokenProvider


@pytest.fixture
def private_key() -> str:
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


async def test_installation_token_is_cached_and_forced_refresh_reloads_key(
    private_key: str,
) -> None:
    requests: list[httpx.Request] = []
    key_loads: list[bool] = []

    async def load_key() -> str:
        key_loads.append(True)
        return private_key

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        scheme, signed = request.headers["Authorization"].split(" ", 1)
        assert scheme == "Bearer"
        claims = jwt.decode(signed, options={"verify_signature": False})
        assert claims["iss"] == "1"
        assert 0 < claims["exp"] - claims["iat"] <= 600
        return httpx.Response(
            201,
            json={
                "token": "ghs_test",
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        provider = InstallationTokenProvider(
            app_id="1", installation_id="2", load_private_key=load_key, client=client
        )
        first = await provider.get_token()
        assert await provider.get_token() is first
        assert "ghs_test" not in repr(first)
        await provider.get_token(force_refresh=True)
        result = await provider.for_sdk(
            {"host": "github.com", "session_id": "s", "reason": GitHubTokenAcquireReason.REFRESH}
        )
        assert result["kind"] == "token"
        assert result["expiresIn"] > 0
        with pytest.raises(AppAuthenticationError, match="unapproved"):
            await provider.for_sdk(
                {
                    "host": "evil.example",
                    "session_id": "s",
                    "reason": GitHubTokenAcquireReason.INITIAL,
                }
            )
    assert len(requests) == len(key_loads) == 3
    assert all(
        str(r.url) == "https://api.github.com/app/installations/2/access_tokens" for r in requests
    )
    assert all(private_key not in r.content.decode() for r in requests)


async def test_token_failure_does_not_surface_github_response(private_key: str) -> None:
    async def load_key() -> str:
        return private_key

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(403, text="sensitive-body"))
    ) as client:
        provider = InstallationTokenProvider(
            app_id="1", installation_id="2", load_private_key=load_key, client=client
        )
        with pytest.raises(AppAuthenticationError, match="HTTP 403") as error:
            await provider.get_token()
        assert "sensitive-body" not in str(error.value)


@pytest.mark.parametrize(
    "body",
    [
        {"token": "ghp_user", "expires_at": "2030-01-01T00:00:00Z"},
        {"token": "ghs_test", "expires_at": "2020-01-01T00:00:00Z"},
        {"token": "ghs_test", "expires_at": "2030-01-01"},
        {},
    ],
)
async def test_invalid_token_response_is_rejected(private_key: str, body: dict[str, str]) -> None:
    async def load_key() -> str:
        return private_key

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(201, json=body))
    ) as client:
        provider = InstallationTokenProvider(
            app_id="1", installation_id="2", load_private_key=load_key, client=client
        )
        with pytest.raises(AppAuthenticationError, match="Invalid installation token"):
            await provider.get_token()
