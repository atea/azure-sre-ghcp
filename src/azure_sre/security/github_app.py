"""Host-only installation token minting; private keys never enter model context."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import httpx
import jwt
from copilot import GitHubTokenProviderArgs, GitHubTokenProviderResult
from copilot.generated.rpc import GitHubTokenAcquireReason
from pydantic import BaseModel, ConfigDict, SecretStr

from azure_sre.runtime.sdk_policy import validate_inference_token


class AppAuthenticationError(RuntimeError):
    """Safe authentication failure that does not contain tokens or HTTP bodies."""


class InstallationToken(BaseModel):
    model_config = ConfigDict(frozen=True)
    token: SecretStr
    expires_at: datetime


class InstallationTokenProvider:
    def __init__(
        self,
        *,
        app_id: str,
        installation_id: str,
        load_private_key: Callable[[], Awaitable[str]],
        client: httpx.AsyncClient,
    ) -> None:
        if not app_id.isdecimal() or not installation_id.isdecimal():
            raise ValueError("GitHub App and installation IDs must be decimal identifiers.")
        self.app_id = app_id
        self.installation_id = installation_id
        self.load_private_key = load_private_key
        self.client = client
        self._cached: InstallationToken | None = None
        self._lock = asyncio.Lock()

    async def get_token(self, *, force_refresh: bool = False) -> InstallationToken:
        async with self._lock:
            if (
                not force_refresh
                and self._cached is not None
                and (self._cached.expires_at - datetime.now(UTC)).total_seconds() > 120
            ):
                return self._cached
            self._cached = None
            private_key = await self.load_private_key()
            now = int(time.time())
            signed = jwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": self.app_id},
                private_key,
                algorithm="RS256",
            )
            response = await self.client.post(
                f"https://api.github.com/app/installations/{self.installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {signed}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={},
                timeout=30,
                follow_redirects=False,
            )
            if response.status_code != 201:
                raise AppAuthenticationError(
                    f"Installation token request failed (HTTP {response.status_code})."
                )
            try:
                body = response.json()
                token = validate_inference_token(body["token"], mode="app")
                expires_at = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
                if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
                    raise ValueError("Expired installation token.")
            except (KeyError, TypeError, ValueError) as exc:
                raise AppAuthenticationError("Invalid installation token response.") from exc
            self._cached = InstallationToken(token=SecretStr(token), expires_at=expires_at)
            return self._cached

    async def for_sdk(self, args: GitHubTokenProviderArgs) -> GitHubTokenProviderResult:
        if args["host"] not in {"github.com", "api.github.com"}:
            raise AppAuthenticationError("SDK requested credentials for an unapproved GitHub host.")
        token = await self.get_token(
            force_refresh=args.get("reason") == GitHubTokenAcquireReason.REFRESH
        )
        remaining = int((token.expires_at - datetime.now(UTC)).total_seconds())
        if remaining <= 0:
            raise AppAuthenticationError("Installation token expired before SDK delivery.")
        return {
            "kind": "token",
            "accessToken": token.token.get_secret_value(),
            "expiresIn": remaining,
        }
