"""Host-only fine-grained PAT supplier for Copilot inference; the PAT never enters model context."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

from copilot import GitHubTokenProviderArgs, GitHubTokenProviderResult
from copilot.generated.rpc import GitHubTokenAcquireReason
from pydantic import SecretStr

from azure_sre.runtime.sdk_policy import (
    PolicyError,
    is_approved_token_host,
    validate_inference_token,
)

DEFAULT_CACHE_SECONDS = 900


class PatAuthenticationError(RuntimeError):
    """Safe PAT failure that never contains the token value."""


class PatTokenProvider:
    """Serve a vault-stored fine-grained PAT to the SDK ``github_token_provider``.

    The PAT is cached in memory for ``cache_seconds``; a ``REFRESH`` request (or cache
    expiry) re-reads the vault so a rotated PAT is picked up without a restart.
    """

    def __init__(
        self,
        *,
        load_pat: Callable[[], Awaitable[str]],
        cache_seconds: int = DEFAULT_CACHE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if cache_seconds <= 0:
            raise ValueError("cache_seconds must be positive.")
        self._load_pat = load_pat
        self._cache_seconds = cache_seconds
        self._clock = clock
        self._cached: SecretStr | None = None
        self._loaded_at = 0.0
        self._lock = asyncio.Lock()

    async def get_token(self, *, force_refresh: bool = False) -> SecretStr:
        async with self._lock:
            fresh = self._clock() - self._loaded_at < self._cache_seconds
            if not force_refresh and self._cached is not None and fresh:
                return self._cached
            self._cached = None
            try:
                token = validate_inference_token(await self._load_pat(), mode="pat")
            except PolicyError:
                raise PatAuthenticationError("Vault secret is not a fine-grained PAT.") from None
            except PatAuthenticationError:
                raise
            except Exception as exc:  # noqa: BLE001 - never surface secret-bearing errors
                raise PatAuthenticationError(
                    f"Inference PAT could not be loaded ({type(exc).__name__})."
                ) from None
            self._cached = SecretStr(token)
            self._loaded_at = self._clock()
            return self._cached

    async def for_sdk(self, args: GitHubTokenProviderArgs) -> GitHubTokenProviderResult:
        if not is_approved_token_host(args["host"]):
            raise PatAuthenticationError("SDK requested credentials for an unapproved GitHub host.")
        token = await self.get_token(
            force_refresh=args.get("reason") == GitHubTokenAcquireReason.REFRESH
        )
        remaining = max(1, int(self._cache_seconds - (self._clock() - self._loaded_at)))
        return {
            "kind": "token",
            "accessToken": token.get_secret_value(),
            "expiresIn": remaining,
        }
