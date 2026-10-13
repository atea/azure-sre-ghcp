"""Tenant-specific Entra signing-key cache.

Keys come only from the fixed discovery URL for the configured tenant. A token can never
choose where keys are fetched from. Unknown ``kid`` values trigger at most one refresh per
minimum interval, which bounds upstream load from forged tokens.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx
import jwt

from azure_sre.ingress.protocols import AuthenticationError, JwksUnavailableError
from azure_sre.ingress.settings import IngressSettings

logger = logging.getLogger(__name__)

_MAX_JWKS_BYTES = 256 * 1024
_FETCH_TIMEOUT_SECONDS = 10.0


def jwks_url(tenant_id: str) -> str:
    """Fixed, tenant-specific JWKS endpoint. The only URL this module ever requests."""
    return f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"


class TenantJwksCache:
    """Async cache of RSA signing keys for one tenant, keyed by ``kid``."""

    def __init__(
        self,
        settings: IngressSettings,
        *,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._url = jwks_url(settings.tenant_id)
        self._http = http
        self._owns_http = http is None
        self._clock = clock
        self._keys: dict[str, jwt.PyJWK] = {}
        self._loaded_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = asyncio.Lock()

    @property
    def url(self) -> str:
        return self._url

    def _age(self) -> float | None:
        return None if self._loaded_at is None else self._clock() - self._loaded_at

    def _fresh(self) -> bool:
        """Keys are usable until ``jwks_max_age_seconds`` after the last successful load."""
        age = self._age()
        return self._keys != {} and age is not None and age <= self._settings.jwks_max_age_seconds

    def _due(self) -> bool:
        """A scheduled refresh is due once keys are ``jwks_refresh_seconds`` old."""
        age = self._age()
        return age is None or age >= self._settings.jwks_refresh_seconds

    def _attempt_allowed(self) -> bool:
        return self._last_attempt is None or (
            self._clock() - self._last_attempt >= self._settings.jwks_min_refresh_seconds
        )

    def ready(self) -> bool:
        """True when keys are loaded and within ``jwks_max_age_seconds`` of the last load."""
        return self._fresh()

    async def refresh(self) -> None:
        """Fetch the tenant key set now. Raises on failure; callers decide whether to keep keys."""
        async with self._lock:
            await self._fetch_locked()

    async def _fetch_locked(self) -> None:
        self._last_attempt = self._clock()
        client = self._http or httpx.AsyncClient(timeout=_FETCH_TIMEOUT_SECONDS)
        try:
            response = await client.get(self._url, timeout=_FETCH_TIMEOUT_SECONDS)
            if response.status_code != 200:
                raise JwksUnavailableError("jwks_http_error")
            if len(response.content) > _MAX_JWKS_BYTES:
                raise JwksUnavailableError("jwks_too_large")
            keys = _parse_rsa_keys(response.json())
        except (httpx.HTTPError, ValueError):
            raise JwksUnavailableError("jwks_fetch_failed") from None
        finally:
            if self._owns_http:
                await client.aclose()
        if not keys:
            raise JwksUnavailableError("jwks_empty")
        self._keys = keys
        self._loaded_at = self._clock()

    async def _refresh(self, reason: str) -> None:
        """Refresh if the minimum interval allows. Cached keys survive a transient failure.

        Raises ``JwksUnavailableError`` only when there is no usable cached key set.
        """
        if not self._attempt_allowed():
            return
        async with self._lock:
            if not self._attempt_allowed():
                return
            try:
                await self._fetch_locked()
            except JwksUnavailableError as exc:
                if self._fresh():
                    logger.warning(
                        "jwks refresh failed category=%s reason=%s; using cached keys",
                        exc.code,
                        reason,
                    )
                    return
                logger.error("jwks unavailable category=%s reason=%s", exc.code, reason)
                raise

    async def key_for(self, kid: str) -> jwt.PyJWK:
        """Return the signing key for ``kid``.

        Scheduled refresh happens at ``jwks_refresh_seconds``. An unknown ``kid`` triggers a
        refresh at most once per ``jwks_min_refresh_seconds``. Keys older than
        ``jwks_max_age_seconds`` are never used.
        """
        if not self._keys or self._due():
            await self._refresh("scheduled" if self._keys else "initial")
        key = self._keys.get(kid)
        if key is None and self._keys:
            await self._refresh("unknown_kid")
            key = self._keys.get(kid)
        if not self._fresh():
            raise JwksUnavailableError("jwks_stale" if self._keys else "jwks_unavailable")
        if key is None:
            raise AuthenticationError("unknown_kid")
        return key


def _parse_rsa_keys(document: Any) -> dict[str, jwt.PyJWK]:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("JWKS document has no keys array")
    keys: dict[str, jwt.PyJWK] = {}
    for entry in document["keys"]:
        if not isinstance(entry, dict) or entry.get("kty") != "RSA":
            continue
        kid = entry.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        try:
            keys[kid] = jwt.PyJWK(entry, algorithm="RS256")
        except (jwt.PyJWKError, ValueError, TypeError):
            continue
    return keys
