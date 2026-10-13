"""Entra bearer-token verification for the Monitor secure-webhook caller.

Order of checks: header and algorithm, tenant-correct issuer, cached signing key, signature, time
and audience claims, then tenant, caller application, caller object id, and role. Anything that
fails returns a stable code; no raw token or claim value is logged.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
import jwt

from azure_sre.config import AppConfig
from azure_sre.ingress.jwks import TenantJwksCache
from azure_sre.ingress.protocols import (
    AuthenticationError,
    AuthorizationError,
    CallerIdentity,
)
from azure_sre.ingress.settings import IngressSettings

_REQUIRED_CLAIMS = ("exp", "nbf", "iss", "aud")


def expected_issuer(tenant_id: str, version: object) -> str:
    """Issuer for a token version, both tenant-specific. Anything else is refused."""
    if version == "2.0":
        return f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    if version == "1.0":
        return f"https://sts.windows.net/{tenant_id}/"
    raise AuthenticationError("unsupported_token_version")


class EntraTokenVerifier:
    """Implements ``TokenVerifier`` against the fixed tenant key set."""

    def __init__(
        self,
        config: AppConfig,
        settings: IngressSettings,
        *,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if settings.tenant_id != config.registry.tenant_id.lower():
            raise ValueError("ingress tenant_id must match registry tenant_id")
        self._config = config
        self._settings = settings
        self._jwks = TenantJwksCache(settings, http=http, clock=clock)

    @property
    def jwks(self) -> TenantJwksCache:
        return self._jwks

    async def refresh(self) -> None:
        await self._jwks.refresh()

    async def ready(self) -> bool:
        return self._jwks.ready()

    async def verify(self, token: str) -> CallerIdentity:
        settings = self._settings
        header = _unverified_header(token)
        if header.get("alg") not in settings.allowed_algorithms:
            raise AuthenticationError("unsupported_algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthenticationError("missing_kid")

        unverified = _unverified_claims(token)
        if unverified.get("tid") != settings.tenant_id:
            raise AuthenticationError("wrong_tenant")
        issuer = expected_issuer(settings.tenant_id, unverified.get("ver"))

        key = await self._jwks.key_for(kid)
        claims = _verified_claims(token, key, issuer, settings)
        return self._authorize(claims)

    def _authorize(self, claims: dict[str, Any]) -> CallerIdentity:
        settings = self._settings
        if claims.get("tid") != settings.tenant_id:
            raise AuthenticationError("wrong_tenant")

        app_claims = [claims[name] for name in ("appid", "azp") if name in claims]
        if not app_claims or any(value != settings.expected_caller_app_id for value in app_claims):
            raise AuthorizationError("foreign_application")

        oid = claims.get("oid")
        if not isinstance(oid, str):
            raise AuthorizationError("missing_object_id")
        sink = self._config.sink_for_caller(oid)
        if sink is None:
            raise AuthorizationError("unknown_caller")

        roles = claims.get("roles", [])
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            raise AuthorizationError("malformed_roles")
        if settings.expected_role not in roles:
            raise AuthorizationError("missing_role")

        return CallerIdentity(
            object_id=oid.strip().lower(),
            application_id=settings.expected_caller_app_id,
            tenant_id=settings.tenant_id,
            roles=frozenset(roles),
            sink=sink,
        )


def _unverified_header(token: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise AuthenticationError("malformed_token") from None
    return header


def _unverified_claims(token: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        raise AuthenticationError("malformed_token") from None
    return claims


def _verified_claims(
    token: str, key: jwt.PyJWK, issuer: str, settings: IngressSettings
) -> dict[str, Any]:
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key=key.key,
            algorithms=list(settings.allowed_algorithms),
            audience=settings.audience,
            issuer=issuer,
            leeway=settings.clock_leeway_seconds,
            options={"require": list(_REQUIRED_CLAIMS)},
        )
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("token_expired") from None
    except jwt.ImmatureSignatureError:
        raise AuthenticationError("token_not_yet_valid") from None
    except jwt.InvalidAudienceError:
        raise AuthenticationError("wrong_audience") from None
    except jwt.InvalidIssuerError:
        raise AuthenticationError("wrong_issuer") from None
    except jwt.InvalidSignatureError:
        raise AuthenticationError("bad_signature") from None
    except jwt.PyJWTError:
        raise AuthenticationError("invalid_token") from None
    return claims
