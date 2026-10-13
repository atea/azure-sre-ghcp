"""Ingress trust settings that are not part of ``AppConfig``.

The audience, tenant, expected Monitor caller application, and expected application role are
deployment facts. ``AppConfig`` does not carry them yet, so the receiver takes them here. Every
value is validated on construction and must be supplied by the entrypoint from deployment
configuration. Nothing is read from the JWT to decide where keys or trust come from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _guid(value: str, name: str) -> str:
    key = value.strip().lower()
    if not _GUID_RE.match(key):
        raise ValueError(f"{name} must be a GUID")
    return key


@dataclass(frozen=True, slots=True)
class IngressSettings:
    """Trust anchors for the Monitor secure-webhook caller.

    ``audience`` is the exact ``aud`` the token must carry. ``expected_caller_app_id`` is the
    Entra application (``appid`` or ``azp``) of the Azure Monitor action group caller, and
    ``expected_role`` is the application role that must be present in ``roles``.
    """

    tenant_id: str
    audience: str
    expected_caller_app_id: str
    expected_role: str
    jwks_refresh_seconds: float = 3600.0
    jwks_min_refresh_seconds: float = 300.0
    jwks_max_age_seconds: float = 86400.0
    clock_leeway_seconds: int = 60
    allowed_algorithms: tuple[str, ...] = field(default=("RS256",))

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _guid(self.tenant_id, "tenant_id"))
        object.__setattr__(
            self,
            "expected_caller_app_id",
            _guid(self.expected_caller_app_id, "expected_caller_app_id"),
        )
        if not self.audience.strip():
            raise ValueError("audience must be set")
        if not self.expected_role.strip():
            raise ValueError("expected_role must be set")
        if self.allowed_algorithms != ("RS256",):
            raise ValueError("only RS256 is accepted")
        if not (
            0
            < self.jwks_min_refresh_seconds
            <= self.jwks_refresh_seconds
            <= self.jwks_max_age_seconds
        ):
            raise ValueError("JWKS refresh intervals must satisfy 0 < min <= refresh <= max_age")
