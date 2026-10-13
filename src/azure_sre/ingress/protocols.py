"""Ingress seams: protocols the receiver depends on and their shared value types.

Only this module defines the cross-package contract for the receiver. Implementations live in
sibling modules (``jwks``, ``auth``, ``servicebus``, ``app``). Tests inject fakes that satisfy the
same protocols.

Routing rule: ``Sink.TEST`` alerts are durably queued like production alerts, but the worker must
record them as tested events and must never call the GitHub publisher for them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from azure_sre.contracts import NormalizedAlert, Sink


class IngressError(Exception):
    """Base for receiver failures. ``code`` is a stable, log-safe category."""

    code: str = "ingress_error"

    def __init__(self, code: str | None = None) -> None:
        super().__init__(code or self.code)
        if code is not None:
            self.code = code


class AuthenticationError(IngressError):
    """Token is missing, malformed, unsigned by the tenant, or otherwise not trusted (401)."""

    code = "unauthenticated"


class AuthorizationError(IngressError):
    """Token is valid but the caller, application, tenant, or role is not allowed (403)."""

    code = "forbidden"


class JwksUnavailableError(IngressError):
    """Tenant signing keys cannot be loaded or are stale past the allowed age (503)."""

    code = "jwks_unavailable"


class PayloadError(IngressError):
    """Body is too large, not JSON, or fails Common Alert Schema validation (400/413)."""

    code = "invalid_payload"


class SendError(IngressError):
    """Durable acceptance failed. Mapped to 503; the message must not be acknowledged."""

    code = "broker_unavailable"


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    """Authenticated caller after signature, claim, and configuration checks."""

    object_id: str
    application_id: str
    tenant_id: str
    roles: frozenset[str]
    sink: Sink


@dataclass(frozen=True, slots=True)
class AcceptedMessage:
    """What the receiver durably queued. ``message_id`` is the deterministic delivery id."""

    message_id: str
    sink: Sink
    incident_key: str
    alert_id: str


@runtime_checkable
class AlertSender(Protocol):
    """Durably enqueues one normalized alert.

    Contract: returns only after the broker has accepted the message. Implementations must set
    ``message_id`` to ``NormalizedAlert.delivery_id`` so redelivery deduplicates. Any failure raises
    ``SendError`` with no partial acceptance claimed.
    """

    async def open(self) -> None:
        """Acquire the broker client. Called once from the application lifespan."""
        ...

    async def send(self, alert: NormalizedAlert) -> AcceptedMessage: ...

    async def ready(self) -> bool:
        """True only when the sender is initialized and can reach the broker."""
        ...

    async def close(self) -> None: ...


@runtime_checkable
class TokenVerifier(Protocol):
    """Verifies an inbound bearer token and returns authenticated claims.

    Must raise ``AuthenticationError`` for signature, issuer, audience, tenant, expiry, or
    not-before failures and ``AuthorizationError`` for caller, application, or role failures.
    """

    async def verify(self, token: str) -> CallerIdentity: ...

    async def ready(self) -> bool:
        """True only when a tenant key set has been loaded and is not stale beyond its limit."""
        ...
