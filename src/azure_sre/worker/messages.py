"""Decode queue messages and re-bind them to the trusted registry at handling time.

The receiver already normalized the alert, but the queue body is still treated as
untrusted serialized input: identity and routing fields must equal what the
current reviewed registry derives for the same application and targets. Any
disagreement is a poison message (dead-lettered with a safe reason), never a
silent re-route.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Final

from pydantic import ValidationError

from azure_sre.contracts import (
    ApplicationRegistry,
    ContractError,
    NormalizedAlert,
    delivery_id,
    incident_key,
)

__all__ = [
    "POISON_DESCRIPTIONS",
    "PoisonMessage",
    "PoisonReason",
    "bind_alert",
    "decode_message",
]


class PoisonReason(StrEnum):
    BODY_TOO_LARGE = "body_too_large"
    INVALID_ENCODING = "invalid_encoding"
    INVALID_JSON = "invalid_json"
    INVALID_CONTRACT = "invalid_contract"
    MISSING_MESSAGE_ID = "missing_message_id"
    MESSAGE_ID_MISMATCH = "message_id_mismatch"
    UNKNOWN_APPLICATION = "unknown_application"
    REGISTRY_MISMATCH = "registry_mismatch"
    DELIVERY_ID_MISMATCH = "delivery_id_mismatch"
    PROCESSING_ATTEMPTS_EXHAUSTED = "processing_attempts_exhausted"


POISON_DESCRIPTIONS: Final[dict[PoisonReason, str]] = {
    PoisonReason.BODY_TOO_LARGE: "Message body exceeds the worker size limit.",
    PoisonReason.INVALID_ENCODING: "Message body is not UTF-8.",
    PoisonReason.INVALID_JSON: "Message body is not a JSON object.",
    PoisonReason.INVALID_CONTRACT: "Message body is not a valid normalized alert.",
    PoisonReason.MISSING_MESSAGE_ID: "Message has no MessageId.",
    PoisonReason.MESSAGE_ID_MISMATCH: "MessageId does not equal the alert delivery id.",
    PoisonReason.UNKNOWN_APPLICATION: "Alert application is not in the trusted registry.",
    PoisonReason.REGISTRY_MISMATCH: "Alert identity or routing disagrees with the registry.",
    PoisonReason.DELIVERY_ID_MISMATCH: "Alert delivery id is not derived from its lifecycle.",
    PoisonReason.PROCESSING_ATTEMPTS_EXHAUSTED: "Processing failed repeatedly; see state.",
}


class PoisonMessage(Exception):
    def __init__(self, reason: PoisonReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def bind_alert(alert: NormalizedAlert, registry: ApplicationRegistry) -> NormalizedAlert:
    """Return the alert bound to the current registry, or raise ``PoisonMessage``."""
    mapping = registry.get(alert.app_id)
    if mapping is None:
        raise PoisonMessage(PoisonReason.UNKNOWN_APPLICATION)
    expected = {
        "tenant_id": registry.tenant_id,
        "environment": mapping.environment,
        "subscription_id": mapping.subscription_id,
        "repository": mapping.repository,
        "installation_id": mapping.installation_id,
        "container_app_id": mapping.container_app_id,
        "app_insights_component_id": mapping.app_insights_component_id,
        "log_analytics_workspace_id": mapping.log_analytics_workspace_id,
    }
    if any(getattr(alert, name) != value for name, value in expected.items()):
        raise PoisonMessage(PoisonReason.REGISTRY_MISMATCH)
    for target in alert.targets:
        resolved = registry.resolve_target(target.canonical_id)
        if resolved is None or resolved[0].app_id != mapping.app_id or resolved[1] != target.kind:
            raise PoisonMessage(PoisonReason.REGISTRY_MISMATCH)
    if alert.incident_key != incident_key(alert.app_id, alert.alert_id):
        raise PoisonMessage(PoisonReason.REGISTRY_MISMATCH)
    expected_delivery = delivery_id(
        alert.app_id, alert.alert_id, alert.monitor_condition, alert.condition_time
    )
    if alert.delivery_id != expected_delivery:
        raise PoisonMessage(PoisonReason.DELIVERY_ID_MISMATCH)
    fingerprint = registry.fingerprint()
    if alert.registry_fingerprint == fingerprint:
        return alert
    data = alert.model_dump()
    data["registry_fingerprint"] = fingerprint
    return NormalizedAlert.model_validate(data)


def decode_message(
    body: bytes | None,
    message_id: str | None,
    registry: ApplicationRegistry,
    *,
    max_bytes: int,
) -> NormalizedAlert:
    """Parse a queue body (``NormalizedAlert`` JSON, MessageId = delivery id) and bind it."""
    if body is None:
        raise PoisonMessage(PoisonReason.INVALID_ENCODING)
    if len(body) > max_bytes:
        raise PoisonMessage(PoisonReason.BODY_TOO_LARGE)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise PoisonMessage(PoisonReason.INVALID_ENCODING) from None
    try:
        document = json.loads(text)
    except ValueError:
        raise PoisonMessage(PoisonReason.INVALID_JSON) from None
    if not isinstance(document, dict):
        raise PoisonMessage(PoisonReason.INVALID_JSON)
    try:
        alert = NormalizedAlert.model_validate(document)
    except (ValidationError, ContractError):
        raise PoisonMessage(PoisonReason.INVALID_CONTRACT) from None
    if not message_id:
        raise PoisonMessage(PoisonReason.MISSING_MESSAGE_ID)
    bound = bind_alert(alert, registry)
    if message_id != bound.delivery_id:
        raise PoisonMessage(PoisonReason.MESSAGE_ID_MISMATCH)
    return bound
