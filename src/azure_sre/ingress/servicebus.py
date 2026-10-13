"""Durable ServiceBus enqueue for normalized alerts.

Only ``ManagedIdentityCredential`` is used, bound to an explicit user-assigned identity client id.
There is no system-assigned identity, default chain, or interactive credential. The message id is
the deterministic ``delivery_id``, so a redelivered webhook maps to the same broker message and
queue duplicate detection can drop it. ``send`` returns only after the broker accepts the message.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from azure.core.exceptions import AzureError
from azure.identity.aio import ManagedIdentityCredential
from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient, ServiceBusSender

from azure_sre.contracts import NormalizedAlert
from azure_sre.ingress.protocols import AcceptedMessage, SendError

logger = logging.getLogger(__name__)

DEFAULT_SEND_TIMEOUT_SECONDS = 1.5
MAX_SEND_TIMEOUT_SECONDS = 2.0
_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class ServiceBusAlertSender:
    """Implements ``AlertSender`` over an async ServiceBus queue sender.

    ``client_id`` is the user-assigned managed identity client id and is required unless a
    ``credential`` is injected (tests). ``ready()`` is true only after ``open()`` has entered the
    sender's AMQP link context and no send has since failed. A failed or timed-out send clears it;
    the next send attempts to reopen the link before sending.
    """

    def __init__(
        self,
        fully_qualified_namespace: str,
        queue_name: str,
        *,
        client_id: str | None = None,
        credential: Any | None = None,
        send_timeout_seconds: float = DEFAULT_SEND_TIMEOUT_SECONDS,
    ) -> None:
        if not fully_qualified_namespace.endswith(".servicebus.windows.net"):
            raise ValueError("fully_qualified_namespace must be a *.servicebus.windows.net host")
        if not queue_name:
            raise ValueError("queue_name must be set")
        if credential is None:
            if client_id is None or not _GUID_RE.match(client_id.strip().lower()):
                raise ValueError("client_id must be the managed identity GUID")
        if not (0 < send_timeout_seconds <= MAX_SEND_TIMEOUT_SECONDS):
            raise ValueError("send_timeout_seconds must satisfy 0 < timeout <= 2")
        self._namespace = fully_qualified_namespace
        self._queue_name = queue_name
        self._client_id = client_id.strip().lower() if client_id else None
        self._credential = credential
        self._send_timeout = send_timeout_seconds
        self._client: ServiceBusClient | None = None
        self._sender: ServiceBusSender | None = None
        self._linked = False

    def _build_credential(self) -> Any:
        if self._credential is None:
            self._credential = ManagedIdentityCredential(client_id=self._client_id)
        return self._credential

    async def open(self) -> None:
        """Create the client and enter the sender's authenticated AMQP link context.

        Raises ``SendError("broker_open_failed")`` on any Azure failure, after cleaning up.
        """
        if self._linked:
            return
        await self._teardown()
        try:
            credential = self._build_credential()
            client = ServiceBusClient(self._namespace, credential=credential)
            self._client = client
            sender = client.get_queue_sender(self._queue_name)
            self._sender = sender
            await client.__aenter__()
            await sender.__aenter__()
        except AzureError as exc:
            logger.error("servicebus open failed category=%s", type(exc).__name__)
            await self._teardown()
            raise SendError("broker_open_failed") from None
        self._linked = True

    async def ready(self) -> bool:
        return self._linked

    async def send(self, alert: NormalizedAlert) -> AcceptedMessage:
        if not self._linked:
            try:
                await asyncio.wait_for(self.open(), timeout=self._send_timeout)
            except (TimeoutError, SendError):
                raise SendError("broker_unavailable") from None
        if self._sender is None:
            raise SendError("broker_unavailable")
        message = ServiceBusMessage(
            alert.model_dump_json().encode("utf-8"),
            message_id=alert.delivery_id,
            content_type="application/json",
            subject=alert.incident_key,
        )
        try:
            async with asyncio.timeout(self._send_timeout):
                await self._sender.send_messages(message)
        except TimeoutError:
            # Ambiguous: the broker may have accepted the message. The caller gets 503 and a
            # redelivery reuses the same message id, so duplicate detection keeps it single.
            self._linked = False
            logger.error("servicebus send timed out sink=%s", alert.sink.value)
            raise SendError("broker_timeout") from None
        except AzureError as exc:
            self._linked = False
            logger.error(
                "servicebus send failed category=%s sink=%s",
                type(exc).__name__,
                alert.sink.value,
            )
            raise SendError("broker_unavailable") from None
        return AcceptedMessage(
            message_id=alert.delivery_id,
            sink=alert.sink,
            incident_key=alert.incident_key,
            alert_id=alert.alert_id,
        )

    async def _teardown(self) -> None:
        self._linked = False
        if self._sender is not None:
            try:
                await self._sender.close()
            except AzureError:
                logger.debug("servicebus sender close failed during teardown")
        if self._client is not None:
            try:
                await self._client.close()
            except AzureError:
                logger.debug("servicebus client close failed during teardown")
        self._sender = None
        self._client = None

    async def close(self) -> None:
        await self._teardown()
        if self._credential is not None and hasattr(self._credential, "close"):
            await self._credential.close()


__all__ = ["DEFAULT_SEND_TIMEOUT_SECONDS", "ServiceBusAlertSender"]
