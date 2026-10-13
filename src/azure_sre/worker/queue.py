"""Peek-lock message source abstraction and the Azure Service Bus implementation."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Final, Protocol

from azure.core.credentials_async import AsyncTokenCredential
from azure.servicebus import ServiceBusReceivedMessage, ServiceBusReceiveMode
from azure.servicebus.aio import AutoLockRenewer, ServiceBusClient, ServiceBusReceiver
from azure.servicebus.amqp import AmqpMessageBodyType

from azure_sre.worker.messages import POISON_DESCRIPTIONS, PoisonReason

__all__ = ["InboundMessage", "MessageSource", "ServiceBusInboundMessage", "ServiceBusMessageSource"]

_log = logging.getLogger("azure_sre.worker")
_MAX_BODY_READ: Final = 256 * 1024


class InboundMessage(Protocol):
    @property
    def message_id(self) -> str | None: ...

    @property
    def body(self) -> bytes | None:
        """Raw data body, or ``None`` when it is not a single-data AMQP body/too large."""
        ...

    @property
    def delivery_count(self) -> int: ...

    @property
    def lock_lost(self) -> asyncio.Event: ...

    async def complete(self) -> None: ...

    async def abandon(self) -> None: ...

    async def dead_letter(self, reason: PoisonReason) -> None: ...


class MessageSource(Protocol):
    async def receive(self, max_messages: int, max_wait_seconds: float) -> list[InboundMessage]: ...

    async def close(self) -> None: ...


def _read_body(message: ServiceBusReceivedMessage) -> bytes | None:
    if message.body_type != AmqpMessageBodyType.DATA:
        return None
    chunks: list[bytes] = []
    total = 0
    for chunk in message.body:
        if not isinstance(chunk, bytes | bytearray):
            return None
        total += len(chunk)
        if total > _MAX_BODY_READ:
            return b"\0" * (_MAX_BODY_READ + 1)
        chunks.append(bytes(chunk))
    return b"".join(chunks)


def _lock_failure_callback(
    event: asyncio.Event,
) -> Callable[[object, Exception | None], Awaitable[None]]:
    async def on_failure(_renewable: object, _error: Exception | None) -> None:
        event.set()

    return on_failure


class ServiceBusInboundMessage:
    def __init__(self, receiver: ServiceBusReceiver, message: ServiceBusReceivedMessage) -> None:
        self._receiver = receiver
        self._message = message
        self._lock_lost = asyncio.Event()
        self._body = _read_body(message)

    @property
    def message_id(self) -> str | None:
        value = self._message.message_id
        return None if value is None else str(value)

    @property
    def body(self) -> bytes | None:
        return self._body

    @property
    def delivery_count(self) -> int:
        return int(self._message.delivery_count or 0)

    @property
    def lock_lost(self) -> asyncio.Event:
        return self._lock_lost

    @property
    def raw(self) -> ServiceBusReceivedMessage:
        return self._message

    async def complete(self) -> None:
        await self._receiver.complete_message(self._message)

    async def abandon(self) -> None:
        await self._receiver.abandon_message(self._message)

    async def dead_letter(self, reason: PoisonReason) -> None:
        await self._receiver.dead_letter_message(
            self._message, reason=reason.value, error_description=POISON_DESCRIPTIONS[reason]
        )


class ServiceBusMessageSource:
    """PEEK_LOCK receiver with prefetch disabled and automatic lock renewal.

    A failed or exhausted lock renewal sets the message's ``lock_lost`` event so
    the processor cancels in-flight work before any publication.
    """

    def __init__(
        self,
        *,
        fully_qualified_namespace: str,
        queue_name: str,
        credential: AsyncTokenCredential,
        lock_renewal_max_seconds: float,
    ) -> None:
        self._client = ServiceBusClient(fully_qualified_namespace, credential)
        self._queue = queue_name
        self._max_renewal = lock_renewal_max_seconds
        self._renewer = AutoLockRenewer(max_lock_renewal_duration=lock_renewal_max_seconds)
        self._receiver: ServiceBusReceiver | None = None

    def _get_receiver(self) -> ServiceBusReceiver:
        if self._receiver is None:
            self._receiver = self._client.get_queue_receiver(
                self._queue, receive_mode=ServiceBusReceiveMode.PEEK_LOCK, prefetch_count=0
            )
        return self._receiver

    async def receive(self, max_messages: int, max_wait_seconds: float) -> list[InboundMessage]:
        receiver = self._get_receiver()
        received = await receiver.receive_messages(
            max_message_count=max_messages, max_wait_time=max_wait_seconds
        )
        out: list[InboundMessage] = []
        for message in received:
            inbound = ServiceBusInboundMessage(receiver, message)
            self._renewer.register(
                receiver,
                message,
                max_lock_renewal_duration=self._max_renewal,
                on_lock_renew_failure=_lock_failure_callback(inbound.lock_lost),
            )
            out.append(inbound)
        return out

    async def close(self) -> None:
        for closer in (self._renewer.close, self._close_receiver, self._client.close):
            try:
                await closer()
            except Exception as exc:  # noqa: BLE001 - shutdown best effort, type logged
                _log.warning("worker.source_close_failed error=%s", type(exc).__name__)

    async def _close_receiver(self) -> None:
        if self._receiver is not None:
            await self._receiver.close()
