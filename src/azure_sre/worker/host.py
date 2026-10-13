"""Worker host: bounded-concurrency peek-lock consumption, reconciliation and graceful stop."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any, Final

from azure_sre.contracts import ApplicationRegistry
from azure_sre.state.errors import StateError
from azure_sre.state.repository import IncidentRepository
from azure_sre.worker.messages import PoisonMessage, PoisonReason, decode_message
from azure_sre.worker.processor import DriveOutcome, IncidentProcessor
from azure_sre.worker.queue import InboundMessage, MessageSource
from azure_sre.worker.retry import Jitter, backoff_delay
from azure_sre.worker.settings import WorkerSettings

__all__ = ["WorkerFatalError", "WorkerHost", "install_stop_signals"]

_log = logging.getLogger("azure_sre.worker")
_SETTLE_TIMEOUT_SECONDS: Final = 10.0


class WorkerFatalError(RuntimeError):
    """The host stopped because of repeated or unexpected failures (safe code only)."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class WorkerHost:
    def __init__(
        self,
        *,
        source: MessageSource,
        processor: IncidentProcessor,
        repository: IncidentRepository,
        registry: ApplicationRegistry,
        settings: WorkerSettings,
        rng: Jitter | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        reconcile: bool = True,
    ) -> None:
        self._source = source
        self._processor = processor
        self._repo = repository
        self._registry = registry
        self._settings = settings
        self._rng = rng
        self._sleep = sleep
        self._reconcile_enabled = reconcile
        self._stop = asyncio.Event()
        self._slots = asyncio.Semaphore(settings.concurrency)
        self._tasks: set[asyncio.Task[None]] = set()
        self._consecutive_failures = 0
        self._fatal: str | None = None
        self.active = 0
        self.max_active = 0

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def request_stop(self) -> None:
        if not self._stop.is_set():
            _log.info("worker.stop_requested")
        self._stop.set()

    def _fail(self, code: str) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._settings.max_consecutive_failures:
            self._fatal = self._fatal or "consecutive_failures"
            self.request_stop()
        _log.warning("worker.failure code=%s consecutive=%d", code, self._consecutive_failures)

    def _ok(self) -> None:
        self._consecutive_failures = 0

    async def _acquire(self) -> bool:
        """Take a concurrency slot unless stopping first."""
        if self._stop.is_set():
            return False
        acquire = asyncio.ensure_future(self._slots.acquire())
        stop = asyncio.ensure_future(self._stop.wait())
        try:
            await asyncio.wait({acquire, stop}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            stop.cancel()
            if not acquire.done():
                acquire.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await acquire
        if acquire.cancelled():
            return False
        if self._stop.is_set():
            self._slots.release()
            return False
        return True

    def _spawn(self, coro: Coroutine[Any, Any, None]) -> None:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        self.active -= 1
        self._slots.release()
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            # Never swallowed: an unexpected handler failure stops the host.
            _log.error("worker.task_failed error=%s", type(exc).__name__)
            self._fatal = self._fatal or "task_failed"
            self.request_stop()

    async def run(self) -> None:
        reconciler = (
            asyncio.create_task(self._reconcile_loop()) if self._reconcile_enabled else None
        )
        try:
            await self._receive_loop()
        finally:
            self.request_stop()
            await self._shutdown(reconciler)
        if self._fatal is not None:
            raise WorkerFatalError(self._fatal)

    async def _receive_loop(self) -> None:
        s = self._settings
        while not self._stop.is_set():
            if not await self._acquire():
                return
            try:
                messages = await self._source.receive(1, s.receive_wait_seconds)
            except asyncio.CancelledError:
                self._slots.release()
                raise
            except Exception as exc:  # noqa: BLE001 - classified; type name logged
                self._slots.release()
                self._fail(f"receive_{type(exc).__name__}")
                await self._pause(self._consecutive_failures)
                continue
            if not messages:
                self._slots.release()
                continue
            first, *extra = messages
            self._spawn(self._handle(first))
            for message in extra:  # defensive: sources must honor max_messages
                await self._settle(message.abandon(), "abandon")

    async def _pause(self, attempt: int) -> None:
        delay = backoff_delay(
            attempt,
            base=self._settings.store_backoff_base_seconds,
            cap=self._settings.store_backoff_max_seconds,
            rng=self._rng,
        )
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stop.wait(), delay)

    async def _settle(self, action: Awaitable[None], what: str) -> bool:
        try:
            await asyncio.wait_for(action, _SETTLE_TIMEOUT_SECONDS)
            return True
        except Exception as exc:  # noqa: BLE001 - redelivery is idempotent; type logged
            _log.warning("worker.settle_failed action=%s error=%s", what, type(exc).__name__)
            return False

    async def _handle(self, message: InboundMessage) -> None:
        try:
            alert = decode_message(
                message.body,
                message.message_id,
                self._registry,
                max_bytes=self._settings.max_message_bytes,
            )
        except PoisonMessage as poison:
            _log.error("worker.poison reason=%s", poison.reason.value)
            await self._settle(message.dead_letter(poison.reason), "dead_letter")
            return
        try:
            outcome = await self._processor.handle_alert(alert, lock_lost=message.lock_lost)
        except asyncio.CancelledError:
            await asyncio.shield(self._settle(message.abandon(), "abandon"))
            raise
        except Exception as exc:  # noqa: BLE001 - classified below; type name logged
            code = exc.code if isinstance(exc, StateError) else type(exc).__name__
            self._fail(f"process_{code}")
            if message.delivery_count >= self._settings.max_delivery_attempts:
                reason = PoisonReason.PROCESSING_ATTEMPTS_EXHAUSTED
                await self._settle(message.dead_letter(reason), "dead_letter")
                return
            await self._pause(max(message.delivery_count, 1))
            await self._settle(message.abandon(), "abandon")
            return
        if outcome is DriveOutcome.LOST:
            # Ownership or the lock was lost: never complete as if handled.
            await self._settle(message.abandon(), "abandon")
            return
        # Completion means "durably recorded"; durable state now owns the remaining work.
        self._ok()
        await self._settle(message.complete(), "complete")

    async def _reconcile_loop(self) -> None:
        s = self._settings
        while not self._stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), s.reconcile_interval_seconds)
            if self._stop.is_set():
                return
            await self.reconcile_once()

    async def reconcile_once(self) -> int:
        """Drive a bounded batch of due active incidents; returns how many were started."""
        s = self._settings
        try:
            records = await self._repo.list_active(s.reconcile_scan_limit)
        except StateError as exc:
            self._fail(f"reconcile_scan_{exc.code}")
            return 0
        now = self._repo.clock()
        due = [r.incident_key for r in records if self._processor.is_due(r, now)]
        started = 0
        for key in due[: s.reconcile_batch]:
            if not await self._acquire():
                break
            self._spawn(self._reconcile_one(key))
            started += 1
        return started

    async def _reconcile_one(self, key: str) -> None:
        try:
            await self._processor.drive(key)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - classified; type name logged
            code = exc.code if isinstance(exc, StateError) else type(exc).__name__
            self._fail(f"reconcile_{code}")
        else:
            self._ok()

    async def _shutdown(self, reconciler: asyncio.Task[None] | None) -> None:
        if reconciler is not None:
            reconciler.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reconciler
        pending = set(self._tasks)
        if pending:
            _, still = await asyncio.wait(pending, timeout=self._settings.shutdown_grace_seconds)
            for task in still:
                task.cancel()
            if still:
                _log.warning("worker.shutdown_cancelled tasks=%d", len(still))
            await asyncio.gather(*pending, return_exceptions=True)
        _log.info("worker.stopped")


def install_stop_signals(host: WorkerHost, loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Translate SIGTERM/SIGINT (Container Apps shutdown) into a graceful stop."""
    target = loop or asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            target.add_signal_handler(sig, host.request_stop)
