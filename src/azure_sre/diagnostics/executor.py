"""Argv-only subprocess execution with bounded output and exact process-group termination."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

_POLL_SECONDS: Final = 0.05
_GRACE_SECONDS: Final = 2.0
_READ_CHUNK: Final = 64 * 1024
MAX_STDOUT_BYTES: Final = 8 * 1024 * 1024
MAX_STDERR_BYTES: Final = 64 * 1024


class CommandCleanupError(RuntimeError):
    """A child process group could not be signalled. The message is fixed and safe to surface."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    cancelled: bool
    output_limit: bool = False


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
        cancel: threading.Event | None = None,
    ) -> CommandResult: ...


class _BoundedPipe:
    """Reads one pipe to EOF, keeping at most ``limit`` bytes and flagging any excess."""

    def __init__(self, fd: int, limit: int) -> None:
        self._fd = fd
        self._limit = limit
        self._buffer = bytearray()
        self.exceeded = threading.Event()
        self._thread = threading.Thread(target=self._pump, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def join(self, timeout: float) -> None:
        self._thread.join(timeout)

    @property
    def finished(self) -> bool:
        return not self._thread.is_alive()

    @property
    def data(self) -> bytes:
        return bytes(self._buffer)

    def _pump(self) -> None:
        while True:
            try:
                chunk = os.read(self._fd, _READ_CHUNK)
            except OSError:
                return
            if not chunk:
                return
            room = self._limit - len(self._buffer)
            if len(chunk) > room:
                # Keep only what fits; the caller terminates the group once the cap is flagged.
                self._buffer.extend(chunk[: max(room, 0)])
                self.exceeded.set()
                return
            self._buffer.extend(chunk)


class SubprocessRunner:
    """Runs a fixed argv with ``shell=False`` in a new session so the whole group can be killed.

    Output is captured while the process runs. Once a stream exceeds its cap the process group
    is terminated and the result carries ``output_limit=True``; excess output is never buffered.
    """

    def __init__(
        self,
        *,
        max_stdout_bytes: int = MAX_STDOUT_BYTES,
        max_stderr_bytes: int = MAX_STDERR_BYTES,
    ) -> None:
        self._max_stdout = max_stdout_bytes
        self._max_stderr = max_stderr_bytes

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
        cancel: threading.Event | None = None,
    ) -> CommandResult:
        if not argv or any(not isinstance(part, str) or "\x00" in part for part in argv):
            raise ValueError("argv must be a non-empty sequence of NUL-free strings")
        # argv is a validated list and shell=False, so no shell parses any part of it.
        proc = subprocess.Popen(  # noqa: S603
            list(argv),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(env),
            close_fds=True,
            start_new_session=True,
        )
        if proc.stdout is None or proc.stderr is None:
            raise RuntimeError("pipes were requested but not created")
        out_pipe = _BoundedPipe(proc.stdout.fileno(), self._max_stdout)
        err_pipe = _BoundedPipe(proc.stderr.fileno(), self._max_stderr)
        out_pipe.start()
        err_pipe.start()

        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        cancelled = False
        while True:
            if out_pipe.exceeded.is_set() or err_pipe.exceeded.is_set():
                break
            if proc.poll() is not None and out_pipe.finished and err_pipe.finished:
                break
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(_POLL_SECONDS)

        output_limit = out_pipe.exceeded.is_set() or err_pipe.exceeded.is_set()
        if output_limit or timed_out or cancelled or proc.poll() is None:
            _terminate_group(proc)
        else:
            # The leader exited cleanly; descendants may still hold pipes open, so kill the group.
            out_pipe.join(_GRACE_SECONDS)
            err_pipe.join(_GRACE_SECONDS)
            if not (out_pipe.finished and err_pipe.finished):
                _terminate_group(proc)
        proc.wait()
        out_pipe.join(_GRACE_SECONDS)
        err_pipe.join(_GRACE_SECONDS)
        return CommandResult(
            returncode=proc.returncode,
            stdout=out_pipe.data,
            stderr=err_pipe.data,
            timed_out=timed_out,
            cancelled=cancelled,
            output_limit=output_limit,
        )


def _terminate_group(proc: subprocess.Popen[bytes]) -> None:
    """Signal only the process group created for this child, never a broad name match."""
    pgid = proc.pid
    _signal_group(pgid, signal.SIGTERM)
    try:
        proc.wait(timeout=_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    # Descendants can outlive the leader and keep pipes open; SIGKILL the group as well.
    _signal_group(pgid, signal.SIGKILL)


def _signal_group(pgid: int, sig: signal.Signals) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return
    except PermissionError:
        # macOS can report EPERM for a group whose members have all exited. Only a group that
        # signal 0 confirms is empty is accepted; anything else is a real cleanup failure.
        if _group_is_gone(pgid):
            return
        raise CommandCleanupError("diagnostic process group could not be terminated") from None


def _group_is_gone(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False
