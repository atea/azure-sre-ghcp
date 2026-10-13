"""Subprocess executor and CLI session isolation tests (real child processes, no az)."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

from azure_sre.diagnostics import AzureCliSession, CliSessionError, SubprocessRunner
from azure_sre.diagnostics.executor import CommandResult

CLIENT_ID = "11111111-2222-3333-4444-555555555555"
ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return False


GRANDCHILD_SCRIPT = (
    "import subprocess, sys, time\n"
    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
    "print(child.pid, flush=True)\n"
    "time.sleep(60)\n"
)


def test_timeout_terminates_exact_process_group_including_grandchild() -> None:
    result = SubprocessRunner().run(
        (sys.executable, "-c", GRANDCHILD_SCRIPT),
        env=ENV,
        timeout_seconds=1.0,
    )
    assert result.timed_out is True
    assert result.returncode is None or result.returncode != 0
    grandchild = int(result.stdout.split()[0])
    assert _wait_dead(grandchild), "grandchild survived group termination"


def test_cancel_terminates_group_and_reports_cancelled() -> None:
    cancel = threading.Event()
    timer = threading.Timer(0.5, cancel.set)
    timer.start()
    try:
        started = time.monotonic()
        result = SubprocessRunner().run(
            (sys.executable, "-c", GRANDCHILD_SCRIPT),
            env=ENV,
            timeout_seconds=30.0,
            cancel=cancel,
        )
        elapsed = time.monotonic() - started
    finally:
        timer.cancel()
    assert result.cancelled is True
    assert result.timed_out is False
    assert elapsed < 15
    grandchild = int(result.stdout.split()[0])
    assert _wait_dead(grandchild)


def test_argv_is_never_parsed_by_a_shell() -> None:
    result = SubprocessRunner().run(
        (sys.executable, "-c", "import sys; print(sys.argv[1])", "$(touch injected)"),
        env=ENV,
        timeout_seconds=10.0,
    )
    assert result.returncode == 0
    assert result.stdout.decode().strip() == "$(touch injected)"


@pytest.mark.parametrize("argv", [(), ("az", "bad\x00arg"), ("az", 3)])
def test_invalid_argv_is_rejected(argv: tuple[object, ...]) -> None:
    with pytest.raises(ValueError):
        SubprocessRunner().run(argv, env=ENV, timeout_seconds=1.0)  # type: ignore[arg-type]


def test_normal_exit_returns_stdout_and_code() -> None:
    result = SubprocessRunner().run(
        (sys.executable, "-c", "print('hello')"), env=ENV, timeout_seconds=10.0
    )
    assert result == CommandResult(
        returncode=0,
        stdout=b"hello\n",
        stderr=b"",
        timed_out=False,
        cancelled=False,
    )


class RecordingRunner:
    def __init__(self, returncode: int | None = 0, timed_out: bool = False) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.returncode = returncode
        self.timed_out = timed_out

    def run(
        self,
        argv: object,
        *,
        env: dict[str, str],
        timeout_seconds: float,
        cancel: threading.Event | None = None,
    ) -> CommandResult:
        self.calls.append((tuple(argv), dict(env)))  # type: ignore[call-overload]
        return CommandResult(
            returncode=self.returncode,
            stdout=b"",
            stderr=b"secret-stderr-detail",
            timed_out=self.timed_out,
            cancelled=False,
        )


def _session(root: Path, runner: RecordingRunner) -> AzureCliSession:
    return AzureCliSession(
        root=root,
        client_id=CLIENT_ID,
        extension_dir=root / "ext",
        runner=runner,  # type: ignore[arg-type]
    )


def test_login_runs_once_on_host_with_client_id_and_fixed_env(tmp_path: Path) -> None:
    runner = RecordingRunner()
    session = _session(tmp_path, runner)
    session.initialize()
    session.initialize()
    assert len(runner.calls) == 1
    argv, env = runner.calls[0]
    assert argv[:2] == ("az", "login")
    assert "--identity" in argv
    assert f"--client-id={CLIENT_ID}" in argv
    assert env["AZURE_CONFIG_DIR"] == str(tmp_path / "host")
    assert env["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] == "no"
    assert env["AZURE_EXTENSION_DIR"] == str(tmp_path / "ext")


def test_login_failure_raises_fixed_message_without_stderr(tmp_path: Path) -> None:
    session = _session(tmp_path, RecordingRunner(returncode=1))
    with pytest.raises(CliSessionError) as info:
        session.initialize()
    assert "secret-stderr-detail" not in str(info.value)


def test_worker_requires_initialization_and_gets_private_config(tmp_path: Path) -> None:
    runner = RecordingRunner()
    session = _session(tmp_path, runner)
    with pytest.raises(CliSessionError):
        session.worker_env("w1")
    session.initialize()
    (tmp_path / "host" / "azureProfile.json").write_text("{}")
    env = session.worker_env("w1")
    assert env["AZURE_CONFIG_DIR"] == str(tmp_path / "workers" / "w1")
    assert "AZURE_CLIENT_SECRET" not in env
    copied = tmp_path / "workers" / "w1" / "azureProfile.json"
    assert copied.is_file()
    assert (copied.stat().st_mode & 0o777) == 0o600
    assert len(runner.calls) == 1, "workers must never run login"


@pytest.mark.parametrize("worker", ["../escape", "A", "", "x/y", "w" * 40])
def test_worker_names_are_restricted(tmp_path: Path, worker: str) -> None:
    session = _session(tmp_path, RecordingRunner())
    session.initialize()
    with pytest.raises(CliSessionError):
        session.worker_env(worker)


def test_client_id_must_be_guid(tmp_path: Path) -> None:
    with pytest.raises(CliSessionError):
        AzureCliSession(
            root=tmp_path,
            client_id="not-a-guid; rm",
            extension_dir=tmp_path,
            runner=RecordingRunner(),  # type: ignore[arg-type]
        )


def test_stdout_cap_is_enforced_while_running_and_reported(tmp_path: Path) -> None:
    runner = SubprocessRunner(max_stdout_bytes=1024, max_stderr_bytes=1024)
    result = runner.run(
        (sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 4096)"),
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout_seconds=20,
    )
    assert result.output_limit is True
    assert len(result.stdout) <= 1024


def test_stderr_cap_is_enforced_while_running(tmp_path: Path) -> None:
    runner = SubprocessRunner(max_stdout_bytes=1024, max_stderr_bytes=1024)
    result = runner.run(
        (sys.executable, "-c", "import sys\nwhile True: sys.stderr.write('e' * 4096)"),
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        timeout_seconds=20,
    )
    assert result.output_limit is True
    assert len(result.stderr) <= 1024


def test_identity_env_keeps_only_validated_managed_identity_keys() -> None:
    from azure_sre.diagnostics.cli_session import validate_identity_env

    kept = validate_identity_env(
        {
            "IDENTITY_ENDPOINT": "http://169.254.169.254/metadata/identity/oauth2/token",
            "IDENTITY_HEADER": "abc123",
            "UNRELATED": "value",
        }
    )
    assert set(kept) == {"IDENTITY_ENDPOINT", "IDENTITY_HEADER"}


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://evil.example.com/token",
        "file:///etc/passwd",
        "http://10.0.0.1/\nx",
        "ftp://127.0.0.1",
    ],
)
def test_identity_endpoint_rejects_unexpected_hosts_and_schemes(endpoint: str) -> None:
    from azure_sre.diagnostics.cli_session import validate_identity_env

    with pytest.raises(CliSessionError):
        validate_identity_env({"IDENTITY_ENDPOINT": endpoint})
