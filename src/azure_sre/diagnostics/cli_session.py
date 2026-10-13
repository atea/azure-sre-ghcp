"""Azure CLI session isolation: host-only managed-identity login and per-worker config dirs.

Token caches are never copied. Workers get only the profile file and the validated managed-identity
endpoint variables, so ``az`` can request tokens from the platform endpoint itself.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from azure_sre.diagnostics.executor import CommandRunner

_GUID_RE: Final = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_WORKER_RE: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_TOKEN_RE: Final = re.compile(r"^[\x21-\x7e]{1,512}$")
_ENDPOINT_KEYS: Final = ("IDENTITY_ENDPOINT", "MSI_ENDPOINT")
_SECRET_KEYS: Final = ("IDENTITY_HEADER", "MSI_SECRET")
_PROFILE_FILE: Final = "azureProfile.json"
# /opt/az/bin is where the container installs the pinned Azure CLI.
_SAFE_PATH: Final = "/opt/az/bin:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
_LOGIN_TIMEOUT_SECONDS: Final = 30


class CliSessionError(RuntimeError):
    """Login or setup failed. The message is fixed and never includes CLI output or credentials."""


def _validate_identity_endpoint(value: str) -> str:
    if len(value) > 512 or any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in value):
        raise CliSessionError("managed identity endpoint is malformed")
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise CliSessionError("managed identity endpoint is malformed")
    host = parts.hostname
    if host == "localhost":
        return value
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise CliSessionError("managed identity endpoint host is not allowed") from None
    if not (address.is_loopback or address.is_link_local):
        raise CliSessionError("managed identity endpoint host is not allowed")
    return value


def _validate_identity_secret(value: str) -> str:
    if not _TOKEN_RE.fullmatch(value):
        raise CliSessionError("managed identity header value is malformed")
    return value


def validate_identity_env(identity_env: Mapping[str, str] | None) -> dict[str, str]:
    """Keep only the four managed-identity variables, validated. Anything else is ignored."""
    if not identity_env:
        return {}
    out: dict[str, str] = {}
    for key in _ENDPOINT_KEYS:
        if key in identity_env:
            out[key] = _validate_identity_endpoint(identity_env[key])
    for key in _SECRET_KEYS:
        if key in identity_env:
            out[key] = _validate_identity_secret(identity_env[key])
    return out


class AzureCliSession:
    """Owns the Azure CLI config directories. Only the host calls ``initialize``.

    Workers receive a copy of the profile file in a private directory, so model tools never see a
    login command, a token, or a config path they can change. The CLI config contains no token
    cache copy; token refresh uses the managed-identity endpoint passed in ``identity_env``.
    """

    def __init__(
        self,
        *,
        root: Path,
        client_id: str,
        extension_dir: Path,
        runner: CommandRunner,
        az_path: str = "az",
        identity_env: Mapping[str, str] | None = None,
    ) -> None:
        if not _GUID_RE.fullmatch(client_id):
            raise CliSessionError("client id must be a GUID")
        self._root = root
        self._client_id = client_id
        self._extension_dir = extension_dir
        self._runner = runner
        self._az_path = az_path
        self._identity_env = validate_identity_env(identity_env)
        self._initialized = False
        self._lock = threading.Lock()

    @property
    def host_config_dir(self) -> Path:
        return self._root / "host"

    def initialize(self) -> None:
        """Run ``az login --identity`` once, on the host only, with the user-assigned client id."""
        with self._lock:
            if self._initialized:
                return
            self.host_config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            result = self._runner.run(
                (
                    self._az_path,
                    "login",
                    "--identity",
                    f"--client-id={self._client_id}",
                    "--allow-no-subscriptions",
                    "--output=none",
                ),
                env=self._env(self.host_config_dir),
                timeout_seconds=_LOGIN_TIMEOUT_SECONDS,
            )
            if (
                result.timed_out
                or result.cancelled
                or result.output_limit
                or result.returncode != 0
            ):
                raise CliSessionError("managed identity login failed")
            self._initialized = True

    def worker_env(self, worker: str) -> dict[str, str]:
        """Create a private config dir for one worker and return its isolated environment."""
        if not _WORKER_RE.fullmatch(worker):
            raise CliSessionError("worker name has unsupported characters")
        if not self._initialized:
            raise CliSessionError("CLI session is not initialized")
        config_dir = self._root / "workers" / worker
        if config_dir.exists():
            shutil.rmtree(config_dir)
        config_dir.mkdir(mode=0o700, parents=True)
        source = self.host_config_dir / _PROFILE_FILE
        if source.is_file():
            fd = os.open(config_dir / _PROFILE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle, source.open("rb") as src:
                handle.write(src.read())
        return self._env(config_dir)

    def _env(self, config_dir: Path) -> dict[str, str]:
        """Fixed environment; the parent process environment is never forwarded."""
        env = {
            "PATH": _SAFE_PATH,
            "HOME": str(config_dir),
            "LANG": "C.UTF-8",
            "AZURE_CONFIG_DIR": str(config_dir),
            "AZURE_EXTENSION_DIR": str(self._extension_dir),
            "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no",
            "AZURE_EXTENSION_REMOVE_OLD": "no",
            "AZURE_CORE_COLLECT_TELEMETRY": "false",
            "AZURE_CORE_ONLY_SHOW_ERRORS": "true",
            "AZURE_CORE_NO_COLOR": "true",
            "AZ_CLI_NO_PROMPT": "true",
        }
        env.update(self._identity_env)
        return env
