"""Host-only stdio session to the official ``github-mcp-server`` (never model connected).

Every publisher operation gets a *fresh* process with a fresh private directory:

* the GitHub App PEM is loaded from Key Vault by the injected loader, written ``0600``
  into a ``0700`` temp dir and passed by path (never via env/argv contents);
* ``HOME``/``TMPDIR``/XDG dirs point into that private dir and every inherited default
  variable is overridden, so no user home, credential helper or ``GITHUB_*`` variable
  reaches the child;
* the server's stderr goes to ``os.devnull`` so raw error text (which may contain HTTP
  bodies) is never logged by the host;
* the temp dir (and key) is removed in ``finally`` -- also on timeout and cancellation;
* advertised tools are checked against the reviewed v2.0.2 contract before any call and
  every call is validated by :func:`azure_sre.runtime.mcp_policy.validate_call`.

A process per operation also means installation tokens never outlive one operation.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, TextIO

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import CallToolResult, ListToolsResult, PaginatedRequestParams, TextContent

from azure_sre.github.tool_schemas import (
    EXPECTED_SERVER_NAME,
    EXPECTED_SERVER_VERSION,
    check_advertised_tools,
    required_arguments,
)
from azure_sre.runtime.mcp_policy import (
    RepositoryTarget,
    github_mcp_stdio_parameters,
    validate_call,
)

__all__ = [
    "MAX_RESPONSE_CHARS",
    "ClientSessionLike",
    "McpSetupError",
    "PublisherSession",
    "SessionFactory",
    "ToolResponse",
    "open_publisher_session",
    "safe_child_environment",
    "single_leaf",
    "stdio_session_factory",
]

MAX_RESPONSE_CHARS: Final = 8 * 1024 * 1024
_MAX_TOOL_PAGES: Final = 4
_KEY_FILE: Final = "app-key.pem"


class McpSetupError(RuntimeError):
    """Failure before any tool call was sent. ``code`` is a safe reason code."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__(code)


class McpProtocolError(RuntimeError):
    """Unexpected MCP result shape (not a ``CallToolResult``)."""


@dataclass(frozen=True)
class ToolResponse:
    is_error: bool
    text: str


class ClientSessionLike(Protocol):
    """The subset of ``mcp.ClientSession`` (v2.3) the publisher uses."""

    async def initialize(self) -> Any: ...

    async def list_tools(
        self, *, params: PaginatedRequestParams | None = None
    ) -> ListToolsResult: ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
    ) -> Any: ...


SessionFactory = Callable[
    [StdioServerParameters, TextIO], AbstractAsyncContextManager[ClientSessionLike]
]


@asynccontextmanager
async def stdio_session_factory(
    params: StdioServerParameters, errlog: TextIO
) -> AsyncIterator[ClientSessionLike]:
    async with stdio_client(params, errlog=errlog) as (read, write):
        async with ClientSession(read, write) as session:
            yield session


def safe_child_environment(private_dir: Path) -> dict[str, str]:
    """Overrides *every* MCP SDK default variable; nothing from the host env survives."""
    home = private_dir / "home"
    return {
        "HOME": str(home),
        "USER": "azure-sre",
        "LOGNAME": "azure-sre",
        "SHELL": "/bin/false",
        "TERM": "dumb",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(private_dir / "tmp"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
    }


def _prepare_private_dir(root: Path | None, pem: str) -> tuple[Path, Path]:
    private_dir = Path(tempfile.mkdtemp(prefix="azure-sre-gms-", dir=root))  # mode 0700
    try:
        for sub in ("home", "tmp"):
            (private_dir / sub).mkdir(mode=0o700)
        key_path = private_dir / _KEY_FILE
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(key_path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(pem)
    except BaseException:
        _remove_private_dir(private_dir)
        raise
    return private_dir, key_path


def _remove_private_dir(private_dir: Path) -> None:
    key_path = private_dir / _KEY_FILE
    try:
        key_path.unlink(missing_ok=True)
    finally:
        shutil.rmtree(private_dir, ignore_errors=True)


def single_leaf(group: BaseExceptionGroup[BaseException]) -> BaseException | None:
    """The only leaf of a (nested) anyio/asyncio exception group, if exactly one."""
    current: BaseException = group
    while isinstance(current, BaseExceptionGroup):
        if len(current.exceptions) != 1:
            return None
        current = current.exceptions[0]
    return current


def _open_devnull() -> TextIO:
    return open(os.devnull, "w", encoding="utf-8")


class PublisherSession:
    """Validated tool calls against one fixed repository on one live server process."""

    def __init__(
        self,
        session: ClientSessionLike,
        target: RepositoryTarget,
        *,
        call_timeout_seconds: float,
    ) -> None:
        self._session = session
        self.target = target
        self._call_timeout = call_timeout_seconds

    async def call(self, name: str, arguments: Mapping[str, Any]) -> ToolResponse:
        """Policy + advertised-schema checks, then exactly one ``tools/call``.

        Raises ``McpPolicyError`` before sending; transport errors/timeouts propagate
        (the caller decides whether the outcome is unknown).
        """
        validate_call(name, arguments, self.target)
        missing = required_arguments(name) - set(arguments)
        if missing:
            raise McpProtocolError(f"tool {name}: required arguments missing")
        result = await self._session.call_tool(
            name, dict(arguments), read_timeout_seconds=self._call_timeout
        )
        if not isinstance(result, CallToolResult):
            raise McpProtocolError(f"tool {name}: unexpected result type")
        parts: list[str] = []
        size = 0
        for block in result.content:
            if isinstance(block, TextContent):
                size += len(block.text)
                if size > MAX_RESPONSE_CHARS:
                    raise McpProtocolError(f"tool {name}: response too large")
                parts.append(block.text)
        return ToolResponse(is_error=bool(result.is_error), text="".join(parts))


async def _advertised_schemas(session: ClientSessionLike) -> dict[str, Any]:
    schemas: dict[str, Any] = {}
    cursor: str | None = None
    for _ in range(_MAX_TOOL_PAGES):
        params = PaginatedRequestParams(cursor=cursor) if cursor else None
        listing = await session.list_tools(params=params)
        for tool in listing.tools:
            if tool.name in schemas:
                raise McpSetupError("mcp_schema_mismatch", retryable=False)
            schemas[tool.name] = tool.input_schema
        cursor = listing.next_cursor
        if not cursor:
            return schemas
    raise McpSetupError("mcp_schema_mismatch", retryable=False)


def _check_server(init: Any) -> None:
    info = getattr(init, "server_info", None)
    name = getattr(info, "name", None)
    version = getattr(info, "version", None)
    if (name, version) != (EXPECTED_SERVER_NAME, EXPECTED_SERVER_VERSION):
        raise McpSetupError("mcp_server_version_mismatch", retryable=False)


@asynccontextmanager
async def open_publisher_session(
    *,
    binary: Path,
    app_id: str,
    installation_id: int,
    load_private_key: Callable[[], Awaitable[str]],
    target: RepositoryTarget,
    factory: SessionFactory = stdio_session_factory,
    startup_timeout_seconds: float = 10.0,
    call_timeout_seconds: float = 10.0,
    private_root: Path | None = None,
) -> AsyncIterator[PublisherSession]:
    """Launch, initialize and schema-check a fresh server; always remove the private dir.

    Setup failures raise :class:`McpSetupError` (no tool call has been sent yet).
    """
    if not binary.is_absolute():
        raise McpSetupError("mcp_binary_invalid", retryable=False)
    try:
        pem = await load_private_key()
    except Exception as exc:
        raise McpSetupError("private_key_unavailable", retryable=True) from exc
    if not pem.lstrip().startswith("-----BEGIN"):
        raise McpSetupError("private_key_unavailable", retryable=False)
    private_dir, key_path = _prepare_private_dir(private_root, pem)
    del pem
    errlog = _open_devnull()
    try:
        params = github_mcp_stdio_parameters(
            binary=binary,
            app_id=app_id,
            installation_id=str(installation_id),
            private_key_path=key_path,
            workdir=private_dir,
        ).model_copy(update={"env": safe_child_environment(private_dir)})
        setup_done = False
        try:
            async with factory(params, errlog) as session:
                with anyio.fail_after(startup_timeout_seconds):
                    init = await session.initialize()
                    _check_server(init)
                    schemas = await _advertised_schemas(session)
                try:
                    check_advertised_tools(schemas)
                except RuntimeError as exc:
                    raise McpSetupError("mcp_schema_mismatch", retryable=False) from exc
                setup_done = True
                yield PublisherSession(session, target, call_timeout_seconds=call_timeout_seconds)
        except Exception as exc:
            leaf = single_leaf(exc) if isinstance(exc, BaseExceptionGroup) else exc
            if setup_done:
                if leaf is not None and leaf is not exc:
                    raise leaf from None
                raise
            if isinstance(leaf, McpSetupError):
                raise leaf from None
            raise McpSetupError("mcp_unavailable", retryable=True) from None
    finally:
        errlog.close()
        _remove_private_dir(private_dir)
