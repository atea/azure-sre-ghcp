"""Model backend seam: a Protocol for deterministic fakes and an adapter for the Copilot SDK."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from copilot import (
    GitHubTokenAcquireReason,
    GitHubTokenProviderArgs,
    GitHubTokenProviderResult,
    Tool,
    ToolInvocation,
    define_tool,
)
from copilot.tools import ToolResult
from pydantic import BaseModel

from azure_sre.runtime import sdk_policy
from azure_sre.security.redaction import redact_text
from azure_sre.worker.protocols import InvestigationDeferred

logger = logging.getLogger(__name__)

TokenSupplier = Callable[[GitHubTokenProviderArgs], Awaitable[GitHubTokenProviderResult]]
ToolHandler = Callable[[Any], Awaitable["ToolOutcome"]]

_APPROVED_TOKEN_HOSTS = frozenset({"github.com", "api.github.com"})
_RATE_LIMIT_MARKERS = ("rate limit", "rate_limit", "429")


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """Text returned to the model. ``ok`` is False for host-side rejections."""

    text: str
    ok: bool


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    params_model: type[BaseModel]
    handler: ToolHandler


class ModelSession(Protocol):
    async def send(
        self, prompt: str, schema: Mapping[str, Any], timeout_seconds: float
    ) -> str | None: ...

    async def close(self) -> list[str]:
        """Dispose the session. Returns cleanup error strings; never raises."""
        ...


class ModelBackend(Protocol):
    async def open(self, tools: Sequence[ToolSpec], root: Path) -> ModelSession:
        """Open an isolated session. ``root`` is a private per-run directory (mode 0700)."""
        ...


class SdkModelBackend:
    """Backend over the pinned SDK with an isolated client and a host-only token supplier."""

    def __init__(
        self,
        *,
        runtime_path: str,
        extra_env: Mapping[str, str],
        initial_token_supplier: TokenSupplier,
        refresh_token_supplier: TokenSupplier | None = None,
        model: str | None = None,
    ) -> None:
        if "COPILOT_SKIP_CLI_DOWNLOAD" not in extra_env:
            raise ValueError("extra_env must carry COPILOT_SKIP_CLI_DOWNLOAD")
        self._runtime_path = runtime_path
        self._extra_env = dict(extra_env)
        self._initial = initial_token_supplier
        self._refresh = refresh_token_supplier
        self._model = model

    async def _token_provider(self, args: GitHubTokenProviderArgs) -> GitHubTokenProviderResult:
        if args["host"] not in _APPROVED_TOKEN_HOSTS:
            raise PermissionError("credentials requested for an unapproved host")
        supplier = self._initial
        if args["reason"] == GitHubTokenAcquireReason.REFRESH and self._refresh is not None:
            supplier = self._refresh
        return await supplier(args)

    async def open(self, tools: Sequence[ToolSpec], root: Path) -> ModelSession:
        state = root / "state"
        workspace = root / "workspace"
        for directory in (state, workspace):
            directory.mkdir(mode=0o700, exist_ok=True)
        client = sdk_policy.create_isolated_client(
            base_directory=state,
            workspace=workspace,
            inference_token=None,
            runtime_path=self._runtime_path,
            extra_env=self._extra_env,
        )
        session = None
        try:
            await client.start()
            session, _perms = await sdk_policy.create_isolated_session(
                client,
                tools=[_sdk_tool(spec) for spec in tools],
                workspace=workspace,
                model=self._model,
                github_token_provider=self._token_provider,
            )
        except BaseException:
            for error in await sdk_policy.dispose(client, session):
                logger.warning("investigation cleanup error: %s", redact_text(error)[:300])
            raise
        return _SdkSession(client, session)


class _SdkSession:
    def __init__(self, client: Any, session: Any) -> None:
        self._client = client
        self._session = session

    async def send(
        self, prompt: str, schema: Mapping[str, Any], timeout_seconds: float
    ) -> str | None:
        try:
            event = await self._session.send_and_wait(
                prompt, response_schema=dict(schema), timeout=timeout_seconds
            )
        except Exception as exc:
            # Heuristic: the SDK exposes no typed rate-limit error in 1.0.20.
            text = str(exc).lower()
            if any(marker in text for marker in _RATE_LIMIT_MARKERS):
                raise InvestigationDeferred("rate_limited", reason="model_rate_limited") from exc
            raise
        if event is None:
            return None
        content = getattr(event.data, "content", None)
        return content if isinstance(content, str) else None

    async def close(self) -> list[str]:
        return await sdk_policy.dispose(self._client, self._session)


def _sdk_tool(spec: ToolSpec) -> Tool:
    async def handler(params: Any, invocation: ToolInvocation) -> ToolResult:
        try:
            outcome = await spec.handler(params)
        except Exception:  # noqa: BLE001 - never leak host exception text to the model
            return ToolResult(
                text_result_for_llm="The host could not complete this request.",
                result_type="failure",
                error="host_error",
            )
        return ToolResult(
            text_result_for_llm=outcome.text,
            result_type="success" if outcome.ok else "failure",
            error=None if outcome.ok else "host_rejected",
        )

    return define_tool(
        name=spec.name,
        description=spec.description,
        params_type=spec.params_model,
        handler=handler,
    )
