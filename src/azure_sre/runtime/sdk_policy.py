"""Hardened construction of Copilot SDK clients and sessions.

Verified against ``github-copilot-sdk==1.0.20`` (runtime 1.0.96):

* ``CopilotClient(mode="empty", base_directory=...)`` disables custom instructions,
  plugins, skills, keytar and environment context, and requires every session to
  pass ``available_tools``.
* ``use_logged_in_user=False`` adds ``--no-auto-login`` so the runtime never falls
  back to a stored user credential. ``github_token`` is handed to the runtime only
  through ``COPILOT_SDK_AUTH_TOKEN`` in the child environment.
* ``env`` is authoritative for the child process; ``None`` would inherit
  ``os.environ`` (and therefore publisher/Azure secrets), so it is always explicit.
* ``available_tools`` (``ToolSet``) hides every built-in/MCP tool that is not listed.
* ``on_permission_request`` receives typed ``PermissionRequest`` variants; anything
  other than an allowlisted ``custom-tool`` request is rejected.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from copilot import (
    CopilotClient,
    CopilotSession,
    PermissionRequest,
    RuntimeConnection,
    Tool,
    ToolSet,
)
from copilot.generated.rpc import (
    PermissionDecisionApproveOnce,
    PermissionDecisionReject,
    ToolsExecuteRequest,
)
from copilot.session import PermissionInvocation, PermissionRequestResult

DENY_FEEDBACK = (
    "Denied by Azure SRE policy: only allowlisted read-only investigation tools may run."
)

# Variables the runtime child may receive. Anything else must be passed explicitly
# and must not look like a credential.
_BASE_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
_SECRET_LIKE = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PRIVATE|_KEY$|^KEY|PEM|CREDENTIAL|CONNECTION_STRING|SAS)",
    re.IGNORECASE,
)
_FORBIDDEN_PREFIXES = ("GITHUB_", "GH_", "AZURE_", "IDENTITY_", "MSI_", "COPILOT_SDK_AUTH")

# GitHub token prefixes accepted for inference, per auth mode:
# * ``pat`` (default): a fine-grained personal access token (``github_pat_``) for a
#   dedicated user with a Copilot seat and the "Copilot Requests" permission.
# * ``app``: a GitHub App installation token (``ghs_``).
# Classic PATs, OAuth, user-to-server and refresh tokens are never accepted.
INSTALLATION_TOKEN_PREFIX = "ghs_"  # noqa: S105 - prefix, not a secret
PAT_TOKEN_PREFIX = "github_pat_"  # noqa: S105 - prefix, not a secret
INFERENCE_AUTH_MODES = ("pat", "app")
DEFAULT_INFERENCE_AUTH_MODE = "pat"
_ALWAYS_REJECTED_PREFIXES = ("ghp_", "gho_", "ghu_", "ghr_")
_MODE_PREFIX = {"pat": PAT_TOKEN_PREFIX, "app": INSTALLATION_TOKEN_PREFIX}
APPROVED_TOKEN_HOSTS = frozenset({"github.com", "api.github.com"})


class PolicyError(ValueError):
    """Raised when a requested SDK configuration would violate the security baseline."""


@dataclass(frozen=True)
class PermissionAuditEntry:
    kind: str
    tool_name: str | None
    approved: bool


@dataclass
class DenyByDefaultPermissions:
    """Permission handler approving only allowlisted custom tools, once per request."""

    allowed_custom_tools: frozenset[str]
    audit: list[PermissionAuditEntry] = field(default_factory=list)

    def __call__(
        self, request: PermissionRequest, invocation: PermissionInvocation
    ) -> PermissionRequestResult:
        kind = getattr(request, "kind", "unknown")
        tool_name = getattr(request, "tool_name", None)
        approved = (
            kind == "custom-tool"
            and tool_name in self.allowed_custom_tools
            and not getattr(request, "managed_approval_required", False)
        )
        self.audit.append(PermissionAuditEntry(kind=kind, tool_name=tool_name, approved=approved))
        if approved:
            return PermissionDecisionApproveOnce()
        return PermissionDecisionReject(feedback=DENY_FEEDBACK)


def custom_tool_allowlist(names: Iterable[str]) -> ToolSet:
    """Build an ``available_tools`` filter exposing only the named custom tools."""
    toolset = ToolSet()
    for name in sorted(set(names)):
        toolset.add_custom(name)
    if not len(toolset):
        raise PolicyError("At least one custom tool must be allowlisted.")
    return toolset


def build_runtime_env(
    *,
    home: Path,
    extra: Mapping[str, str] | None = None,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return an explicit minimal environment for the Copilot runtime child process."""
    import os

    src = os.environ if source is None else source
    env = {k: src[k] for k in _BASE_ENV_KEYS if k in src}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["HOME"] = str(home)
    for key, value in (extra or {}).items():
        if key.upper().startswith(_FORBIDDEN_PREFIXES) or _SECRET_LIKE.search(key):
            raise PolicyError(f"Refusing to pass credential-like variable {key!r} to the runtime.")
        env[key] = value
    return env


def validate_inference_auth_mode(mode: str) -> str:
    mode = mode.strip().lower()
    if mode not in INFERENCE_AUTH_MODES:
        raise PolicyError(f"Inference auth mode must be one of {INFERENCE_AUTH_MODES}.")
    return mode


def is_approved_token_host(host: object) -> bool:
    """Return True only for github.com/api.github.com, as a bare host or bare HTTPS origin.

    The SDK token callback reports the host as an origin such as ``https://github.com``.
    Anything with userinfo, a port, a path, a query or a fragment is rejected.
    """
    if not isinstance(host, str) or not host or host != host.strip():
        return False
    if "://" not in host:
        return host.lower() in APPROVED_TOKEN_HOSTS
    try:
        parts = urlsplit(host)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme.lower() == "https"
        and parts.hostname in APPROVED_TOKEN_HOSTS
        and parts.netloc.lower() == parts.hostname
        and port is None
        and parts.path in ("", "/")
        and not parts.query
        and not parts.fragment
    )


def validate_inference_token(token: str, *, mode: str) -> str:
    """Accept only the token type configured for ``mode``.

    ``pat`` accepts fine-grained PATs (``github_pat_``); ``app`` accepts installation
    tokens (``ghs_``). Classic PATs and OAuth/user-to-server tokens are always rejected.
    """
    expected = _MODE_PREFIX[validate_inference_auth_mode(mode)]
    token = token.strip()
    if token.startswith(_ALWAYS_REJECTED_PREFIXES):
        raise PolicyError("Classic PAT, OAuth or user-to-server tokens are not permitted.")
    if not token.startswith(expected):
        raise PolicyError(f"Inference auth mode {mode!r} requires a {expected}-prefixed token.")
    return token


def create_isolated_client(
    *,
    base_directory: Path,
    workspace: Path,
    inference_token: str | None = None,
    inference_auth_mode: str = DEFAULT_INFERENCE_AUTH_MODE,
    runtime_path: str | None = None,
    extra_env: Mapping[str, str] | None = None,
    log_level: str = "error",
) -> CopilotClient:
    """Create a client in ``empty`` mode with no user-credential fallback.

    ``inference_token=None`` yields an unauthenticated runtime, which is sufficient
    for offline lifecycle/tool-gating checks but cannot perform inference.
    """
    base_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = (
        validate_inference_token(inference_token, mode=inference_auth_mode)
        if inference_token
        else None
    )
    return CopilotClient(
        mode="empty",
        connection=RuntimeConnection.for_stdio(path=runtime_path),
        base_directory=str(base_directory),
        working_directory=str(workspace),
        env=build_runtime_env(home=base_directory, extra=extra_env),
        github_token=token,
        use_logged_in_user=False,
        log_level=log_level,  # type: ignore[arg-type]
    )


async def create_isolated_session(
    client: CopilotClient,
    *,
    tools: list[Tool],
    workspace: Path,
    permissions: DenyByDefaultPermissions | None = None,
    model: str | None = None,
    **session_options: Any,
) -> tuple[CopilotSession, DenyByDefaultPermissions]:
    """Create a session exposing exactly ``tools`` behind deny-by-default permissions."""
    names = [t.name for t in tools]
    if len(names) != len(set(names)):
        raise PolicyError("Duplicate custom tool names.")
    for tool in tools:
        if tool.skip_permission or tool.overrides_built_in_tool:
            raise PolicyError(f"Tool {tool.name!r} must not skip permission or override built-ins.")
    perms = permissions or DenyByDefaultPermissions(frozenset(names))
    session = await client.create_session(
        tools=tools,
        available_tools=custom_tool_allowlist(names),
        on_permission_request=perms,
        working_directory=str(workspace),
        model=model,
        enable_config_discovery=False,
        skip_custom_instructions=True,
        enable_skills=False,
        enable_file_hooks=False,
        enable_host_git_operations=False,
        enable_session_store=False,
        mcp_servers={},
        **session_options,
    )
    return session, perms


async def execute_tool_directly(
    session: CopilotSession, name: str, arguments: Mapping[str, Any]
) -> dict[str, Any]:
    """Run one offered tool through the runtime's native pipeline without a model.

    Uses the experimental ``session.tools.execute`` RPC. In SDK 1.0.20 the generated
    wrapper is annotated ``ToolResultExpanded`` but returns the raw JSON dict, so the
    result is normalized here.
    """
    result: Any = await session.rpc.tools.execute(
        ToolsExecuteRequest(arguments=dict(arguments), name=name)
    )
    if isinstance(result, dict):
        return result
    to_dict: Callable[[], dict[str, Any]] = result.to_dict
    return to_dict()


async def dispose(client: CopilotClient, session: CopilotSession | None) -> list[str]:
    """Abort, detach and delete the session, then stop the runtime. Returns errors."""
    errors: list[str] = []
    if session is not None:
        session_id = session.session_id
        for step in (session.abort, session.disconnect):
            try:
                await step()
            except Exception as exc:  # noqa: BLE001 - disposal must continue
                errors.append(f"{step.__name__}: {exc}")
        try:
            await client.delete_session(session_id)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"delete_session: {exc}")
    try:
        await client.stop()
    except Exception as exc:  # noqa: BLE001 - includes ExceptionGroup[StopError]
        errors.append(f"stop: {exc}")
        await client.force_stop()
    return errors
