"""Baseline for the application-owned GitHub MCP stdio client.

Verified offline against ``github-mcp-server`` v2.0.2 (commit eb47a99) and the
Python ``mcp==2.3.0`` client: ``stdio --tools=<list>`` advertises exactly the listed
tools and tool listing works without credentials. ``issue_write`` accepts
``method`` in {create, update} and ``state`` (open/closed), so the host must
enforce create-only/no-close itself; the server flags are not sufficient.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.client.stdio import StdioServerParameters

# Only these tools are ever advertised to the application publisher.
PUBLISHER_TOOLS: tuple[str, ...] = (
    "issue_write",
    "issue_read",
    "list_issues",
    "search_issues",
    "add_issue_comment",
)

# Per-tool argument rules enforced by the host before any call.
_ALLOWED_ARGS: Mapping[str, frozenset[str]] = {
    "issue_write": frozenset({"method", "owner", "repo", "title", "body", "labels"}),
    "issue_read": frozenset({"method", "owner", "repo", "issue_number", "page", "perPage"}),
    "list_issues": frozenset(
        {"owner", "repo", "labels", "state", "since", "orderBy", "direction", "perPage", "after"}
    ),
    "search_issues": frozenset({"query", "owner", "repo", "sort", "order", "page", "perPage"}),
    "add_issue_comment": frozenset({"owner", "repo", "issue_number", "body"}),
}


class McpPolicyError(ValueError):
    """Raised for MCP calls outside the publisher allowlist."""


@dataclass(frozen=True)
class RepositoryTarget:
    owner: str
    repo: str


def github_mcp_stdio_parameters(
    *,
    binary: Path,
    app_id: str,
    installation_id: str,
    private_key_path: Path,
    workdir: Path,
) -> StdioServerParameters:
    """Stdio launch for the official server using native GitHub App authentication.

    The PEM path is passed by flag (never via environment); the child env is empty
    apart from the MCP SDK's safe defaults (HOME, LOGNAME, PATH, SHELL, TERM, USER).
    """
    return StdioServerParameters(
        command=str(binary),
        args=[
            "stdio",
            f"--tools={','.join(PUBLISHER_TOOLS)}",
            f"--app-id={app_id}",
            f"--app-installation-id={installation_id}",
            f"--app-private-key-path={private_key_path}",
        ],
        env={},
        cwd=str(workdir),
    )


def unexpected_advertised_tools(advertised: Iterable[str]) -> set[str]:
    return set(advertised) - set(PUBLISHER_TOOLS)


def validate_call(name: str, arguments: Mapping[str, Any], target: RepositoryTarget) -> None:
    """Reject any call that is not a fixed-repository, create/read/comment-only operation."""
    allowed = _ALLOWED_ARGS.get(name)
    if allowed is None:
        raise McpPolicyError(f"Tool {name!r} is not allowlisted.")
    extra = set(arguments) - allowed
    if extra:
        raise McpPolicyError(f"Arguments {sorted(extra)} are not allowed for {name!r}.")
    if name != "search_issues" or "owner" in arguments or "repo" in arguments:
        if (arguments.get("owner"), arguments.get("repo")) != (target.owner, target.repo):
            raise McpPolicyError("Repository must be the host-configured target.")
    if name == "issue_write" and arguments.get("method") != "create":
        raise McpPolicyError("issue_write is restricted to method=create.")
    if name == "search_issues":
        query = str(arguments.get("query", ""))
        scope, _, terms = query.partition(" ")
        if (
            scope != f"repo:{target.owner}/{target.repo}"
            or not terms.strip()
            or ":" in terms
            or re.search(r"\b(?:OR|NOT)\b", terms, re.IGNORECASE)
        ):
            raise McpPolicyError(
                "search_issues requires one exact repository and plain search terms."
            )
