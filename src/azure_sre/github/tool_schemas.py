"""Expected ``github-mcp-server`` v2.0.2 tool contract for the application publisher.

Captured offline from the pinned binary (``stdio --tools=<PUBLISHER_TOOLS>``, no
credentials) into ``gms_tools_v2_0_2.json``. At every session start the publisher checks
the *advertised* schemas against these expectations: exact tool set, exact required
arguments, and the type/enum of every argument the host actually sends. A server upgrade
that changes any of these fails closed before any write.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from azure_sre.runtime.mcp_policy import PUBLISHER_TOOLS

__all__ = [
    "EXPECTED_SERVER_NAME",
    "EXPECTED_SERVER_VERSION",
    "EXPECTED_TOOLS",
    "SchemaMismatchError",
    "ToolExpectation",
    "check_advertised_tools",
]

EXPECTED_SERVER_NAME: Final = "github-mcp-server"
EXPECTED_SERVER_VERSION: Final = "2.0.2"


class SchemaMismatchError(RuntimeError):
    """Advertised tools differ from the reviewed contract. Message is safe (no payloads)."""


@dataclass(frozen=True)
class ArgExpectation:
    json_type: str
    enum_values: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ToolExpectation:
    required: frozenset[str]
    used: Mapping[str, ArgExpectation]


def _arg(json_type: str, *values: str) -> ArgExpectation:
    return ArgExpectation(json_type, frozenset(values))


_OWNER_REPO: Final = {"owner": _arg("string"), "repo": _arg("string")}

EXPECTED_TOOLS: Final[Mapping[str, ToolExpectation]] = {
    "issue_write": ToolExpectation(
        required=frozenset({"method", "owner", "repo"}),
        used={
            **_OWNER_REPO,
            "method": _arg("string", "create"),
            "title": _arg("string"),
            "body": _arg("string"),
        },
    ),
    "issue_read": ToolExpectation(
        required=frozenset({"method", "owner", "repo", "issue_number"}),
        used={
            **_OWNER_REPO,
            "method": _arg("string", "get", "get_comments"),
            "issue_number": _arg("number"),
            "page": _arg("number"),
            "perPage": _arg("number"),
        },
    ),
    "list_issues": ToolExpectation(
        required=frozenset({"owner", "repo"}),
        used={
            **_OWNER_REPO,
            "orderBy": _arg("string", "CREATED_AT"),
            "direction": _arg("string", "DESC"),
            "since": _arg("string"),
            "after": _arg("string"),
            "perPage": _arg("number"),
        },
    ),
    "search_issues": ToolExpectation(
        required=frozenset({"query"}),
        used={"query": _arg("string"), "perPage": _arg("number")},
    ),
    "add_issue_comment": ToolExpectation(
        required=frozenset({"owner", "repo", "issue_number"}),
        used={**_OWNER_REPO, "issue_number": _arg("number"), "body": _arg("string")},
    ),
}

assert set(EXPECTED_TOOLS) == set(PUBLISHER_TOOLS)  # noqa: S101


def _check_tool(name: str, schema: Any) -> None:
    expectation = EXPECTED_TOOLS[name]
    if not isinstance(schema, Mapping) or schema.get("type") != "object":
        raise SchemaMismatchError(f"tool {name}: input schema is not an object")
    required = schema.get("required") or []
    if not isinstance(required, Sequence) or frozenset(map(str, required)) != expectation.required:
        raise SchemaMismatchError(f"tool {name}: required arguments changed")
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        raise SchemaMismatchError(f"tool {name}: properties missing")
    for arg, expected in expectation.used.items():
        prop = properties.get(arg)
        if not isinstance(prop, Mapping) or prop.get("type") != expected.json_type:
            raise SchemaMismatchError(f"tool {name}: argument {arg} missing or retyped")
        if expected.enum_values:
            enum = prop.get("enum")
            if not isinstance(enum, Sequence) or not expected.enum_values <= set(map(str, enum)):
                raise SchemaMismatchError(f"tool {name}: argument {arg} enum changed")


def check_advertised_tools(tools: Mapping[str, Any]) -> None:
    """``tools`` maps advertised tool name -> JSON input schema."""
    if set(tools) != set(PUBLISHER_TOOLS):
        raise SchemaMismatchError("advertised tool set differs from the publisher allowlist")
    for name in PUBLISHER_TOOLS:
        _check_tool(name, tools[name])


def required_arguments(name: str) -> frozenset[str]:
    return EXPECTED_TOOLS[name].required
