"""Shared fakes for the publisher tests (no test functions here).

``FakeGitHub`` simulates one repository and answers with the *actual* github-mcp-server
v2.0.2 text-JSON shapes (``MinimalResponse``, ``MinimalIssue``, ``MinimalIssuesResponse``,
``[]MinimalIssueComment``, raw search result) and error strings. ``FakeSession`` speaks
the real ``mcp`` 2.3 types and advertises the tools captured from the pinned binary.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TextIO

from mcp.client.stdio import StdioServerParameters
from mcp.types import (
    CallToolResult,
    Implementation,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

import azure_sre.github as gh
from azure_sre import contracts as c
from azure_sre.config import BudgetPolicy
from azure_sre.github import McpPublisher
from azure_sre.state.records import issue_marker, recovery_marker
from azure_sre.worker import PublishRequest, RecoveryRequest
from tests.unit.test_worker_support import REGISTRY, complete_report, make_alert

REPO = "contoso/shop"
OWNER, NAME = REPO.split("/")
BOT = "azure-sre-app[bot]"
FIXTURE_PATH = Path(gh.__file__).parent / "gms_tools_v2_0_2.json"
FIXTURE: dict[str, Any] = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
TEST_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIfake\n-----END RSA PRIVATE KEY-----\n"


def real_tools() -> list[Tool]:
    return [
        Tool(name=t["name"], input_schema=deepcopy(t["input_schema"])) for t in FIXTURE["tools"]
    ]


def text_result(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=is_error)


def issue_url(number: int, repo: str = REPO) -> str:
    return f"https://github.com/{repo}/issues/{number}"


Hook = Callable[[str, dict[str, Any]], Any]


@dataclass
class FakeGitHub:
    """One repository plus scripted faults. ``hooks[tool]`` runs before the default.

    A hook may return a ``CallToolResult`` (sent instead of the default), raise, or
    return ``None`` (fall through). ``after_hooks[tool]`` run after state changed and
    may raise to simulate a lost response.
    """

    issues: dict[int, dict[str, Any]] = field(default_factory=dict)
    comments: dict[int, list[dict[str, Any]]] = field(default_factory=dict)
    next_number: int = 100
    next_comment: int = 9000
    hooks: dict[str, Hook] = field(default_factory=dict)
    after_hooks: dict[str, Hook] = field(default_factory=dict)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    search_index: set[int] | None = None  # None: search sees everything
    tools: list[Tool] = field(default_factory=real_tools)
    server_version: str = "2.0.2"
    sessions: list[FakeSession] = field(default_factory=list)
    params: list[StdioServerParameters] = field(default_factory=list)

    def add_issue(self, body: str, *, author: str = BOT, number: int | None = None) -> int:
        number = number or self.next_number
        self.next_number = max(self.next_number, number + 1)
        self.issues[number] = {
            "number": number,
            "title": "t",
            "body": body,
            "state": "open",
            "html_url": issue_url(number),
            "user": {"login": author, "id": 1},
            "comments": 0,
            "created_at": f"2026-10-13T06:{number % 60:02d}:00Z",
        }
        self.comments.setdefault(number, [])
        return number

    def add_comment(self, number: int, body: str, *, author: str = BOT) -> int:
        comment_id = self.next_comment
        self.next_comment += 1
        self.comments.setdefault(number, []).append(
            {
                "id": comment_id,
                "body": body,
                "html_url": f"{issue_url(number)}#issuecomment-{comment_id}",
                "user": {"login": author, "id": 1},
                "created_at": "2026-10-13T06:30:00Z",
            }
        )
        self.issues[number]["comments"] += 1
        return comment_id

    def writes(self) -> list[str]:
        return [n for n, _ in self.calls if n in ("issue_write", "add_issue_comment")]

    def dispatch(self, name: str, args: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, deepcopy(args)))
        if name in self.hooks:
            hooked = self.hooks[name](name, args)
            if hooked is not None:
                assert isinstance(hooked, CallToolResult)
                return hooked
        result: CallToolResult = getattr(self, f"_{name}")(args)
        if name in self.after_hooks:
            self.after_hooks[name](name, args)
        return result

    # ---- default behaviours (shapes copied from github-mcp-server v2.0.2)

    def _issue_write(self, args: dict[str, Any]) -> CallToolResult:
        assert args["method"] == "create"
        number = self.add_issue(args["body"])
        self.issues[number]["title"] = args["title"]
        return text_result(json.dumps({"id": "3999999999", "url": issue_url(number)}))

    def _issue_read(self, args: dict[str, Any]) -> CallToolResult:
        number = int(args["issue_number"])
        if number not in self.issues:
            return text_result(
                f"failed to get issue: GET https://api.github.com/repos/{REPO}/issues/"
                f"{number}: 404 Not Found []",
                is_error=True,
            )
        if args["method"] == "get":
            issue = dict(self.issues[number])
            if issue["comments"] == 0:
                del issue["comments"]  # omitempty
            return text_result(json.dumps(issue))
        assert args["method"] == "get_comments"
        page, per_page = int(args.get("page", 1)), int(args.get("perPage", 30))
        items = self.comments.get(number, [])[(page - 1) * per_page : page * per_page]
        return text_result(json.dumps(items))

    def _list_issues(self, args: dict[str, Any]) -> CallToolResult:
        assert args["orderBy"] == "CREATED_AT" and args["direction"] == "DESC"
        ordered = sorted(self.issues.values(), key=lambda i: i["number"], reverse=True)
        start = int(args.get("after", "0"))
        per_page = int(args["perPage"])
        page = ordered[start : start + per_page]
        end = start + len(page)
        issues = [
            {
                "number": i["number"],
                "title": i["title"],
                "body": i["body"],
                "state": "OPEN",
                "user": {"login": i["user"]["login"].removesuffix("[bot]")},
                "created_at": i["created_at"],
            }
            for i in page
        ]
        info = {
            "hasNextPage": end < len(ordered),
            "hasPreviousPage": start > 0,
            "startCursor": str(start),
            "endCursor": str(end),
        }
        payload = {"issues": issues, "totalCount": len(ordered), "pageInfo": info}
        return text_result(json.dumps(payload))

    def _search_issues(self, args: dict[str, Any]) -> CallToolResult:
        terms = args["query"].split(" ", 1)[1]
        visible = [
            i
            for n, i in sorted(self.issues.items())
            if terms in i["body"] and (self.search_index is None or n in self.search_index)
        ]
        items = [{"number": i["number"], "html_url": i["html_url"]} for i in visible]
        return text_result(
            json.dumps({"total_count": len(items), "incomplete_results": False, "items": items})
        )

    def _add_issue_comment(self, args: dict[str, Any]) -> CallToolResult:
        number = int(args["issue_number"])
        comment_id = self.add_comment(number, args["body"])
        url = f"{issue_url(number)}#issuecomment-{comment_id}"
        return text_result(json.dumps({"id": str(comment_id), "url": url}))


class FakeSession:
    def __init__(self, github: FakeGitHub, params: StdioServerParameters) -> None:
        self.github = github
        self.params = params
        self.key_snapshot: tuple[bool, int] | None = None

    def _snapshot_key(self) -> None:
        flag = next(a for a in self.params.args if a.startswith("--app-private-key-path="))
        key_path = Path(flag.split("=", 1)[1])
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        self.key_snapshot = (key_path.read_text() == TEST_PEM, mode)

    async def initialize(self) -> Any:
        self._snapshot_key()
        return SimpleNamespace(
            server_info=Implementation(name="github-mcp-server", version=self.github.server_version)
        )

    async def list_tools(self, *, params: PaginatedRequestParams | None = None) -> ListToolsResult:
        return ListToolsResult(tools=self.github.tools)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
    ) -> Any:
        await asyncio.sleep(0)
        return self.github.dispatch(name, dict(arguments or {}))


def factory_for(github: FakeGitHub) -> Any:
    @asynccontextmanager
    async def factory(params: StdioServerParameters, errlog: TextIO) -> AsyncIterator[FakeSession]:
        assert errlog.name == os.devnull
        github.params.append(params)
        session = FakeSession(github, params)
        github.sessions.append(session)
        yield session

    return factory


def make_publisher(
    github: FakeGitHub,
    private_root: Path,
    *,
    registry: c.ApplicationRegistry = REGISTRY,
    budget: BudgetPolicy | None = None,
    load_private_key: Callable[[], Any] | None = None,
    **kwargs: Any,
) -> McpPublisher:
    async def load() -> str:
        return TEST_PEM

    return McpPublisher(
        registry=registry,
        budget=budget or BudgetPolicy(),
        binary=Path("/opt/gms/github-mcp-server"),
        app_id="123456",
        load_private_key=load_private_key or load,
        author_login=kwargs.pop("author_login", BOT),
        private_root=private_root,
        session_factory=factory_for(github),
        **kwargs,
    )


def publish_request(
    report: c.InvestigationReport | None = None,
    *,
    alert: c.NormalizedAlert | None = None,
    repository: str = REPO,
    marker: str | None = None,
) -> PublishRequest:
    alert = alert or make_alert()
    return PublishRequest(
        alert=alert,
        report=report or complete_report(alert),
        repository=repository,
        sink=alert.sink,
        marker=marker or issue_marker(alert.incident_key),
        attempt=1,
    )


def recovery_request(number: int, *, marker: str | None = None) -> RecoveryRequest:
    resolved = make_alert("Resolved")
    key = resolved.incident_key
    record = c.PublicationRecord(
        repository=REPO,
        issue_number=number,
        issue_url=issue_url(number),
        incident_key=key,
        marker=issue_marker(key),
    )
    return RecoveryRequest(
        incident_key=key,
        resolved=resolved,
        publication=record,
        marker=marker or recovery_marker(key),
        attempt=1,
    )


def entries(root: Path) -> list[Path]:
    return sorted(root.iterdir())
