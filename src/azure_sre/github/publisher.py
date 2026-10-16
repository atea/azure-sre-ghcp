"""Application-owned GitHub issue publisher over the official GitHub MCP server.

Semantics (see ``docs/publication.md``):

* ``publish`` sends exactly one ``issue_write`` create, then verifies the issue by a
  separate ``issue_read`` (repository URL, number, exact first-line marker). Anything
  after the write was sent that is not verified is ``UNCERTAIN`` -- never ``ABSENT``.
  ``ABSENT`` is returned only when no write was sent (host validation, key/process
  setup) or GitHub provably rejected the write (REST 401/403/404/410/422 status).
* ``reconcile`` never writes: bounded ``list_issues`` scan (GraphQL listing, consistent,
  newest first) for the exact marker, verified by ``issue_read``. ``ABSENT`` only for a
  complete scan; incomplete scans try ``search_issues`` and otherwise stay ``UNCERTAIN``.
  Search results (indexing lag) are only ever used to *find*, never to conclude absence.
* ``recover`` sends exactly one ``add_issue_comment`` with a separate recovery marker and
  verifies it by reading comments; issues are never closed or edited.
* The worker owns persistence of intent and all retries.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

from azure_sre.config import BudgetPolicy
from azure_sre.contracts import (
    ApplicationMapping,
    ApplicationRegistry,
    NormalizedAlert,
    PublicationRecord,
    Sink,
)
from azure_sre.github.mcp_client import (
    InstallationResolver,
    McpSetupError,
    PublisherSession,
    SessionFactory,
    ToolResponse,
    discover_repository_installation,
    open_publisher_session,
    single_leaf,
    stdio_session_factory,
)
from azure_sre.github.recommendations import probe_recommendation_refs
from azure_sre.github.render import (
    RenderError,
    render_issue_body,
    render_issue_title,
    render_probe_improvement,
    render_recovery_comment,
    starts_with_marker,
)
from azure_sre.runtime.mcp_policy import McpPolicyError, RepositoryTarget
from azure_sre.state.records import improvement_marker, issue_marker, recovery_marker
from azure_sre.worker.messages import PoisonMessage, bind_alert
from azure_sre.worker.protocols import (
    MAX_RETRY_AFTER_SECONDS,
    PublicationStatus,
    PublishRequest,
    PublishResult,
    RecoveryRequest,
    RecoveryResult,
)

__all__ = ["McpPublisher", "PrivateKeyLoaderFn"]

PrivateKeyLoaderFn = Callable[[], Awaitable[str]]

_DEFINITIVE_WRITE_REJECTION: Final = re.compile(
    r"^failed to create (?:issue|comment): POST https://api\.github\.com/repos/"
    r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues(?:/[0-9]+/comments)?: (401|403|404|410|422) "
)
_RATE_LIMIT: Final = re.compile(r"(?i)rate limit exceeded")
_RETRY_AFTER: Final = re.compile(r"Retry after ((?:[0-9]+(?:\.[0-9]+)?(?:h|m|s|ms|us|µs|ns))+)\.")
_GO_DURATION_PART: Final = re.compile(r"([0-9]+(?:\.[0-9]+)?)(h|ms|us|µs|ns|m|s)")
_UNIT_SECONDS: Final = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 1e-3, "us": 1e-6, "µs": 1e-6}
_DEFAULT_RATE_LIMIT_RETRY: Final = 60.0
_COMMENTS_PER_PAGE: Final = 100


class _Rejected(Exception):
    """Host-side validation failure before any remote call (safe reason code)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class _Unverified(Exception):
    """Remote state could not be established (safe reason, optional retry hint)."""

    def __init__(self, reason: str, retry_after: float | None = None) -> None:
        self.reason = reason
        self.retry_after = retry_after
        super().__init__(reason)


@dataclass
class _Progress:
    write_sent: bool = False


@dataclass(frozen=True)
class _Issue:
    number: int
    html_url: str | None
    body: str | None
    author: str | None
    comments: int


def _parse_go_duration(text: str) -> float:
    total = 0.0
    for value, unit in _GO_DURATION_PART.findall(text):
        total += float(value) * _UNIT_SECONDS.get(unit, 0.0)
    return total


def _rate_limit_retry(text: str) -> float | None:
    if not _RATE_LIMIT.search(text):
        return None
    match = _RETRY_AFTER.search(text)
    seconds = _parse_go_duration(match.group(1)) if match else _DEFAULT_RATE_LIMIT_RETRY
    return min(max(math.ceil(seconds), 1.0), MAX_RETRY_AFTER_SECONDS)


def _definitive_rejection(text: str) -> str | None:
    """Reason code iff GitHub provably refused the write (no resource was created)."""
    if _RATE_LIMIT.search(text):
        return None
    match = _DEFINITIVE_WRITE_REJECTION.match(text)
    if match is None:
        return None
    return {
        "401": "github_auth_denied",
        "403": "github_auth_denied",
        "404": "github_target_not_found",
        "410": "github_target_not_found",
        "422": "github_validation_rejected",
    }[match.group(1)]


def _json(response: ToolResponse, what: str) -> Any:
    if response.is_error:
        raise _Unverified(f"{what}_failed", _rate_limit_retry(response.text))
    try:
        return json.loads(response.text)
    except ValueError as exc:
        raise _Unverified(f"{what}_unparseable") from exc


def _login(value: object) -> str | None:
    if isinstance(value, Mapping):
        login = value.get("login")
        if isinstance(login, str) and login:
            return login.removesuffix("[bot]").lower()
    return None


def _strict_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdecimal() and not value.startswith("0"):
        return int(value)
    return None


def _issue_from(obj: object) -> _Issue | None:
    if not isinstance(obj, Mapping):
        return None
    number = obj.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        return None
    comments = obj.get("comments", 0)
    if isinstance(comments, bool) or not isinstance(comments, int) or comments < 0:
        return None
    url = obj.get("html_url")
    body = obj.get("body")
    return _Issue(
        number=number,
        html_url=url if isinstance(url, str) else None,
        body=body if isinstance(body, str) else None,
        author=_login(obj.get("user")),
        comments=comments,
    )


_LOGIN_RE: Final = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$")


def _canonical_issue_url(repository: str, number: int) -> str:
    return f"https://github.com/{repository}/issues/{number}"


class McpPublisher:
    """``worker.protocols.Publisher`` over a fresh ``github-mcp-server`` per operation.

    ``app_id`` is the *GitHub App* ID (decimal). The installation is always taken from
    the trusted ``registry`` mapping of the alert's application -- never from the
    request alone -- and must agree with the alert snapshot and requested repository.
    """

    def __init__(
        self,
        *,
        registry: ApplicationRegistry,
        budget: BudgetPolicy,
        binary: Path,
        app_id: str,
        load_private_key: PrivateKeyLoaderFn,
        author_login: str,
        operation_timeout_seconds: float = 25.0,
        call_timeout_seconds: float = 10.0,
        startup_timeout_seconds: float = 10.0,
        reconcile_page_size: int = 50,
        reconcile_max_pages: int = 6,
        comment_max_pages: int = 10,
        reconcile_lookback: timedelta = timedelta(minutes=5),
        private_root: Path | None = None,
        session_factory: SessionFactory = stdio_session_factory,
        installation_resolver: InstallationResolver = discover_repository_installation,
    ) -> None:
        if not app_id.isdecimal():
            raise ValueError("GitHub App ID must be a decimal identifier.")
        if not _LOGIN_RE.fullmatch(author_login):
            raise ValueError("Publisher author login must be the GitHub App bot login.")
        if not binary.is_absolute():
            raise ValueError("GitHub MCP server binary path must be absolute.")
        if not 1 <= reconcile_page_size <= 100 or reconcile_max_pages < 1 or comment_max_pages < 1:
            raise ValueError("Reconcile bounds are invalid.")
        if not 0 < call_timeout_seconds <= operation_timeout_seconds:
            raise ValueError("Timeouts are invalid.")
        self._registry = registry
        self._budget = budget
        self._binary = binary
        self._app_id = app_id
        self._load_private_key = load_private_key
        self._author: str | None = author_login.removesuffix("[bot]").lower()
        self._operation_timeout = operation_timeout_seconds
        self._call_timeout = call_timeout_seconds
        self._startup_timeout = startup_timeout_seconds
        self._page_size = reconcile_page_size
        self._max_pages = reconcile_max_pages
        self._comment_pages = comment_max_pages
        self._lookback = reconcile_lookback
        self._private_root = private_root
        self._factory = session_factory
        self._installation_resolver = installation_resolver

    # ------------------------------------------------------------------ validation

    def _mapping(self, alert: NormalizedAlert, repository: str) -> ApplicationMapping:
        if alert.sink is not Sink.PRODUCTION:
            raise _Rejected("test_sink_rejected")
        mapping = self._registry.get(alert.app_id)
        if mapping is None:
            raise _Rejected("unknown_application")
        if not (mapping.repository == alert.repository == repository):
            raise _Rejected("repository_mismatch")
        if mapping.installation_id != alert.installation_id:
            raise _Rejected("installation_mismatch")
        try:
            # Full trusted binding: tenant, subscription, targets, incident/delivery ids.
            bind_alert(alert, self._registry)
        except PoisonMessage as exc:
            raise _Rejected(f"alert_binding_{exc.reason.value}") from None
        return mapping

    def _check_publish(self, request: PublishRequest) -> ApplicationMapping:
        if request.sink is not Sink.PRODUCTION:
            raise _Rejected("test_sink_rejected")
        alert, report = request.alert, request.report
        mapping = self._mapping(alert, request.repository)
        expected_marker = (
            improvement_marker(alert.incident_key)
            if request.purpose == "probe_improvement"
            else issue_marker(alert.incident_key)
        )
        if request.marker != expected_marker:
            raise _Rejected("marker_mismatch")
        if request.purpose == "probe_improvement" and not probe_recommendation_refs(report):
            raise _Rejected("recommendation_missing")
        if (
            report.alert_id != alert.alert_id
            or report.app_id != alert.app_id
            or report.incident_key != alert.incident_key
            or report.severity != alert.severity
            or report.sink is not alert.sink
            or report.evidence.incident_key != alert.incident_key
        ):
            raise _Rejected("report_mismatch")
        return mapping

    def _check_recovery(self, request: RecoveryRequest) -> ApplicationMapping:
        publication = request.publication
        mapping = self._mapping(request.resolved, publication.repository)
        if request.marker != recovery_marker(request.incident_key):
            raise _Rejected("marker_mismatch")
        if (
            publication.marker != issue_marker(request.incident_key)
            or publication.incident_key != request.incident_key
            or publication.issue_url
            != _canonical_issue_url(mapping.repository, publication.issue_number)
        ):
            raise _Rejected("publication_mismatch")
        return mapping

    # ------------------------------------------------------------------ plumbing

    @staticmethod
    def _target(mapping: ApplicationMapping) -> RepositoryTarget:
        owner, repo = mapping.repository.split("/", 1)
        return RepositoryTarget(owner=owner, repo=repo)

    async def _session_run[R](
        self,
        mapping: ApplicationMapping,
        body: Callable[[PublisherSession, _Progress], Awaitable[R]],
        progress: _Progress,
    ) -> R:
        async with asyncio.timeout(self._operation_timeout):
            try:
                return await self._open_and_run(mapping, body, progress)
            except BaseExceptionGroup as group:
                inner = single_leaf(group)
                if inner is None:
                    raise
                raise inner from None

    async def _open_and_run[R](
        self,
        mapping: ApplicationMapping,
        body: Callable[[PublisherSession, _Progress], Awaitable[R]],
        progress: _Progress,
    ) -> R:
        async with open_publisher_session(
            binary=self._binary,
            app_id=self._app_id,
            installation_id=mapping.installation_id,
            load_private_key=self._load_private_key,
            target=self._target(mapping),
            factory=self._factory,
            startup_timeout_seconds=self._startup_timeout,
            call_timeout_seconds=self._call_timeout,
            private_root=self._private_root,
            installation_resolver=self._installation_resolver,
        ) as session:
            return await body(session, progress)

    def _owner_repo(self, session: PublisherSession) -> dict[str, Any]:
        return {"owner": session.target.owner, "repo": session.target.repo}

    def _is_ours(self, author: str | None) -> bool:
        return self._author is None or author == self._author

    async def _read_issue(self, session: PublisherSession, number: int) -> _Issue:
        response = await session.call(
            "issue_read", {**self._owner_repo(session), "method": "get", "issue_number": number}
        )
        issue = _issue_from(_json(response, "issue_read"))
        if issue is None:
            raise _Unverified("issue_read_unparseable")
        return issue

    async def _verify_issue(
        self, session: PublisherSession, number: int, repository: str, marker: str
    ) -> _Issue:
        issue = await self._read_issue(session, number)
        expected = _canonical_issue_url(repository, number)
        if (
            issue.number != number
            or issue.html_url is None
            or issue.html_url.lower() != expected.lower()
            or not starts_with_marker(issue.body, marker)
            or not self._is_ours(issue.author)
        ):
            raise _Unverified("verification_mismatch")
        return issue

    def _record(self, repository: str, number: int, key: str, marker: str) -> PublicationRecord:
        return PublicationRecord(
            repository=repository,
            issue_number=number,
            issue_url=_canonical_issue_url(repository, number),
            incident_key=key,
            marker=marker,
        )

    # ------------------------------------------------------------------ publish

    async def publish(self, request: PublishRequest) -> PublishResult:
        try:
            mapping = self._check_publish(request)
            if request.purpose == "probe_improvement":
                title, body = render_probe_improvement(
                    request.alert,
                    request.report,
                    marker=request.marker,
                    max_bytes=self._budget.issue_body_bytes,
                )
            else:
                title = render_issue_title(request.alert, request.report)
                body = render_issue_body(
                    request.alert,
                    request.report,
                    marker=request.marker,
                    max_bytes=self._budget.issue_body_bytes,
                    window_before_minutes=self._budget.window_before_minutes,
                    window_after_minutes=self._budget.window_after_minutes,
                )
        except _Rejected as exc:
            return _absent(exc.reason, retryable=False)
        except RenderError:
            return _absent("render_failed", retryable=False)

        async def run(session: PublisherSession, progress: _Progress) -> PublishResult:
            args = {**self._owner_repo(session), "method": "create", "title": title, "body": body}
            progress.write_sent = True
            response = await session.call("issue_write", args)
            if response.is_error:
                rejected = _definitive_rejection(response.text)
                if rejected is not None:
                    return _absent(rejected, retryable=False)
                retry = _rate_limit_retry(response.text)
                reason = "github_rate_limited" if retry is not None else "create_unconfirmed"
                return _uncertain(reason, retry)
            number = self._created_issue_number(response, request.repository)
            await self._verify_issue(session, number, request.repository, request.marker)
            record = self._record(
                request.repository, number, request.alert.incident_key, request.marker
            )
            return PublishResult(status=PublicationStatus.PUBLISHED, record=record)

        return await self._guard_publish(mapping, run)

    def _created_issue_number(self, response: ToolResponse, repository: str) -> int:
        created = _json(response, "issue_write")
        url = created.get("url") if isinstance(created, Mapping) else None
        if not isinstance(url, str):
            raise _Unverified("create_response_unparseable")
        prefix = f"https://github.com/{repository}/issues/"
        if not url.lower().startswith(prefix.lower()):
            raise _Unverified("create_wrong_repository")
        number = _strict_int(url[len(prefix) :])
        if number is None:
            raise _Unverified("create_response_unparseable")
        return number

    async def _guard_publish(
        self,
        mapping: ApplicationMapping,
        run: Callable[[PublisherSession, _Progress], Awaitable[PublishResult]],
    ) -> PublishResult:
        progress = _Progress()
        try:
            return await self._session_run(mapping, run, progress)
        except _Unverified as exc:
            return _uncertain(exc.reason, exc.retry_after)
        except McpSetupError as exc:
            return _absent(exc.code, retryable=exc.retryable)
        except McpPolicyError:
            if progress.write_sent:
                return _uncertain("policy_rejected_after_write")
            return _absent("policy_rejected", retryable=False)
        except TimeoutError:
            if progress.write_sent:
                return _uncertain("publish_timeout")
            return _absent("mcp_timeout", retryable=True)
        except Exception:  # noqa: BLE001 - outcome unknown; never leak raw error text
            if progress.write_sent:
                return _uncertain("publish_interrupted")
            return _absent("mcp_unavailable", retryable=True)

    # ------------------------------------------------------------------ reconcile

    async def reconcile(self, request: PublishRequest) -> PublishResult:
        try:
            mapping = self._check_publish(request)
        except _Rejected as exc:
            return _uncertain(exc.reason, retryable=False)
        since = (request.alert.fired_at - self._lookback).astimezone(UTC)

        async def run(session: PublisherSession, _: _Progress) -> PublishResult:
            candidates, complete = await self._scan_issues(session, request.marker, since)
            numbers = sorted(candidates)
            if not numbers and not complete:
                numbers = await self._search_candidates(session, request.alert.incident_key)
            for number in numbers[:3]:
                try:
                    await self._verify_issue(session, number, request.repository, request.marker)
                except _Unverified:
                    continue
                record = self._record(
                    request.repository, number, request.alert.incident_key, request.marker
                )
                return PublishResult(status=PublicationStatus.PUBLISHED, record=record)
            if numbers:
                return _uncertain("candidate_unverified")
            if complete:
                return _absent("not_found", retryable=True)
            return _uncertain("reconcile_incomplete")

        return await self._guard_read(mapping, run)

    async def _scan_issues(
        self, session: PublisherSession, marker: str, since: datetime
    ) -> tuple[set[int], bool]:
        """Newest-first listing back to ``since``. Returns (marker matches, complete)."""
        found: set[int] = set()
        after: str | None = None
        since_text = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        for _ in range(self._max_pages):
            args: dict[str, Any] = {
                **self._owner_repo(session),
                "orderBy": "CREATED_AT",
                "direction": "DESC",
                "since": since_text,
                "perPage": self._page_size,
            }
            if after:
                args["after"] = after
            page = _json(await session.call("list_issues", args), "list_issues")
            issues = page.get("issues") if isinstance(page, Mapping) else None
            info = page.get("pageInfo") if isinstance(page, Mapping) else None
            if not isinstance(issues, list) or not isinstance(info, Mapping):
                raise _Unverified("list_issues_unparseable")
            for raw in issues:
                issue = _issue_from(raw)
                if issue is None:
                    raise _Unverified("list_issues_unparseable")
                if starts_with_marker(issue.body, marker) and self._is_ours(issue.author):
                    found.add(issue.number)
            has_next = info.get("hasNextPage")
            cursor = info.get("endCursor")
            if has_next is False:
                return found, True
            if has_next is not True or not isinstance(cursor, str) or not cursor:
                raise _Unverified("list_issues_unparseable")
            after = cursor
        return found, False

    async def _search_candidates(self, session: PublisherSession, incident_key: str) -> list[int]:
        """Search may lag behind writes: hits are candidates only, misses mean nothing."""
        query = f"repo:{session.target.owner}/{session.target.repo} {incident_key}"
        try:
            result = _json(
                await session.call("search_issues", {"query": query, "perPage": 10}),
                "search_issues",
            )
        except _Unverified:
            return []
        items = result.get("items") if isinstance(result, Mapping) else None
        if not isinstance(items, list):
            return []
        numbers = {i.number for i in map(_issue_from, items) if i is not None}
        return sorted(numbers)

    async def _guard_read(
        self,
        mapping: ApplicationMapping,
        run: Callable[[PublisherSession, _Progress], Awaitable[PublishResult]],
    ) -> PublishResult:
        try:
            return await self._session_run(mapping, run, _Progress())
        except _Unverified as exc:
            return _uncertain(exc.reason, exc.retry_after)
        except McpSetupError as exc:
            return _uncertain(exc.code, retryable=exc.retryable)
        except McpPolicyError:
            return _uncertain("policy_rejected", retryable=False)
        except TimeoutError:
            return _uncertain("reconcile_timeout")
        except Exception:  # noqa: BLE001 - reads failing are never evidence of absence
            return _uncertain("reconcile_interrupted")

    # ------------------------------------------------------------------ recovery

    async def recover(self, request: RecoveryRequest) -> RecoveryResult:
        try:
            mapping = self._check_recovery(request)
            body = render_recovery_comment(
                request.resolved, marker=request.marker, max_bytes=self._budget.issue_body_bytes
            )
        except _Rejected as exc:
            return _r_absent(exc.reason, retryable=False)
        except RenderError:
            return _r_absent("render_failed", retryable=False)
        number = request.publication.issue_number
        repository = request.publication.repository

        async def run(session: PublisherSession, progress: _Progress) -> RecoveryResult:
            args = {**self._owner_repo(session), "issue_number": number, "body": body}
            progress.write_sent = True
            response = await session.call("add_issue_comment", args)
            if response.is_error:
                rejected = _definitive_rejection(response.text)
                if rejected is not None:
                    return _r_absent(rejected, retryable=False)
                retry = _rate_limit_retry(response.text)
                reason = "github_rate_limited" if retry is not None else "comment_unconfirmed"
                return _r_uncertain(reason, retry)
            comment_id = self._created_comment_id(response, repository, number)
            matches, _ = await self._scan_comments(session, number, request.marker)
            if comment_id not in matches:
                raise _Unverified("verification_mismatch")
            return RecoveryResult(status=PublicationStatus.PUBLISHED, comment_id=comment_id)

        progress = _Progress()
        try:
            return await self._session_run(mapping, run, progress)
        except _Unverified as exc:
            return _r_uncertain(exc.reason, exc.retry_after)
        except McpSetupError as exc:
            return _r_absent(exc.code, retryable=exc.retryable)
        except McpPolicyError:
            if progress.write_sent:
                return _r_uncertain("policy_rejected_after_write")
            return _r_absent("policy_rejected", retryable=False)
        except TimeoutError:
            if progress.write_sent:
                return _r_uncertain("recover_timeout")
            return _r_absent("mcp_timeout", retryable=True)
        except Exception:  # noqa: BLE001 - outcome unknown; never leak raw error text
            if progress.write_sent:
                return _r_uncertain("recover_interrupted")
            return _r_absent("mcp_unavailable", retryable=True)

    @staticmethod
    def _created_comment_id(response: ToolResponse, repository: str, number: int) -> int:
        created = _json(response, "add_issue_comment")
        if not isinstance(created, Mapping):
            raise _Unverified("comment_response_unparseable")
        comment_id = _strict_int(created.get("id"))
        url = created.get("url")
        expected = f"{_canonical_issue_url(repository, number)}#issuecomment-{comment_id}"
        if comment_id is None or not isinstance(url, str):
            raise _Unverified("comment_response_unparseable")
        if url.lower() != expected.lower():
            raise _Unverified("comment_wrong_target")
        return comment_id

    async def _scan_comments(
        self, session: PublisherSession, number: int, marker: str
    ) -> tuple[list[int], bool]:
        """Ascending REST pages until a short page. Returns (marker comment ids, complete)."""
        found: list[int] = []
        for page in range(1, self._comment_pages + 1):
            args = {
                **self._owner_repo(session),
                "method": "get_comments",
                "issue_number": number,
                "page": page,
                "perPage": _COMMENTS_PER_PAGE,
            }
            comments = _json(await session.call("issue_read", args), "get_comments")
            if not isinstance(comments, list):
                raise _Unverified("get_comments_unparseable")
            for raw in comments:
                if not isinstance(raw, Mapping):
                    raise _Unverified("get_comments_unparseable")
                comment_id = raw.get("id")
                if isinstance(comment_id, bool) or not isinstance(comment_id, int):
                    raise _Unverified("get_comments_unparseable")
                if starts_with_marker(raw.get("body"), marker) and self._is_ours(
                    _login(raw.get("user"))
                ):
                    found.append(comment_id)
            if len(comments) < _COMMENTS_PER_PAGE:
                return found, True
        return found, False

    async def reconcile_recovery(self, request: RecoveryRequest) -> RecoveryResult:
        try:
            mapping = self._check_recovery(request)
        except _Rejected as exc:
            return _r_uncertain(exc.reason, retryable=False)
        number = request.publication.issue_number
        repository = request.publication.repository

        async def run(session: PublisherSession, _: _Progress) -> RecoveryResult:
            await self._verify_issue(session, number, repository, request.publication.marker)
            matches, complete = await self._scan_comments(session, number, request.marker)
            positive = [m for m in matches if m > 0]
            if positive:
                return RecoveryResult(status=PublicationStatus.PUBLISHED, comment_id=min(positive))
            if complete:
                return RecoveryResult(status=PublicationStatus.ABSENT, reason="not_found")
            return _r_uncertain("reconcile_incomplete")

        try:
            return await self._session_run(mapping, run, _Progress())
        except _Unverified as exc:
            return _r_uncertain(exc.reason, exc.retry_after)
        except McpSetupError as exc:
            return _r_uncertain(exc.code, retryable=exc.retryable)
        except McpPolicyError:
            return _r_uncertain("policy_rejected", retryable=False)
        except TimeoutError:
            return _r_uncertain("reconcile_timeout")
        except Exception:  # noqa: BLE001 - reads failing are never evidence of absence
            return _r_uncertain("reconcile_interrupted")


def _absent(reason: str, *, retryable: bool) -> PublishResult:
    return PublishResult(status=PublicationStatus.ABSENT, reason=reason, retryable=retryable)


def _uncertain(
    reason: str, retry_after: float | None = None, *, retryable: bool = True
) -> PublishResult:
    return PublishResult(
        status=PublicationStatus.UNCERTAIN,
        reason=reason,
        retryable=retryable,
        retry_after_seconds=retry_after,
    )


def _r_absent(reason: str, *, retryable: bool) -> RecoveryResult:
    return RecoveryResult(status=PublicationStatus.ABSENT, reason=reason, retryable=retryable)


def _r_uncertain(
    reason: str, retry_after: float | None = None, *, retryable: bool = True
) -> RecoveryResult:
    return RecoveryResult(
        status=PublicationStatus.UNCERTAIN,
        reason=reason,
        retryable=retryable,
        retry_after_seconds=retry_after,
    )
