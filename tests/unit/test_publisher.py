"""McpPublisher semantics: verified writes, conservative uncertainty, bounded reconcile."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from azure_sre import contracts as c
from azure_sre.github.render import marker_comment
from azure_sre.state.records import issue_marker, recovery_marker
from azure_sre.worker import PublicationStatus
from tests.unit import test_publisher_support as support
from tests.unit.test_publisher_support import (
    BOT,
    REPO,
    FakeGitHub,
    entries,
    issue_url,
    make_publisher,
    publish_request,
    recovery_request,
    text_result,
)
from tests.unit.test_worker_support import complete_report, make_alert, make_registry

PUBLISHED = PublicationStatus.PUBLISHED
ABSENT = PublicationStatus.ABSENT
UNCERTAIN = PublicationStatus.UNCERTAIN


def body_for(key: str) -> str:
    return f"{marker_comment(issue_marker(key))}\n\n## Summary\n"


def assert_clean(root: Path) -> None:
    assert entries(root) == []


# --------------------------------------------------------------------------- publish


async def test_publish_creates_once_then_verifies_by_read(tmp_path: Path) -> None:
    gh = FakeGitHub()
    publisher = make_publisher(gh, tmp_path)
    request = publish_request()

    result = await publisher.publish(request)

    assert result.status is PUBLISHED and result.record is not None
    record = result.record
    assert record.repository == REPO and record.issue_number == 100
    assert record.issue_url == issue_url(100)
    assert record.marker == request.marker
    assert record.incident_key == request.alert.incident_key
    assert gh.writes() == ["issue_write"]
    assert [n for n, _ in gh.calls] == ["issue_write", "issue_read"]
    write_args = gh.calls[0][1]
    assert set(write_args) == {"owner", "repo", "method", "title", "body"}
    assert (write_args["owner"], write_args["repo"], write_args["method"]) == (
        "contoso",
        "shop",
        "create",
    )
    assert write_args["body"].split("\n", 1)[0] == f"<!-- {request.marker} -->"
    assert gh.calls[1][1]["method"] == "get"
    assert_clean(tmp_path)


async def test_publish_wrong_repository_in_response_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()
    gh.hooks["issue_write"] = lambda n, a: text_result(
        json.dumps({"id": "1", "url": "https://github.com/evil/shop/issues/100"})
    )
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is UNCERTAIN and result.reason == "create_wrong_repository"
    assert gh.writes() == ["issue_write"]


async def test_publish_verification_mismatch_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()

    def tamper(name: str, args: dict[str, Any]) -> None:
        gh.issues[100]["body"] = "no marker here"

    gh.after_hooks["issue_write"] = tamper
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is UNCERTAIN and result.reason == "verification_mismatch"


async def test_publish_pull_request_url_does_not_verify(tmp_path: Path) -> None:
    gh = FakeGitHub()

    def as_pull(name: str, args: dict[str, Any]) -> None:
        gh.issues[100]["html_url"] = f"https://github.com/{REPO}/pull/100"

    gh.after_hooks["issue_write"] = as_pull
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is UNCERTAIN


async def test_lost_create_response_is_uncertain_then_reconciles(tmp_path: Path) -> None:
    gh = FakeGitHub()

    def lose(name: str, args: dict[str, Any]) -> None:
        raise ConnectionResetError("stdio closed after write")

    gh.after_hooks["issue_write"] = lose
    publisher = make_publisher(gh, tmp_path)
    request = publish_request()

    first = await publisher.publish(request)
    assert first.status is UNCERTAIN and first.reason == "publish_interrupted"
    assert len(gh.issues) == 1  # the write did happen remotely

    reconciled = await publisher.reconcile(request)
    assert reconciled.status is PUBLISHED and reconciled.record is not None
    assert reconciled.record.issue_number == 100
    assert gh.writes() == ["issue_write"]  # reconcile never writes
    assert_clean(tmp_path)


async def test_read_failure_after_accepted_create_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()
    gh.hooks["issue_read"] = lambda n, a: text_result(
        "failed to get issue: GET https://api.github.com/repos/contoso/shop/issues/100: "
        "502 Bad Gateway []",
        is_error=True,
    )
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is UNCERTAIN and result.reason == "issue_read_failed"
    assert result.record is None


async def test_create_error_after_write_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()
    gh.hooks["issue_write"] = lambda n, a: text_result(
        "issue created but requested labels were not fully applied: missing labels", is_error=True
    )
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is UNCERTAIN and result.reason == "create_unconfirmed"


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        ("401 Requires authentication", "github_auth_denied"),
        ("403 Resource not accessible by integration", "github_auth_denied"),
        ("404 Not Found", "github_target_not_found"),
        ("410 Issues are disabled for this repo", "github_target_not_found"),
    ],
)
async def test_provable_pre_write_rejection_is_absent(
    tmp_path: Path, status: str, reason: str
) -> None:
    gh = FakeGitHub()
    gh.hooks["issue_write"] = lambda n, a: text_result(
        f"failed to create issue: POST https://api.github.com/repos/{REPO}/issues: {status} []",
        is_error=True,
    )
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is ABSENT and result.reason == reason and result.retryable is False


@pytest.mark.parametrize(
    "text",
    [
        "failed to create issue: Validation Failed\nbody is too long",  # reformatted 422
        "failed to create issue: context deadline exceeded",
        "failed to create issue: POST https://api.github.com/repos/contoso/shop/issues: "
        "502 Bad Gateway []",
        "failed to create issue: Something went wrong while executing your query.",
    ],
)
async def test_ambiguous_create_errors_are_uncertain(tmp_path: Path, text: str) -> None:
    gh = FakeGitHub()
    gh.hooks["issue_write"] = lambda n, a: text_result(text, is_error=True)
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is UNCERTAIN and result.reason == "create_unconfirmed"


async def test_rate_limited_create_is_uncertain_with_retry_after(tmp_path: Path) -> None:
    gh = FakeGitHub()
    gh.hooks["issue_write"] = lambda n, a: text_result(
        "failed to create issue: GitHub secondary rate limit exceeded. Retry after 1m30s.",
        is_error=True,
    )
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is UNCERTAIN and result.reason == "github_rate_limited"
    assert result.retry_after_seconds == 90


async def test_hung_create_times_out_uncertain_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gh = FakeGitHub()
    real = support.FakeSession.call_tool

    async def call_tool(self: Any, name: str, arguments: Any = None, **kw: Any) -> Any:
        if name == "issue_write":
            gh.calls.append((name, dict(arguments)))
            await asyncio.sleep(10)
        return await real(self, name, arguments, **kw)

    monkeypatch.setattr(support.FakeSession, "call_tool", call_tool)
    publisher = make_publisher(
        gh, tmp_path, operation_timeout_seconds=0.2, call_timeout_seconds=0.1
    )
    result = await publisher.publish(publish_request())
    assert result.status is UNCERTAIN and result.reason == "publish_timeout"
    assert gh.writes() == ["issue_write"]
    assert_clean(tmp_path)


async def test_setup_failure_before_write_is_retryable_absent(tmp_path: Path) -> None:
    gh = FakeGitHub()

    async def broken_vault() -> str:
        raise RuntimeError("vault down: secret=abc")

    publisher = make_publisher(gh, tmp_path, load_private_key=broken_vault)
    result = await publisher.publish(publish_request())
    assert result.status is ABSENT and result.reason == "private_key_unavailable"
    assert result.retryable is True
    assert gh.calls == [] and gh.sessions == []


async def test_schema_drift_blocks_before_any_call(tmp_path: Path) -> None:
    gh = FakeGitHub()
    gh.tools[2].input_schema["required"] = ["method", "owner", "repo", "title"]
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is ABSENT and result.reason == "mcp_schema_mismatch"
    assert result.retryable is False and gh.calls == []
    assert_clean(tmp_path)


async def test_server_version_drift_blocks(tmp_path: Path) -> None:
    gh = FakeGitHub(server_version="2.1.0")
    result = await make_publisher(gh, tmp_path).publish(publish_request())
    assert result.status is ABSENT and result.reason == "mcp_server_version_mismatch"
    assert gh.calls == []


async def test_test_sink_is_rejected_without_launch(tmp_path: Path) -> None:
    gh = FakeGitHub()
    alert = make_alert(sink=c.Sink.TEST)
    request = publish_request(alert=alert)
    publisher = make_publisher(gh, tmp_path)
    result = await publisher.publish(request)
    assert result.status is ABSENT and result.reason == "test_sink_rejected"
    assert result.retryable is False
    assert (await publisher.reconcile(request)).status is UNCERTAIN
    assert gh.sessions == []


async def test_repository_and_installation_must_match_trusted_registry(tmp_path: Path) -> None:
    gh = FakeGitHub()
    wrong_repo = publish_request(repository="contoso/other")
    result = await make_publisher(gh, tmp_path).publish(wrong_repo)
    assert result.status is ABSENT and result.reason == "repository_mismatch"

    drifted = c.ApplicationRegistry.model_validate(
        {
            **make_registry().model_dump(mode="json"),
            "applications": [
                {**make_registry().applications[0].model_dump(mode="json"), "installation_id": 7}
            ],
        }
    )
    result = await make_publisher(gh, tmp_path, registry=drifted).publish(publish_request())
    assert result.status is ABSENT and result.reason == "installation_mismatch"

    moved = make_registry("contoso/elsewhere")
    result = await make_publisher(gh, tmp_path, registry=moved).publish(publish_request())
    assert result.status is ABSENT and result.reason == "repository_mismatch"
    assert gh.sessions == []


async def test_wrong_marker_is_rejected(tmp_path: Path) -> None:
    gh = FakeGitHub()
    request = publish_request(marker="azure-sre:incident:" + "0" * 64)
    result = await make_publisher(gh, tmp_path).publish(request)
    assert result.status is ABSENT and result.reason == "marker_mismatch"


async def test_session_uses_registry_installation_and_private_env(tmp_path: Path) -> None:
    gh = FakeGitHub()
    await make_publisher(gh, tmp_path).publish(publish_request())
    (params,) = gh.params
    assert "--app-id=123456" in params.args and "--app-installation-id=42" in params.args
    assert gh.sessions[0].key_snapshot == (True, 0o600)


# --------------------------------------------------------------------------- reconcile


async def test_reconcile_complete_scan_without_match_is_absent(tmp_path: Path) -> None:
    gh = FakeGitHub()
    for _ in range(5):
        gh.add_issue("unrelated")
    result = await make_publisher(gh, tmp_path).reconcile(publish_request())
    assert result.status is ABSENT and result.reason == "not_found" and result.retryable
    assert gh.writes() == []


async def test_reconcile_finds_lowest_duplicate_and_is_idempotent(tmp_path: Path) -> None:
    gh = FakeGitHub()
    request = publish_request()
    key = request.alert.incident_key
    gh.add_issue("noise")
    first = gh.add_issue(body_for(key))
    gh.add_issue("noise")
    gh.add_issue(body_for(key))
    publisher = make_publisher(gh, tmp_path, reconcile_page_size=2)

    results = [await publisher.reconcile(request) for _ in range(2)]

    for result in results:
        assert result.status is PUBLISHED and result.record is not None
        assert result.record.issue_number == first
    assert gh.writes() == []


async def test_reconcile_ignores_marker_not_on_first_line(tmp_path: Path) -> None:
    gh = FakeGitHub()
    key = make_alert().incident_key
    gh.add_issue(f"quoted:\n{marker_comment(issue_marker(key))}\n")
    gh.add_issue(f" {marker_comment(issue_marker(key))}")
    result = await make_publisher(gh, tmp_path).reconcile(publish_request())
    assert result.status is ABSENT


async def test_reconcile_ignores_spoofed_marker_from_other_author(tmp_path: Path) -> None:
    gh = FakeGitHub()
    key = make_alert().incident_key
    gh.add_issue(body_for(key), author="mallory")
    publisher = make_publisher(gh, tmp_path, author_login=BOT)
    assert (await publisher.reconcile(publish_request())).status is ABSENT
    ours = gh.add_issue(body_for(key))
    result = await publisher.reconcile(publish_request())
    assert result.status is PUBLISHED and result.record is not None
    assert result.record.issue_number == ours


async def test_reconcile_incomplete_pagination_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()
    for _ in range(12):
        gh.add_issue("unrelated")
    publisher = make_publisher(gh, tmp_path, reconcile_page_size=2, reconcile_max_pages=3)
    result = await publisher.reconcile(publish_request())
    assert result.status is UNCERTAIN and result.reason == "reconcile_incomplete"
    assert [n for n, _ in gh.calls].count("list_issues") == 3
    assert "search_issues" in [n for n, _ in gh.calls]


async def test_reconcile_incomplete_scan_uses_search_hit(tmp_path: Path) -> None:
    gh = FakeGitHub()
    key = make_alert().incident_key
    old = gh.add_issue(body_for(key) + f"- **Incident key:** `{key}`\n")
    for _ in range(12):
        gh.add_issue("unrelated")
    publisher = make_publisher(gh, tmp_path, reconcile_page_size=2, reconcile_max_pages=2)
    result = await publisher.reconcile(publish_request())
    assert result.status is PUBLISHED and result.record is not None
    assert result.record.issue_number == old


async def test_reconcile_search_lag_never_means_absent(tmp_path: Path) -> None:
    gh = FakeGitHub(search_index=set())
    key = make_alert().incident_key
    gh.add_issue(body_for(key) + key)
    for _ in range(12):
        gh.add_issue("unrelated")
    publisher = make_publisher(gh, tmp_path, reconcile_page_size=2, reconcile_max_pages=2)
    result = await publisher.reconcile(publish_request())
    assert result.status is UNCERTAIN and result.reason == "reconcile_incomplete"


async def test_reconcile_read_errors_are_uncertain_with_rate_limit(tmp_path: Path) -> None:
    gh = FakeGitHub()
    gh.hooks["list_issues"] = lambda n, a: text_result(
        "failed to list issues: GitHub API rate limit exceeded. Retry after 45s.", is_error=True
    )
    result = await make_publisher(gh, tmp_path).reconcile(publish_request())
    assert result.status is UNCERTAIN and result.reason == "list_issues_failed"
    assert result.retry_after_seconds == 45


async def test_reconcile_unparseable_listing_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()
    gh.hooks["list_issues"] = lambda n, a: text_result(json.dumps({"issues": []}))
    result = await make_publisher(gh, tmp_path).reconcile(publish_request())
    assert result.status is UNCERTAIN


async def test_reconcile_candidate_that_fails_verification_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()
    key = make_alert().incident_key
    gh.add_issue(body_for(key))
    gh.hooks["issue_read"] = lambda n, a: text_result("boom", is_error=True)
    result = await make_publisher(gh, tmp_path).reconcile(publish_request())
    assert result.status is UNCERTAIN and result.reason == "candidate_unverified"


async def test_reconcile_transport_failure_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()

    def die(name: str, args: dict[str, Any]) -> None:
        raise BrokenPipeError

    gh.hooks["list_issues"] = die
    result = await make_publisher(gh, tmp_path).reconcile(publish_request())
    assert result.status is UNCERTAIN and result.reason == "reconcile_interrupted"
    assert_clean(tmp_path)


# --------------------------------------------------------------------------- recovery


async def test_recover_comments_once_and_verifies(tmp_path: Path) -> None:
    gh = FakeGitHub()
    number = gh.add_issue(body_for(make_alert().incident_key))
    request = recovery_request(number)
    result = await make_publisher(gh, tmp_path).recover(request)
    assert result.status is PUBLISHED and result.comment_id == 9000
    assert gh.writes() == ["add_issue_comment"]
    (comment,) = gh.comments[number]
    assert comment["body"].split("\n", 1)[0] == f"<!-- {recovery_marker(request.incident_key)} -->"
    assert "issue_write" not in [n for n, _ in gh.calls]  # never closes/updates
    assert gh.issues[number]["state"] == "open"


async def test_recover_lost_comment_response_then_reconcile(tmp_path: Path) -> None:
    gh = FakeGitHub()
    number = gh.add_issue(body_for(make_alert().incident_key))
    request = recovery_request(number)

    def lose(name: str, args: dict[str, Any]) -> None:
        raise TimeoutError

    gh.after_hooks["add_issue_comment"] = lose
    publisher = make_publisher(gh, tmp_path)
    first = await publisher.recover(request)
    assert first.status is UNCERTAIN and first.comment_id is None

    second = await publisher.reconcile_recovery(request)
    assert second.status is PUBLISHED and second.comment_id == 9000
    assert gh.writes() == ["add_issue_comment"]


async def test_reconcile_recovery_complete_scan_absent_and_incomplete_uncertain(
    tmp_path: Path,
) -> None:
    gh = FakeGitHub()
    number = gh.add_issue(body_for(make_alert().incident_key))
    for _ in range(250):
        gh.add_comment(number, "chatter")
    request = recovery_request(number)
    assert (await make_publisher(gh, tmp_path).reconcile_recovery(request)).status is ABSENT
    limited = make_publisher(gh, tmp_path, comment_max_pages=2)
    result = await limited.reconcile_recovery(request)
    assert result.status is UNCERTAIN and result.reason == "reconcile_incomplete"


async def test_recover_rejected_comment_is_absent(tmp_path: Path) -> None:
    gh = FakeGitHub()
    number = gh.add_issue(body_for(make_alert().incident_key))
    gh.hooks["add_issue_comment"] = lambda n, a: text_result(
        f"failed to create comment: POST https://api.github.com/repos/{REPO}/issues/"
        f"{number}/comments: 403 Resource not accessible by integration []",
        is_error=True,
    )
    result = await make_publisher(gh, tmp_path).recover(recovery_request(number))
    assert result.status is ABSENT and result.reason == "github_auth_denied"
    assert result.retryable is False


async def test_recover_comment_on_wrong_issue_is_uncertain(tmp_path: Path) -> None:
    gh = FakeGitHub()
    number = gh.add_issue(body_for(make_alert().incident_key))
    gh.hooks["add_issue_comment"] = lambda n, a: text_result(
        json.dumps({"id": "5", "url": f"{issue_url(999)}#issuecomment-5"})
    )
    result = await make_publisher(gh, tmp_path).recover(recovery_request(number))
    assert result.status is UNCERTAIN and result.reason == "comment_wrong_target"


async def test_recover_wrong_marker_rejected(tmp_path: Path) -> None:
    gh = FakeGitHub()
    number = gh.add_issue(body_for(make_alert().incident_key))
    request = recovery_request(number, marker=issue_marker(make_alert().incident_key))
    result = await make_publisher(gh, tmp_path).recover(request)
    assert result.status is ABSENT and result.reason == "marker_mismatch"
    assert gh.sessions == []


async def test_reconcile_recovery_requires_our_issue(tmp_path: Path) -> None:
    gh = FakeGitHub()
    number = gh.add_issue("someone else's issue")
    result = await make_publisher(gh, tmp_path).reconcile_recovery(recovery_request(number))
    assert result.status is UNCERTAIN and result.reason == "verification_mismatch"


# --------------------------------------------------------------------------- lifecycle


async def test_private_dir_removed_on_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gh = FakeGitHub()
    started = asyncio.Event()

    async def call_tool(self: Any, name: str, arguments: Any = None, **kw: Any) -> Any:
        started.set()
        await asyncio.sleep(30)

    monkeypatch.setattr(support.FakeSession, "call_tool", call_tool)
    task = asyncio.create_task(make_publisher(gh, tmp_path).publish(publish_request()))
    await started.wait()
    (private,) = entries(tmp_path)
    assert (private / "app-key.pem").exists()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert_clean(tmp_path)


async def test_private_dir_removed_after_error_and_success(tmp_path: Path) -> None:
    gh = FakeGitHub()
    gh.hooks["issue_read"] = lambda n, a: (_ for _ in ()).throw(RuntimeError("x"))
    await make_publisher(gh, tmp_path).publish(publish_request())
    assert_clean(tmp_path)
    gh.hooks.clear()
    await make_publisher(gh, tmp_path).publish(publish_request())
    assert_clean(tmp_path)


async def test_partial_host_report_publishes_with_gaps(tmp_path: Path) -> None:
    gh = FakeGitHub()
    alert = make_alert()
    base = complete_report(alert)
    report = c.InvestigationReport(
        schema_version=1,
        incident_key=alert.incident_key,
        alert_id=alert.alert_id,
        app_id=alert.app_id,
        severity=alert.severity,
        sink=alert.sink,
        generated_at=base.generated_at,
        status="partial",
        partial_category=c.PartialCategory.TIMEOUT,
        evidence=base.evidence,
        host_gaps=(
            c.ReportGap(description="Investigation timed out", category=c.PartialCategory.TIMEOUT),
        ),
    )
    result = await make_publisher(gh, tmp_path).publish(publish_request(report))
    assert result.status is PUBLISHED
    body = gh.issues[100]["body"]
    assert "Investigation timed out" in body and "[!WARNING]" in body
    assert gh.issues[100]["title"].startswith("[partial] [Sev2] shop (prod): ")


async def test_alert_must_bind_to_trusted_registry(tmp_path: Path) -> None:
    gh = FakeGitHub()
    alert = make_alert()
    forged = alert.model_copy(update={"tenant_id": "00000000-0000-0000-0000-000000000000"})
    request = publish_request(alert=alert).model_copy(update={"alert": forged})
    result = await make_publisher(gh, tmp_path).publish(request)
    assert result.status is ABSENT and result.reason == "alert_binding_registry_mismatch"
    assert result.retryable is False and gh.sessions == []


@pytest.mark.parametrize(
    "update",
    [{"severity": c.Severity.SEV0}, {"incident_key": "f" * 64}, {"app_id": "other"}],
)
async def test_report_must_match_alert(tmp_path: Path, update: dict[str, Any]) -> None:
    gh = FakeGitHub()
    request = publish_request()
    forged = request.model_copy(update={"report": request.report.model_copy(update=update)})
    result = await make_publisher(gh, tmp_path).publish(forged)
    assert result.status is ABSENT and result.reason == "report_mismatch"
    assert gh.sessions == []


async def test_recovery_publication_url_must_be_canonical(tmp_path: Path) -> None:
    gh = FakeGitHub()
    number = gh.add_issue(body_for(make_alert().incident_key))
    request = recovery_request(number)
    bad = request.publication.model_copy(update={"issue_url": issue_url(number, "evil/shop")})
    result = await make_publisher(gh, tmp_path).recover(
        request.model_copy(update={"publication": bad})
    )
    assert result.status is ABSENT and result.reason == "publication_mismatch"
    assert gh.sessions == []


@pytest.mark.parametrize("login", ["", "bad login", "<!--", "a" * 60])
def test_author_login_is_required_and_validated(tmp_path: Path, login: str) -> None:
    with pytest.raises(ValueError, match="author login"):
        make_publisher(FakeGitHub(), tmp_path, author_login=login)
