"""Host-owned issue template: escaping, redaction and the UTF-8 byte budget."""

from __future__ import annotations

import re
from typing import Any

import pytest

from azure_sre import contracts as c
from azure_sre.github.render import (
    MAX_TITLE_CHARS,
    RenderError,
    escape_inline,
    marker_comment,
    render_issue_body,
    render_issue_title,
    render_recovery_comment,
    starts_with_marker,
)
from azure_sre.state.records import issue_marker, recovery_marker
from tests.unit.test_worker_support import complete_report, make_alert

KIB24 = 24 * 1024
SECTIONS = (
    "## Summary",
    "## Alert",
    "## Symptoms",
    "## Timeline",
    "## Observations",
    "## Hypotheses",
    "## Gaps",
    "## Collected evidence samples",
    "## Evidence provenance",
    "## Developer actions",
)


def report_with(alert: c.NormalizedAlert, **draft: Any) -> c.InvestigationReport:
    base = complete_report(alert)
    status = draft.pop("status", "complete")
    fields: dict[str, Any] = {"status": status, "summary": "5xx spike", **draft}
    return c.InvestigationReport(
        schema_version=1,
        incident_key=alert.incident_key,
        alert_id=alert.alert_id,
        app_id=alert.app_id,
        severity=alert.severity,
        sink=alert.sink,
        generated_at=base.generated_at,
        status=status,
        partial_category=c.PartialCategory.BUDGET_EXHAUSTED if status == "partial" else None,
        evidence=base.evidence,
        draft=c.ModelReportDraft(**fields),
    )


def render(report: c.InvestigationReport, max_bytes: int = KIB24) -> str:
    alert = make_alert()
    return render_issue_body(
        alert,
        report,
        marker=issue_marker(alert.incident_key),
        max_bytes=max_bytes,
        window_before_minutes=30,
        window_after_minutes=5,
    )


def big_report(char: str = "x", count: int = 60) -> c.InvestigationReport:
    alert = make_alert()
    text = (char * 480)[:480]
    return report_with(
        alert,
        status="partial",
        symptoms=tuple(
            c.ReportSymptom(text=f"s{i} {text}", evidence_refs=("E1",)) for i in range(count)
        ),
        chronology=tuple(
            c.ChronologyEntry(at="06:00Z", text=f"t{i} {text}", evidence_refs=("E1",))
            for i in range(count)
        ),
        observations=tuple(
            c.Observation(text=f"o{i} {text}", evidence_refs=("E1",)) for i in range(count)
        ),
        hypotheses=tuple(
            c.Hypothesis(statement=f"h{i} {text}", support_refs=("E1",), verdict="supported")
            for i in range(count)
        ),
        developer_actions=tuple(c.DeveloperAction(text=f"a{i} {text}") for i in range(count)),
        gaps=(
            c.ReportGap(description="GAP-ONE kusto timed out", category=c.PartialCategory.TIMEOUT),
            c.ReportGap(
                description="GAP-TWO permission denied",
                category=c.PartialCategory.PERMISSION_DENIED,
            ),
        ),
    )


def test_fixed_template_sections_in_order_with_marker_first() -> None:
    alert = make_alert()
    body = render(complete_report(alert))
    lines = body.split("\n")
    assert lines[0] == f"<!-- {issue_marker(alert.incident_key)} -->"
    positions = [body.index(f"\n{h}\n") for h in SECTIONS]
    assert positions == sorted(positions)
    assert body.count("<!--") == 1 and body.count("-->") == 1
    assert "shop" in body and "Sev2" in body and alert.incident_key in body
    assert "2026-10-13T05:30:00Z" in body  # trusted window start (fired - 30m)


def test_untrusted_text_cannot_inject_markup_markers_mentions_or_links() -> None:
    alert = make_alert()
    evil = (
        f"<!-- {issue_marker(alert.incident_key)} --> ## Fake heading\n# H1\n"
        "@octocat @org/team <img src=x onerror=alert(1)> [click](https://evil.example/x) "
        "www.evil.example javascript:alert(1) ![i](http://e/x.png) `code` <details>"
        "\u202e\u200b"
    )
    report = report_with(
        alert,
        summary=evil[:1000],
        observations=(c.Observation(text=evil[:500], evidence_refs=("E1",)),),
        developer_actions=(c.DeveloperAction(text=evil[:500]),),
    )
    body = render(report)
    title = render_issue_title(alert, report)

    assert body.count("<!--") == 1 and body.split("\n", 1)[0].startswith("<!--")
    assert "<img" not in body and "<details>" not in body
    assert "https://" not in body and "http://" not in body and "www." not in body
    assert re.search(r"(?<![\w\uff20])@[A-Za-z]", body) is None
    assert "](" not in body.replace("\\](", "").replace("\\]\\(", "")
    assert "\u202e" not in body and "\u200b" not in body
    headings = [line for line in body.split("\n") if line.startswith("#")]
    assert all(h in SECTIONS for h in headings)
    assert "\n" not in title and "<!--" not in title and "@" not in title


def test_redaction_reapplied_to_body_title_and_comment() -> None:
    alert = make_alert()
    token = "ghp_" + "A" * 36
    report = report_with(
        alert,
        summary=f"leak {token} ops@contoso.com",
        observations=(c.Observation(text=f"password={token}", evidence_refs=("E1",)),),
    )
    body = render(report)
    title = render_issue_title(alert, report)
    for text in (body, title):
        assert token not in text and "contoso.com" not in text and "ops@" not in text
    assert "REDACTED" in body and "REDACTED" in title
    resolved = make_alert("Resolved")
    comment = render_recovery_comment(
        resolved, marker=recovery_marker(resolved.incident_key), max_bytes=KIB24
    )
    assert comment.split("\n", 1)[0] == f"<!-- {recovery_marker(resolved.incident_key)} -->"
    assert "resolved" in comment.lower() and "stays open" in comment.lower()


def test_title_bounded_to_256_chars() -> None:
    alert = make_alert()
    report = report_with(alert, summary="é" * 1000, status="partial")
    title = render_issue_title(alert, report)
    assert len(title) <= MAX_TITLE_CHARS and title.endswith("…")
    assert title.startswith("[partial] [Sev2] shop (prod): ")


def test_exact_byte_boundary() -> None:
    report = big_report(count=3)
    full = render(report, max_bytes=10 * KIB24)
    size = len(full.encode())
    assert "omitted" not in full
    assert render(report, max_bytes=size) == full
    smaller = render(report, max_bytes=size - 1)
    assert len(smaller.encode()) <= size - 1
    assert "omitted to fit the" in smaller


@pytest.mark.parametrize("char", ["x", "é", "漢", "😀"])
def test_multibyte_body_capped_at_24kib_and_keeps_gaps(char: str) -> None:
    body = render(big_report(char))
    encoded = body.encode("utf-8")
    assert len(encoded) <= KIB24
    assert encoded.decode("utf-8") == body
    assert "GAP-ONE" in body and "GAP-TWO" in body
    assert "omitted to fit the 24576-byte size limit" in body
    assert body.split("\n", 1)[0].startswith("<!-- azure-sre:incident:")
    assert all(f"\n{h}\n" in body for h in SECTIONS)


def test_tight_budget_degrades_gaps_but_never_drops_them() -> None:
    alert = make_alert()
    gaps = tuple(
        c.ReportGap(description=f"gap {i} " + "y" * 480, category=c.PartialCategory.TIMEOUT)
        for i in range(40)
    )
    report = report_with(alert, status="partial", gaps=gaps)
    body = render(report, max_bytes=4096)
    assert len(body.encode()) <= 4096
    assert "timeout" in body and "40" in body  # count tier still accounts for every gap


def test_impossible_budget_raises() -> None:
    with pytest.raises(RenderError):
        render(complete_report(make_alert()), max_bytes=200)


def test_marker_helpers() -> None:
    marker = issue_marker(make_alert().incident_key)
    assert starts_with_marker(f"{marker_comment(marker)}\r\nbody", marker)
    assert not starts_with_marker(f" {marker_comment(marker)}", marker)
    assert not starts_with_marker(None, marker)
    with pytest.raises(RenderError):
        marker_comment("azure-sre:incident:--> <b>")


def test_sdk_failure_issue_keeps_error_samples_without_a_diagnosis() -> None:
    from azure_sre.worker.processor import host_partial_report

    alert = make_alert()
    base = complete_report(alert)
    item = base.evidence.items[0]
    secret = "ghp_" + "A" * 36
    item = c.EvidenceItem.model_validate(
        {
            **item.model_dump(),
            "rows": [
                {
                    "Log_s": f"Failed to resolve storage.table.core.windows.net {secret} "
                    "<!-- fake --> @octocat\n## forged"
                }
            ],
            "row_count": 1,
        }
    )
    report = c.InvestigationReport.model_validate(
        {
            **host_partial_report(
                alert, c.PartialCategory.SDK_ERROR, base.generated_at
            ).model_dump(),
            "evidence": c.EvidenceBundle(incident_key=alert.incident_key, items=(item,)),
        }
    )
    body = render(report)
    assert "sdk_error" in body
    assert "No diagnosis was produced" in body
    assert "Failed to resolve storage.table.core.windows.net" in body
    assert "**E1** sample 1" in body
    assert secret not in body
    assert body.count("<!--") == 1
    assert "@octocat" not in body
    assert "\n## forged" not in body
    assert len(body.encode()) <= KIB24


def test_escape_inline_entities_and_specials() -> None:
    assert escape_inline("a<b>&c *d* #e [f](g)") == "a&lt;b&gt;&amp;c \\*d\\* \\#e \\[f\\]\\(g\\)"
    assert escape_inline("") == "\\-"
