"""Host-owned Markdown rendering for incident issues and recovery comments.

Everything the model or Azure telemetry produced is *untrusted*: it is redacted,
collapsed to one line, stripped of control/invisible characters, URL-defanged,
HTML-escaped and Markdown-escaped, and ``@`` is replaced so it cannot mention anyone.
Untrusted text therefore can never create a heading, link, image, HTML comment (hidden
marker), table, mention or autolink. The host-owned hidden marker is always the exact
first line. The whole body is redacted again and must fit the UTF-8 byte budget;
truncation is explicit and never drops the Gaps section.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final

from azure_sre.contracts import (
    CONCLUSIVE_HOST_FINDING_CODES,
    EvidenceItem,
    InvestigationReport,
    NormalizedAlert,
    ReportGap,
    incident_window,
)
from azure_sre.github.recommendations import probe_recommendation_refs
from azure_sre.security.redaction import redact_text

__all__ = [
    "MAX_TITLE_CHARS",
    "RenderError",
    "escape_inline",
    "marker_comment",
    "render_issue_body",
    "render_issue_title",
    "render_recovery_comment",
    "starts_with_marker",
]

MAX_TITLE_CHARS: Final = 256
_MARKER_RE: Final = re.compile(r"^azure-sre:(?:incident|recovery|improvement):[0-9a-f]{64}$")
_URL_SCHEME_RE: Final = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,30}):(/{1,})")
_WWW_RE: Final = re.compile(r"(?i)\bwww\.")
_MD_SPECIALS: Final = frozenset("\\`*_{}[]()#!|~")
_WS_RE: Final = re.compile(r"\s+")
_ELLIPSIS: Final = "…"
_FULLWIDTH_AT: Final = "\uff20"  # renders like "@" but never mentions anyone


class RenderError(ValueError):
    """The publication cannot be rendered safely within the budget."""


def marker_comment(marker: str) -> str:
    if not _MARKER_RE.fullmatch(marker):
        raise RenderError("marker is not a host incident/recovery marker")
    return f"<!-- {marker} -->"


def starts_with_marker(body: object, marker: str) -> bool:
    """True iff the first line is exactly the host marker comment (``\\r\\n`` tolerated)."""
    if not isinstance(body, str):
        return False
    first = body.split("\n", 1)[0].removesuffix("\r")
    return first == marker_comment(marker)


def _plain(text: str, limit: int) -> str:
    """Redacted, normalized single line without control/invisible/format characters."""
    text = unicodedata.normalize("NFKC", redact_text(text))
    kept: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if char.isspace() or category in ("Zl", "Zp"):
            kept.append(" ")
        elif category[0] == "C":
            continue
        else:
            kept.append(char)
    line = _WS_RE.sub(" ", "".join(kept)).strip()
    line = _URL_SCHEME_RE.sub(lambda m: f"{m.group(1)}[:]{m.group(2)}", line)
    line = _WWW_RE.sub(lambda m: m.group(0)[:-1] + "[.]", line)
    line = line.replace("@", _FULLWIDTH_AT)
    if len(line) > limit:
        line = line[: max(limit - 1, 0)].rstrip() + _ELLIPSIS
    return line


def escape_inline(text: str, limit: int = 500) -> str:
    """Untrusted text -> inert single-line Markdown."""
    out: list[str] = []
    for char in _plain(text, limit):
        if char == "&":
            out.append("&amp;")
        elif char == "<":
            out.append("&lt;")
        elif char == ">":
            out.append("&gt;")
        elif char in _MD_SPECIALS:
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out) or "\\-"


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _refs(refs: Sequence[str], label: str = "evidence") -> str:
    # Evidence ids are contract-validated (^E[1-9][0-9]{0,2}$) and therefore inert.
    return f" _({label}: {', '.join(refs)})_" if refs else ""


def render_issue_title(alert: NormalizedAlert, report: InvestigationReport) -> str:
    summary = report.draft.summary if report.draft is not None else _finding_headline(report)
    prefix = ""
    if report.status == "partial":
        prefix = "[likely cause] " if report.conclusion == "conclusive" else "[partial] "
    head = f"{prefix}[{alert.severity.value}] {alert.app_id} ({alert.environment}): "
    # Titles are not rendered as HTML, but angle brackets are still neutralized so an
    # untrusted summary can never carry a lookalike of the host marker comment.
    safe = _plain(summary, MAX_TITLE_CHARS).replace("<", "\uff1c").replace(">", "\uff1e")
    title = head + safe
    if len(title) > MAX_TITLE_CHARS:
        title = title[: MAX_TITLE_CHARS - 1].rstrip() + _ELLIPSIS
    return title


def _finding_headline(report: InvestigationReport) -> str:
    strong = [f for f in report.host_findings if f.code in CONCLUSIVE_HOST_FINDING_CODES]
    findings = strong or list(report.host_findings)
    return findings[0].text if findings else "investigation incomplete"


@dataclass
class _Section:
    heading: str
    items: list[str]
    empty: str
    shown: int = 0

    def render(self, budget_label: str) -> list[str]:
        lines = [f"## {self.heading}", ""]
        if not self.items:
            lines.append(self.empty)
        else:
            lines.extend(self.items[: self.shown])
            omitted = len(self.items) - self.shown
            if omitted:
                lines.append(
                    f"- _{omitted} more item(s) omitted to fit the {budget_label} size limit._"
                )
        lines.append("")
        return lines


def _gap_line(gap: ReportGap, limit: int) -> str:
    return (
        f"- **{gap.category.value}**: {escape_inline(gap.description, limit)}"
        f"{_refs(gap.evidence_refs)}"
    )


def _gap_tiers(gaps: Sequence[ReportGap]) -> list[list[str]]:
    if not gaps:
        return [["_No gaps reported._"]]
    counts: dict[str, int] = {}
    for gap in gaps:
        counts[gap.category.value] = counts.get(gap.category.value, 0) + 1
    summary = [f"- **{cat}**: {n} gap(s)" for cat, n in sorted(counts.items())]
    summary.append("- _Gap details shortened to fit the size limit._")
    return [
        [_gap_line(g, 500) for g in gaps],
        [
            *(_gap_line(g, 120) for g in gaps),
            "- _Gap descriptions shortened to fit the size limit._",
        ],
        summary,
    ]


def _evidence_line(item: EvidenceItem) -> str:
    p = item.provenance
    parts = [
        f"- **{item.evidence_id}** · `{p.source.value}` · template `{p.template_id}`",
        f"scope {escape_inline(p.scope_ref, 120)}",
        f"window {_utc(p.window.start)} to {_utc(p.window.end)}",
        f"status `{item.status.value}`",
        f"rows {item.row_count}" + (" (truncated)" if item.truncated else ""),
    ]
    if item.error is not None:
        parts.append(f"error `{item.error.category.value}`")
        parts.append(escape_inline(item.error.message, 200))
    line = " · ".join(parts)
    if item.summary:
        line += f" — {escape_inline(item.summary, 300)}"
    return line


def _evidence_samples(item: EvidenceItem) -> list[str]:
    lines = [
        f"- **{item.evidence_id}** sample {index}: "
        f"{escape_inline(json.dumps(dict(row), sort_keys=True, ensure_ascii=False), 1000)}"
        for index, row in enumerate(item.rows[:3], start=1)
    ]
    if len(item.rows) > 3:
        lines.append(f"- **{item.evidence_id}**: additional rows omitted from this issue.")
    return lines


def render_issue_body(
    alert: NormalizedAlert,
    report: InvestigationReport,
    *,
    marker: str,
    max_bytes: int,
    window_before_minutes: int,
    window_after_minutes: int,
) -> str:
    """Fixed-template issue body, final-redacted, ``<= max_bytes`` UTF-8 bytes."""
    marker_line = marker_comment(marker)
    draft = report.draft
    budget_label = f"{max_bytes}-byte"
    window = incident_window(
        alert, before_minutes=window_before_minutes, after_minutes=window_after_minutes
    )

    banner: list[str] = []
    if report.status == "partial" and report.conclusion == "conclusive":
        category = report.partial_category.value if report.partial_category else "unknown"
        banner = [
            "> [!IMPORTANT]",
            f"> Likely cause identified; some evidence was unavailable (`{category}`). "
            "See **Host-verified findings**, **Hypotheses** and **Gaps**.",
            "",
        ]
    elif report.status == "partial":
        category = report.partial_category.value if report.partial_category else "unknown"
        banner = [
            "> [!WARNING]",
            f"> Partial investigation (`{category}`): findings may be incomplete. See **Gaps**.",
            "",
        ]
    alert_lines = [
        "## Alert",
        "",
        f"- **Application:** `{alert.app_id}` (`{alert.environment}`)",
        f"- **Severity:** {alert.severity.value} · **Signal:** {alert.signal_type.value}",
        f"- **Fired at:** {_utc(alert.fired_at)}",
        f"- **Investigation window:** {_utc(window.start)} to {_utc(window.end)}",
        f"- **Alert rule:** {escape_inline(alert.alert_rule or 'unknown', 200)}",
        f"- **Alert ID:** {escape_inline(alert.alert_id, 300)}",
        f"- **Incident key:** `{alert.incident_key}`",
        "",
    ]
    if draft is not None:
        summaries = [escape_inline(draft.summary, n) for n in (1000, 280, 80)]
    elif report.host_findings:
        summaries = [
            "_No model diagnosis was produced; see the host-verified findings below. "
            "This is a host-generated partial report._"
        ]
    else:
        summaries = ["_No diagnosis was produced; this is a host-generated partial report._"]

    gaps = [*(draft.gaps if draft else ()), *report.host_gaps]
    gap_tiers = _gap_tiers(gaps)

    def verdict(h_verdict: str) -> str:
        return {"supported": "Supported", "contradicted": "Contradicted"}.get(
            h_verdict, "Unverified"
        )

    sections = {
        "findings": _Section(
            "Host-verified findings",
            [f"- {escape_inline(f.text)}{_refs(f.evidence_refs)}" for f in report.host_findings],
            "_No deterministic findings._",
        ),
        "symptoms": _Section(
            "Symptoms",
            [
                f"- {escape_inline(s.text)}{_refs(s.evidence_refs)}"
                for s in (draft.symptoms if draft else ())
            ],
            "_None reported._",
        ),
        "timeline": _Section(
            "Timeline",
            [
                f"- **{escape_inline(e.at, 64)}** — {escape_inline(e.text)}{_refs(e.evidence_refs)}"
                for e in (draft.chronology if draft else ())
            ],
            "_None reported._",
        ),
        "observations": _Section(
            "Observations",
            [
                f"- {escape_inline(o.text)}{_refs(o.evidence_refs)}"
                for o in (draft.observations if draft else ())
            ],
            "_None reported._",
        ),
        "hypotheses": _Section(
            "Hypotheses",
            [
                f"- **{verdict(h.verdict)}:** {escape_inline(h.statement)}"
                f"{_refs(h.support_refs, 'supported by')}"
                f"{_refs(h.contradiction_refs, 'contradicted by')}"
                for h in (draft.hypotheses if draft else ())
            ],
            "_None reported._",
        ),
        "evidence": _Section(
            "Evidence provenance",
            [_evidence_line(i) for i in report.evidence.items],
            "_No evidence was collected._",
        ),
        "samples": _Section(
            "Collected evidence samples",
            [line for item in report.evidence.items for line in _evidence_samples(item)],
            "_No evidence rows were collected; see provenance and gaps._",
        ),
        "validation": _Section(
            "Model output validation",
            [
                f"- `{n.code.value}`: {escape_inline(n.detail, 300)}"
                for n in report.validation_notes
            ],
            "_No validation notes._",
        ),
        "actions": _Section(
            "Developer actions",
            [
                f"- [ ] {escape_inline(a.text)}{_refs(a.evidence_refs)}"
                for a in (draft.developer_actions if draft else ())
            ],
            "_None suggested._",
        ),
    }
    footer = [
        "---",
        "_Generated by Azure SRE Copilot from read-only diagnostics. Statements cite "
        "evidence IDs; model-written text is escaped and redacted._",
    ]

    state = {"summary": 0, "gaps": 0}

    def compose() -> str:
        lines = [marker_line, "", *banner, "## Summary", "", summaries[state["summary"]], ""]
        lines += sections["findings"].render(budget_label)
        lines += alert_lines
        order = ("symptoms", "timeline", "observations", "hypotheses")
        for key in order:
            lines += sections[key].render(budget_label)
        lines += ["## Gaps", "", *gap_tiers[state["gaps"]], ""]
        if report.validation_notes:
            lines += sections["validation"].render(budget_label)
        for key in ("samples", "evidence", "actions"):
            lines += sections[key].render(budget_label)
        lines += footer
        return redact_text("\n".join(lines) + "\n")

    def fits() -> bool:
        return len(compose().encode("utf-8")) <= max_bytes

    # Required content first: shrink gaps, then the summary, until the skeleton fits.
    while not fits():
        if state["gaps"] < len(gap_tiers) - 1:
            state["gaps"] += 1
        elif state["summary"] < len(summaries) - 1:
            state["summary"] += 1
        else:
            raise RenderError("issue body budget too small for required content")

    # Optional items in priority order; each section keeps its leading items.
    for key in (
        "findings",
        "samples",
        "hypotheses",
        "observations",
        "symptoms",
        "actions",
        "validation",
        "timeline",
        "evidence",
    ):
        _fill(sections[key], fits)

    body = compose()
    if not starts_with_marker(body, marker) or len(body.encode("utf-8")) > max_bytes:
        raise RenderError("rendered body failed final checks")
    return body


def _fill(section: _Section, fits: Callable[[], bool]) -> None:
    total = len(section.items)
    if total == 0:
        return
    section.shown = total
    if fits():
        return
    # With an omission notice present, size is monotonic in ``shown``.
    low, high = 0, total - 1
    while low < high:
        mid = (low + high + 1) // 2
        section.shown = mid
        if fits():
            low = mid
        else:
            high = mid - 1
    section.shown = low


def render_recovery_comment(resolved: NormalizedAlert, *, marker: str, max_bytes: int) -> str:
    resolved_at = _utc(resolved.resolved_at) if resolved.resolved_at else "unknown"
    lines = [
        marker_comment(marker),
        "",
        "## Alert resolved",
        "",
        f"- **Resolved at:** {resolved_at}",
        f"- **Application:** `{resolved.app_id}` (`{resolved.environment}`)",
        f"- **Severity:** {resolved.severity.value} · **Signal:** {resolved.signal_type.value}",
        f"- **Alert rule:** {escape_inline(resolved.alert_rule or 'unknown', 200)}",
        f"- **Incident key:** `{resolved.incident_key}`",
        "",
        "Azure Monitor reports this alert as resolved. The issue stays open for developer "
        "follow-up; Azure SRE Copilot never closes or edits issues.",
        "",
    ]
    body = redact_text("\n".join(lines))
    if not starts_with_marker(body, marker) or len(body.encode("utf-8")) > max_bytes:
        raise RenderError("recovery comment failed final checks")
    return body


def render_probe_improvement(
    alert: NormalizedAlert,
    report: InvestigationReport,
    *,
    marker: str,
    max_bytes: int,
) -> tuple[str, str]:
    refs = probe_recommendation_refs(report)
    if not refs:
        raise RenderError("no host-verified probe recommendation")
    title = (
        f"[suggested improvement] {alert.app_id} ({alert.environment}): "
        "review dependency-aware readiness probes"
    )
    lines = [
        marker_comment(marker),
        "",
        "## Suggested improvement",
        "",
        f"Review readiness probes for `{alert.app_id}` (`{alert.environment}`).",
        "Collected configuration shows TCP readiness probes or containers without explicit "
        "readiness probes. TCP probes establish only that a port accepts connections; "
        "they do not establish storage or other dependency health." + _refs(refs),
        "",
        "## Recommendation",
        "",
        "- Consider a bounded HTTP readiness endpoint that checks dependencies required to "
        "serve requests, with appropriate timeouts and failure thresholds.",
        "- Review platform-generated default probes before changing configuration.",
        "- HTTP probes alone do not prove dependency coverage; review the handler.",
        "- Keep liveness independent of transient dependency outages to avoid restart loops.",
        "",
        "## Context",
        "",
        f"- **Incident key:** `{alert.incident_key}`",
        "- This is a reliability suggestion, not a verified incident root cause.",
        "- No application code or Azure resources were modified.",
        "",
        "## Evidence",
        "",
        *[
            line
            for item in report.evidence.items
            if item.evidence_id in refs
            for line in _evidence_samples(item)
        ],
    ]
    body = redact_text("\n".join(lines) + "\n")
    if len(body.encode()) > max_bytes:
        # The recommendation and evidence references remain; only optional samples shrink.
        body = redact_text(
            "\n".join(lines[: lines.index("## Evidence")]) + "\n"
            "_Evidence samples omitted to fit the size limit._\n"
        )
    if len(body.encode()) > max_bytes or not starts_with_marker(body, marker):
        raise RenderError("improvement issue exceeds body budget")
    return title, body
