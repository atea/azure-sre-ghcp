from __future__ import annotations

from typing import Any

from azure_sre import contracts as c
from azure_sre.contracts import EvidenceStatus, ValidationNoteCode
from azure_sre.diagnostics.templates import DiagnosticKind
from azure_sre.investigation.salvage import salvage_draft
from tests.unit.test_investigation import make_item


def bundle() -> c.EvidenceBundle:
    ok = make_item(kind=DiagnosticKind.CONTAINER_APP_HEALTH)
    failed = make_item(
        rows=(), kind=DiagnosticKind.CONTAINER_APP_CONSOLE_ERRORS, status=EvidenceStatus.ERROR
    )
    return c.EvidenceBundle(
        incident_key="a" * 64,
        items=(ok, c.EvidenceItem.model_validate({**failed.model_dump(), "evidence_id": "E2"})),
    )


def salvage(document: dict[str, Any]) -> tuple[c.ModelReportDraft | None, list[str]]:
    draft, notes = salvage_draft(document, bundle())
    if draft is not None:
        c.validate_model_output(draft.model_dump(mode="json"), bundle())
    return draft, [code.value for code, _ in notes]


def hypothesis(
    verdict: str, support: list[str], against: list[str] | None = None
) -> dict[str, Any]:
    return {
        "statement": "Storage DNS fails.",
        "support_refs": support,
        "contradiction_refs": against or [],
        "verdict": verdict,
    }


def test_supported_hypothesis_on_failed_evidence_is_downgraded() -> None:
    draft, notes = salvage({"summary": "s", "hypotheses": [hypothesis("supported", ["E2"])]})
    assert draft is not None
    assert draft.hypotheses[0].verdict == "unverified"
    assert draft.hypotheses[0].support_refs == ("E2",)
    assert notes == [ValidationNoteCode.DOWNGRADED.value]


def test_supported_hypothesis_keeps_ok_support_and_drops_failed_refs() -> None:
    draft, notes = salvage(
        {"summary": "s", "hypotheses": [hypothesis("supported", ["E1", "E2"], ["E2"])]}
    )
    assert draft is not None
    h = draft.hypotheses[0]
    assert (h.verdict, h.support_refs, h.contradiction_refs) == ("supported", ("E1",), ())
    assert notes == [ValidationNoteCode.REFS_REMOVED.value] * 2


def test_contradicted_without_contradiction_is_unverified() -> None:
    draft, notes = salvage({"summary": "s", "hypotheses": [hypothesis("contradicted", ["E1"])]})
    assert draft is not None and draft.hypotheses[0].verdict == "unverified"
    assert ValidationNoteCode.DOWNGRADED.value in notes


def test_long_text_is_truncated_and_unknown_fields_ignored() -> None:
    draft, notes = salvage(
        {
            "summary": "x" * 1500,
            "extra": "ignored",
            "observations": [{"text": "y" * 900, "evidence_refs": ["E1"]}],
        }
    )
    assert draft is not None
    assert len(draft.summary) == 1000 and len(draft.observations[0].text) == 500
    assert notes.count(ValidationNoteCode.TRUNCATED.value) == 2
    assert ValidationNoteCode.FIELD_IGNORED.value in notes


def test_missing_summary_falls_back_to_supported_hypothesis() -> None:
    draft, notes = salvage(
        {
            "hypotheses": [
                {**hypothesis("unverified", []), "statement": "Maybe CPU."},
                hypothesis("supported", ["E1"]),
            ]
        }
    )
    assert draft is not None and draft.summary == "Storage DNS fails."
    assert ValidationNoteCode.SUMMARY_REPLACED.value in notes


def test_malformed_items_are_dropped_and_categories_defaulted() -> None:
    draft, notes = salvage(
        {
            "summary": "s",
            "symptoms": "not a list",
            "chronology": [{"at": "06:00", "text": "t", "evidence_refs": ["E2"]}, 7],
            "developer_actions": [{"text": "Fix the account name.", "evidence_refs": ["bad"]}],
            "gaps": [{"description": "No traces.", "category": "nope", "evidence_refs": []}],
        }
    )
    assert draft is not None
    assert draft.symptoms == () and draft.chronology == ()
    assert draft.developer_actions[0].evidence_refs == ()
    assert draft.gaps[0].category is c.PartialCategory.EVIDENCE_MISSING
    assert notes.count(ValidationNoteCode.ITEM_DROPPED.value) == 3


def test_nothing_salvageable_returns_none() -> None:
    assert salvage({"summary": " ", "observations": [{"text": ""}]})[0] is None
    assert salvage({})[0] is None
