"""Salvage a model draft that failed strict validation instead of discarding it wholesale.

The salvaged draft always satisfies the same contract and evidence rules as a strictly valid
one: unsupported claims are downgraded to unverified hypotheses, unknown references are
removed, and items that still cannot be repaired are dropped. Every alteration is returned
as a host-written note; notes never echo model text.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final, TypeGuard

from azure_sre.contracts import (
    EvidenceBundle,
    EvidenceStatus,
    ModelReportDraft,
    PartialCategory,
    ReportValidationError,
    ValidationNoteCode,
    validate_model_output,
)

Note = tuple[ValidationNoteCode, str]

_TEXT_LIMIT: Final = 500
_SUMMARY_LIMIT: Final = 1000
_AT_LIMIT: Final = 64
_REF_RE: Final = re.compile(r"^E[1-9][0-9]{0,2}$")
_VERDICTS: Final = frozenset({"supported", "contradicted", "unverified"})
_LISTS: Final = (
    "symptoms",
    "chronology",
    "observations",
    "hypotheses",
    "developer_actions",
    "gaps",
)
_KNOWN: Final = frozenset({"status", "summary", *_LISTS})


def _is_list(value: object) -> TypeGuard[Sequence[object]]:
    return isinstance(value, Sequence) and not isinstance(value, str | bytes)


class _Salvager:
    def __init__(self, bundle: EvidenceBundle) -> None:
        self.known = bundle.ids()
        self.ok = frozenset(i.evidence_id for i in bundle.items if i.status is EvidenceStatus.OK)
        self.notes: list[Note] = []

    def note(self, code: ValidationNoteCode, detail: str) -> None:
        self.notes.append((code, detail))

    def text(self, value: object, path: str, limit: int = _TEXT_LIMIT) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        if len(text) > limit:
            self.note(ValidationNoteCode.TRUNCATED, f"{path}: shortened to {limit} characters")
            text = text[: limit - 1].rstrip() + "…"
        return text

    def refs(self, value: object, path: str) -> list[str]:
        items: Sequence[object] = value if _is_list(value) else ()
        kept: list[str] = []
        for ref in items:
            if isinstance(ref, str) and _REF_RE.match(ref) and ref in self.known:
                if ref not in kept:
                    kept.append(ref)
        removed = len(items) - len(kept)
        if removed > 0 or (value is not None and not _is_list(value)):
            self.note(
                ValidationNoteCode.REFS_REMOVED,
                f"{path}: removed {max(removed, 1)} unknown or malformed evidence reference(s)",
            )
        return kept

    def only_ok(self, refs: list[str], path: str, *, quiet_if_empty: bool = True) -> list[str]:
        """Keep OK refs; a caller that downgrades an item on empty output notes that itself."""
        kept = [ref for ref in refs if ref in self.ok]
        dropped = [ref for ref in refs if ref not in self.ok]
        if dropped and (kept or not quiet_if_empty):
            self.note(
                ValidationNoteCode.REFS_REMOVED,
                f"{path}: removed {', '.join(dropped)}; failed evidence cannot support a claim",
            )
        return kept

    def unverified(self, statement: str, refs: list[str], path: str) -> dict[str, Any]:
        self.note(
            ValidationNoteCode.DOWNGRADED,
            f"{path}: moved to unverified hypotheses; no OK evidence supports it",
        )
        return {
            "statement": statement,
            "support_refs": refs,
            "contradiction_refs": [],
            "verdict": "unverified",
        }

    def claims(
        self, entries: object, name: str, extra: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Symptoms and observations must cite OK evidence, else they become hypotheses."""
        kept: list[dict[str, Any]] = []
        for index, entry in enumerate(self.entries(entries, name)):
            path = f"{name}[{index}]"
            text = self.text(entry.get("text"), path)
            if text is None:
                self.note(ValidationNoteCode.ITEM_DROPPED, f"{path}: missing text")
                continue
            refs = self.refs(entry.get("evidence_refs"), path)
            ok = self.only_ok(refs, path)
            if ok:
                kept.append({"text": text, "evidence_refs": ok})
            else:
                extra.append(self.unverified(text, refs, path))
        return kept

    def chronology(self, entries: object) -> list[dict[str, Any]]:
        kept: list[dict[str, Any]] = []
        for index, entry in enumerate(self.entries(entries, "chronology")):
            path = f"chronology[{index}]"
            at = self.text(entry.get("at"), path, _AT_LIMIT)
            text = self.text(entry.get("text"), path)
            ok = self.only_ok(self.refs(entry.get("evidence_refs"), path), path)
            if at is None or text is None or not ok:
                self.note(
                    ValidationNoteCode.ITEM_DROPPED,
                    f"{path}: dropped; needs a time, text and OK evidence",
                )
                continue
            kept.append({"at": at, "text": text, "evidence_refs": ok})
        return kept

    def hypotheses(self, entries: object) -> list[dict[str, Any]]:
        kept: list[dict[str, Any]] = []
        for index, entry in enumerate(self.entries(entries, "hypotheses")):
            path = f"hypotheses[{index}]"
            statement = self.text(entry.get("statement"), path)
            if statement is None:
                self.note(ValidationNoteCode.ITEM_DROPPED, f"{path}: missing statement")
                continue
            verdict = entry.get("verdict")
            if verdict not in _VERDICTS:
                self.note(ValidationNoteCode.DOWNGRADED, f"{path}: unknown verdict; unverified")
                verdict = "unverified"
            support = self.refs(entry.get("support_refs"), f"{path}.support_refs")
            against = self.refs(entry.get("contradiction_refs"), f"{path}.contradiction_refs")
            if verdict != "unverified":
                ok_support = self.only_ok(support, f"{path}.support_refs")
                if verdict == "supported" and not ok_support:
                    self.note(
                        ValidationNoteCode.DOWNGRADED,
                        f"{path}: supported → unverified; no OK evidence supports it",
                    )
                    verdict = "unverified"
                elif verdict == "contradicted" and not against:
                    self.note(
                        ValidationNoteCode.DOWNGRADED,
                        f"{path}: contradicted → unverified; no contradicting evidence cited",
                    )
                    verdict = "unverified"
                else:
                    support = ok_support
            if verdict == "supported":
                against = self.only_ok(against, f"{path}.contradiction_refs", quiet_if_empty=False)
            kept.append(
                {
                    "statement": statement,
                    "support_refs": support,
                    "contradiction_refs": against,
                    "verdict": verdict,
                }
            )
        return kept

    def actions(self, entries: object) -> list[dict[str, Any]]:
        kept: list[dict[str, Any]] = []
        for index, entry in enumerate(self.entries(entries, "developer_actions")):
            path = f"developer_actions[{index}]"
            text = self.text(entry.get("text"), path)
            if text is None:
                self.note(ValidationNoteCode.ITEM_DROPPED, f"{path}: missing text")
                continue
            kept.append(
                {"text": text, "evidence_refs": self.refs(entry.get("evidence_refs"), path)}
            )
        return kept

    def gaps(self, entries: object) -> list[dict[str, Any]]:
        kept: list[dict[str, Any]] = []
        categories = {c.value for c in PartialCategory}
        for index, entry in enumerate(self.entries(entries, "gaps")):
            path = f"gaps[{index}]"
            description = self.text(entry.get("description"), path)
            if description is None:
                self.note(ValidationNoteCode.ITEM_DROPPED, f"{path}: missing description")
                continue
            category = entry.get("category")
            if category not in categories:
                self.note(
                    ValidationNoteCode.DOWNGRADED, f"{path}: unknown category; evidence_missing"
                )
                category = PartialCategory.EVIDENCE_MISSING.value
            kept.append(
                {
                    "description": description,
                    "category": category,
                    "evidence_refs": self.refs(entry.get("evidence_refs"), path),
                }
            )
        return kept

    def entries(self, value: object, name: str) -> list[Mapping[str, Any]]:
        if value is None:
            return []
        if not _is_list(value):
            self.note(ValidationNoteCode.ITEM_DROPPED, f"{name}: not a list; ignored")
            return []
        kept: list[Mapping[str, Any]] = []
        for index, entry in enumerate(value):
            if isinstance(entry, Mapping):
                kept.append(entry)
            else:
                self.note(ValidationNoteCode.ITEM_DROPPED, f"{name}[{index}]: not an object")
        return kept


def salvage_draft(
    document: Mapping[str, Any], bundle: EvidenceBundle
) -> tuple[ModelReportDraft | None, list[Note]]:
    """Return the best contract-valid draft from ``document`` and the notes describing changes.

    ``document`` must already be redacted. The draft's ``status`` is a placeholder; the host
    decides the final status.
    """
    s = _Salvager(bundle)
    unknown = [key for key in document if key not in _KNOWN]
    if unknown:
        s.note(
            ValidationNoteCode.FIELD_IGNORED, f"ignored {len(unknown)} unknown top-level field(s)"
        )
    moved: list[dict[str, Any]] = []
    symptoms = s.claims(document.get("symptoms"), "symptoms", moved)
    observations = s.claims(document.get("observations"), "observations", moved)
    hypotheses = s.hypotheses(document.get("hypotheses")) + moved
    candidate: dict[str, Any] = {
        "status": "partial",
        "summary": None,
        "symptoms": symptoms,
        "chronology": s.chronology(document.get("chronology")),
        "observations": observations,
        "hypotheses": hypotheses,
        "developer_actions": s.actions(document.get("developer_actions")),
        "gaps": s.gaps(document.get("gaps")),
    }
    summary = s.text(document.get("summary"), "summary", _SUMMARY_LIMIT)
    if summary is None:
        ranked = sorted(hypotheses, key=lambda h: h["verdict"] != "supported")
        fallback = [h["statement"] for h in ranked] + [o["text"] for o in observations]
        if not fallback:
            return None, s.notes
        s.note(ValidationNoteCode.SUMMARY_REPLACED, "summary: missing; used the leading finding")
        summary = fallback[0]
    candidate["summary"] = summary
    try:
        draft = validate_model_output(candidate, bundle)
    except ReportValidationError:
        return None, s.notes
    return draft, s.notes
