"""Exact UTF-8 byte-budget fitting for evidence bundles."""

from __future__ import annotations

from collections.abc import Sequence

from azure_sre.contracts import EvidenceBundle, EvidenceError, EvidenceItem, EvidenceStatus

_OMITTED_MESSAGE = "omitted: evidence byte budget exceeded"


class EvidenceBudgetExhausted(ValueError):
    """Even the minimum envelopes cannot fit.

    Carries what did fit so the host can handle partial results.
    """

    def __init__(
        self, fitted: tuple[EvidenceItem, ...], omitted_evidence_ids: tuple[str, ...]
    ) -> None:
        super().__init__("evidence byte budget exhausted")
        self.fitted = fitted
        self.omitted_evidence_ids = omitted_evidence_ids


def bundle_bytes(incident_key: str, items: Sequence[EvidenceItem]) -> int:
    """Exact serialized size, bypassing validation so oversize input can still be measured."""
    return EvidenceBundle.model_construct(incident_key=incident_key, items=tuple(items)).byte_size()


def fit_items(
    incident_key: str, items: Sequence[EvidenceItem], max_bytes: int
) -> tuple[EvidenceItem, ...]:
    """Trim rows (largest item first) until the bundle fits ``max_bytes``.

    Items that still do not fit once they have no rows are replaced by a bounded error envelope so
    the gap is recorded. Evidence is never dropped silently: if the envelopes themselves cannot fit,
    ``EvidenceBudgetExhausted`` is raised with the items that did fit and the ids that did not.
    """
    working = list(items)
    while bundle_bytes(incident_key, working) > max_bytes:
        index = _largest_row_item(working)
        if index is not None:
            item = working[index]
            working[index] = item.model_copy(update={"rows": item.rows[:-1], "truncated": True})
            continue
        index = _first_envelope_candidate(working)
        if index is not None:
            item = working[index]
            working[index] = EvidenceItem(
                evidence_id=item.evidence_id,
                provenance=item.provenance,
                status=EvidenceStatus.ERROR,
                summary="",
                row_count=0,
                truncated=True,
                error=EvidenceError(category=EvidenceStatus.ERROR, message=_OMITTED_MESSAGE),
            )
            continue
        omitted = tuple(item.evidence_id for item in working)
        raise EvidenceBudgetExhausted(_fitting_prefix(incident_key, working, max_bytes), omitted)
    return tuple(working)


def _fitting_prefix(
    incident_key: str, items: Sequence[EvidenceItem], max_bytes: int
) -> tuple[EvidenceItem, ...]:
    kept: list[EvidenceItem] = []
    for item in items:
        if bundle_bytes(incident_key, [*kept, item]) > max_bytes:
            break
        kept.append(item)
    return tuple(kept)


def _largest_row_item(items: Sequence[EvidenceItem]) -> int | None:
    best: int | None = None
    for index, item in enumerate(items):
        if item.rows and (best is None or len(item.rows) > len(items[best].rows)):
            best = index
    return best


def _first_envelope_candidate(items: Sequence[EvidenceItem]) -> int | None:
    """Index of the first item not already reduced to a bounded error envelope."""
    for index, item in enumerate(items):
        if not (item.error is not None and item.summary == "" and item.rows == ()):
            return index
    return None
