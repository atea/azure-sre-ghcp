"""Host-side budgets shared by baseline and model-requested diagnostics."""

from __future__ import annotations

import threading

from azure_sre.contracts import EvidenceItem
from azure_sre.diagnostics.budget import EvidenceBudgetExhausted, fit_items


class BudgetRefused(Exception):
    """A host budget refused an operation. ``reason`` is a safe code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class CallLedger:
    """Counts every diagnostic invocation, including repeats and baseline calls."""

    def __init__(self, max_calls: int) -> None:
        self._max = max_calls
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    def charge(self) -> None:
        with self._lock:
            if self._used >= self._max:
                raise BudgetRefused("calls")
            self._used += 1


class EvidenceLedger:
    """Renumbers collector output (E1 standalone) into one bounded, ordered bundle."""

    def __init__(self, incident_key: str, max_bytes: int) -> None:
        self._incident_key = incident_key
        self._max_bytes = max_bytes
        self._items: list[EvidenceItem] = []
        self._next = 1
        self._exhausted = False
        self._lock = threading.Lock()

    @property
    def items(self) -> tuple[EvidenceItem, ...]:
        with self._lock:
            return tuple(self._items)

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self._exhausted

    def admit(self, item: EvidenceItem) -> EvidenceItem | None:
        """Add ``item`` under the next id. Returns the admitted item, or None when bytes run out.

        Earlier items are kept (rows may be trimmed) so ids stay stable for the model.
        """
        with self._lock:
            numbered = EvidenceItem.model_validate(
                {**item.model_dump(), "evidence_id": f"E{self._next}"}
            )
            self._next += 1
            candidate = [*self._items, numbered]
            try:
                fitted = fit_items(self._incident_key, candidate, self._max_bytes)
            except EvidenceBudgetExhausted as exc:
                self._items = list(exc.fitted)
                self._exhausted = True
                return None
            self._items = list(fitted)
            return next((i for i in fitted if i.evidence_id == numbered.evidence_id), None)
