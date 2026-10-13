"""State-layer errors. Messages are fixed, safe strings; they never embed raw payloads."""

from __future__ import annotations

__all__ = [
    "ConcurrencyConflict",
    "LeaseLost",
    "ReportUnavailable",
    "StaleTransition",
    "StateAccessDenied",
    "StateCorrupt",
    "StateError",
    "StateTooLarge",
    "TransientStateError",
]


class StateError(Exception):
    """Base class. ``code`` is a stable machine-readable reason safe to log."""

    code = "state_error"

    def __init__(self, code: str | None = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(self.code)


class ConcurrencyConflict(StateError):
    """An ETag/existence precondition failed: someone else changed the entity."""

    code = "concurrency_conflict"


class TransientStateError(StateError):
    """Throttling, timeout or server error. The write outcome may be unknown."""

    code = "transient"


class StateAccessDenied(StateError):
    """Authentication/authorization failure. Not retried; indicates misconfiguration."""

    code = "access_denied"


class StateCorrupt(StateError):
    """A stored entity or blob failed validation."""

    code = "state_corrupt"


class StateTooLarge(StateError):
    """A value exceeds the Table/Blob property budget."""

    code = "state_too_large"


class LeaseLost(StateError):
    """This worker no longer owns the incident claim."""

    code = "lease_lost"


class StaleTransition(StateError):
    """The fresh record no longer satisfies the transition's precondition."""

    code = "stale_transition"


class ReportUnavailable(StateError):
    """A referenced report blob is missing or does not verify."""

    code = "report_unavailable"
