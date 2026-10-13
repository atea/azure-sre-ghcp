"""Bounded retry helpers: full-jitter exponential backoff with injectable randomness."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import Protocol

from azure_sre.state.errors import TransientStateError

__all__ = ["Jitter", "backoff_delay", "retry_transient"]


class Jitter(Protocol):
    def uniform(self, a: float, b: float, /) -> float: ...


def backoff_delay(
    attempt: int,
    *,
    base: float,
    cap: float,
    rng: Jitter | None = None,
    retry_after: float | None = None,
) -> float:
    """Full-jitter delay for ``attempt`` (1-based). ``retry_after`` is a floor, capped."""
    exponent = min(max(attempt, 1) - 1, 30)
    ceiling = min(cap, base * (2**exponent))
    delay = (rng or random).uniform(0.0, ceiling)
    if retry_after is not None:
        delay = max(delay, min(max(retry_after, 0.0), cap))
    return delay


async def retry_transient[T](
    operation: Callable[[], Awaitable[T]],
    *,
    attempts: int,
    base: float,
    cap: float,
    rng: Jitter | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> T:
    """Retry ``TransientStateError`` a bounded number of times; re-raise the last one."""
    for attempt in range(1, attempts + 1):
        try:
            return await operation()
        except TransientStateError:
            if attempt >= attempts:
                raise
            await sleep(backoff_delay(attempt, base=base, cap=cap, rng=rng))
    raise AssertionError("unreachable")  # pragma: no cover
