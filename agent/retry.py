"""Retry helper with exponential backoff for flaky tool calls."""

from __future__ import annotations

import asyncio
import random
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")

# Results matching these shapes are considered transient and worth retrying.
TRANSIENT_MARKERS = (
    "timeout",
    "timed out",
    "connection refused",
    "connection reset",
    "temporarily unavailable",
    "network is unreachable",
    "rate limit",
    "too many requests",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
)


def is_transient(result: str) -> bool:
    """Heuristic: should this tool result be retried?"""
    if not result:
        return False
    low = result.lower()
    if any(m in low for m in TRANSIENT_MARKERS):
        return True
    # MCP servers signal failures with an "error:" prefix.
    return low.lstrip().startswith("error:")


async def with_retry(
    fn: Callable[[], Awaitable[str]],
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 8.0,
    on_retry: Callable[[int, str], None] | None = None,
) -> str:
    """Call fn() until it returns a non-transient result or attempts run out.

    Returns the last result regardless, so the caller always has something to
    feed back to the model.
    """
    last = ""
    for attempt in range(1, max_attempts + 1):
        try:
            last = await fn()
        except Exception as e:  # noqa: BLE001
            last = f"error: {type(e).__name__}: {e}"

        if not is_transient(last):
            return last

        if attempt == max_attempts:
            break

        # Exponential backoff with jitter to avoid thundering herds.
        delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
        delay *= 0.5 + random.random()
        if on_retry:
            on_retry(attempt, last[:120])
        await asyncio.sleep(delay)

    return last
