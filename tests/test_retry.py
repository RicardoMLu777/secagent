"""Tests for the retry helper."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.retry import is_transient, with_retry


def test_detects_timeout_as_transient():
    assert is_transient("error: timeout after 300s")
    assert is_transient("Connection refused")
    assert is_transient("502 Bad Gateway")
    assert is_transient("error: boom")


def test_success_is_not_transient():
    assert not is_transient('{"status_code": 200}')
    assert not is_transient("22/tcp open ssh")
    assert not is_transient("")


@pytest.mark.asyncio
async def test_retries_until_success():
    calls = {"n": 0}

    async def flaky() -> str:
        calls["n"] += 1
        return "error: timeout" if calls["n"] < 3 else "ok"

    result = await with_retry(flaky, max_attempts=5, base_delay=0.01, max_delay=0.02)
    assert result == "ok"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_gives_up_after_max_attempts():
    calls = {"n": 0}

    async def always_fail() -> str:
        calls["n"] += 1
        return "error: timeout"

    result = await with_retry(always_fail, max_attempts=2, base_delay=0.01, max_delay=0.02)
    assert "timeout" in result
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_no_retry_on_success():
    calls = {"n": 0}

    async def fine() -> str:
        calls["n"] += 1
        return "ok"

    result = await with_retry(fine, max_attempts=3, base_delay=0.01)
    assert result == "ok"
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_exception_is_retried_then_reported():
    calls = {"n": 0}

    async def raises() -> str:
        calls["n"] += 1
        raise RuntimeError("connection reset")

    result = await with_retry(raises, max_attempts=2, base_delay=0.01, max_delay=0.02)
    assert "connection reset" in result
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_on_retry_callback_fires():
    seen: list[int] = []

    async def flaky() -> str:
        return "error: timeout" if len(seen) < 1 else "ok"

    await with_retry(
        flaky, max_attempts=3, base_delay=0.01, max_delay=0.02,
        on_retry=lambda attempt, preview: seen.append(attempt),
    )
    assert seen == [1]
