"""Scope and network checks must key on the hostname, not the raw URL string.

Regression tests for the scope-allowlist bypass: matching a pattern anywhere
inside the full target string let ``--scope 'example\\.com'`` authorise
``example.com.attacker.net`` and ``evilexample.com``.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.policy import Decision, EngagementPolicy


def _probe(target: str, scope: list[str]) -> tuple[Decision, str]:
    policy = EngagementPolicy(mode="ask", scope=scope)
    return policy.evaluate("httpx_server__http_probe", {"target": target})


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "http://example.com:8443/path?q=1#frag",
        "example.com",
        "example.com:8080",
        "HTTPS://EXAMPLE.COM/",
    ],
)
def test_scope_accepts_exact_host(target):
    decision, reason = _probe(target, [r"example\.com"])
    assert decision is Decision.ALLOW, f"{target} rejected: {reason}"


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com.attacker.net",
        "https://evilexample.com",
        "https://example.com.cn",
        "https://example.com@attacker.net",
        "https://attacker.net/?next=example.com",
    ],
)
def test_scope_rejects_lookalike_hosts(target):
    decision, reason = _probe(target, [r"example\.com"])
    assert decision is Decision.DENY, f"{target} slipped through the scope check"
    assert "outside the declared scope" in reason


def test_scope_reports_the_parsed_hostname():
    decision, reason = _probe("https://example.com@attacker.net", [r"example\.com"])
    assert decision is Decision.DENY
    assert "attacker.net" in reason


def test_scope_allows_explicit_subdomain_pattern():
    decision, _ = _probe("https://a.b.example.com", [r".*\.example\.com"])
    assert decision is Decision.ALLOW


def test_subdomain_pattern_does_not_cover_the_apex():
    decision, _ = _probe("https://example.com", [r".+\.example\.com"])
    assert decision is Decision.DENY


def test_scope_ignores_tool_calls_without_a_target():
    policy = EngagementPolicy(mode="ask", scope=[r"example\.com"])
    decision, _ = policy.evaluate("sqlmap_scan", {})
    assert decision is not Decision.DENY


@pytest.mark.parametrize(
    "target",
    [
        "http://127.0.0.1/",
        "http://127.1.2.3:8080/",
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://172.31.255.254/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:3000/",
        "http://[::1]/",
    ],
)
def test_private_targets_denied(target):
    policy = EngagementPolicy(mode="allow", deny_private_targets=True)
    decision, _ = policy.evaluate("httpx_server__http_probe", {"url": target})
    assert decision is Decision.DENY, target


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com",
        "http://172.15.0.1/",
        "http://172.32.0.1/",
        "http://notlocalhost.com/",
        "http://10.example.com/",
    ],
)
def test_public_lookalikes_not_treated_as_private(target):
    """The old regex matched 'localhost' and '10.' anywhere in the string."""
    policy = EngagementPolicy(mode="allow", deny_private_targets=True)
    decision, reason = policy.evaluate("httpx_server__http_probe", {"url": target})
    assert decision is Decision.ALLOW, f"{target} false positive: {reason}"
