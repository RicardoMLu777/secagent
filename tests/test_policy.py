"""Tests for the engagement policy gate."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.policy import Decision, EngagementPolicy


def test_passive_tools_allowed_in_ask_mode():
    p = EngagementPolicy(mode="ask")
    for tool in ("httpx_server__http_probe", "httpx_server__check_robots"):
        d, _ = p.evaluate(tool, {"url": "http://x"})
        assert d is Decision.ALLOW, tool


def test_intrusive_tool_requires_approval():
    p = EngagementPolicy(mode="ask")
    d, reason = p.evaluate("sqlmap_server__sqlmap_scan", {"url": "http://x"})
    assert d is Decision.ASK
    assert "approval" in reason


def test_passive_mode_blocks_intrusive():
    p = EngagementPolicy(mode="passive")
    d, _ = p.evaluate("nmap_server__nmap_scan", {"target": "x"})
    assert d is Decision.DENY


def test_allow_mode_permits_everything():
    p = EngagementPolicy(mode="allow")
    d, _ = p.evaluate("sqlmap_server__sqlmap_dump", {"url": "http://x"})
    assert d is Decision.ALLOW


def test_denied_tools_blocked_in_every_mode():
    p = EngagementPolicy(mode="allow", denied_tools={"sqlmap_dump"})
    d, reason = p.evaluate("sqlmap_server__sqlmap_dump", {"url": "http://x"})
    assert d is Decision.DENY
    assert "denied" in reason


def test_scope_allowlist_denies_out_of_scope():
    p = EngagementPolicy(mode="allow", scope=[r"example\.com"])
    d, reason = p.evaluate("httpx_server__http_probe", {"url": "http://evil.com"})
    assert d is Decision.DENY
    assert "scope" in reason

    d2, _ = p.evaluate("httpx_server__http_probe", {"url": "http://example.com"})
    assert d2 is Decision.ALLOW


def test_deny_private_targets():
    p = EngagementPolicy(mode="allow", deny_private_targets=True)
    for target in ("http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/",
                   "http://169.254.169.254/"):
        d, _ = p.evaluate("httpx_server__http_probe", {"url": target})
        assert d is Decision.DENY, target

    d, _ = p.evaluate("httpx_server__http_probe", {"url": "http://example.com"})
    assert d is Decision.ALLOW


def test_applies_to_both_qualified_and_bare_names():
    p = EngagementPolicy(mode="ask")
    d1, _ = p.evaluate("sqlmap_scan", {})
    d2, _ = p.evaluate("sqlmap_server__sqlmap_scan", {})
    assert d1 is d2 is Decision.ASK


def test_no_approver_fails_closed():
    p = EngagementPolicy(mode="ask")
    assert p.request_approval("x", {}, "reason") is False


def test_approver_can_grant():
    p = EngagementPolicy(mode="ask", approver=lambda req: True)
    assert p.request_approval("x", {}, "reason") is True


def test_from_dict_roundtrip():
    p = EngagementPolicy.from_dict(
        {"mode": "ask", "scope": ["a"], "deny_private_targets": True,
         "denied_tools": ["ffuf_dirs"]}
    )
    assert p.mode == "ask"
    assert p.scope == ["a"]
    assert p.deny_private_targets is True
    assert "ffuf_dirs" in p.denied_tools
