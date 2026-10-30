"""Hostname resolution checks for --deny-private --resolve-targets.

Every case injects a resolver, so this file never touches the network.
"""

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.policy import Decision, EngagementPolicy


def _resolver_returning(*addresses):
    def resolve(host: str) -> tuple[str, ...]:
        return tuple(addresses)

    return resolve


def _resolver_raising(exc: Exception):
    def resolve(host: str) -> tuple[str, ...]:
        raise exc

    return resolve


def _evaluate(target: str, resolver, resolve_targets: bool = True):
    policy = EngagementPolicy(
        mode="allow",
        deny_private_targets=True,
        resolve_targets=resolve_targets,
        resolver=resolver,
    )
    return policy.evaluate("httpx_server__http_probe", {"url": target})


def test_hostname_allowed_when_public():
    decision, reason = _evaluate("http://example.com", _resolver_returning("93.184.216.34"))
    assert decision is Decision.ALLOW, reason


def test_hostname_denied_when_it_resolves_to_private():
    decision, reason = _evaluate("http://internal.example.com", _resolver_returning("192.168.1.10"))
    assert decision is Decision.DENY
    assert "192.168.1.10" in reason


def test_hostname_denied_when_any_address_is_private():
    """A name with one public and one private answer must still be rejected."""
    decision, reason = _evaluate(
        "http://mixed.example.com",
        _resolver_returning("93.184.216.34", "10.1.2.3"),
    )
    assert decision is Decision.DENY
    assert "10.1.2.3" in reason


def test_loopback_answer_denied():
    decision, _ = _evaluate("http://rebind.example.com", _resolver_returning("127.0.0.1"))
    assert decision is Decision.DENY


def test_link_local_answer_denied():
    decision, _ = _evaluate("http://metadata.example.com", _resolver_returning("169.254.169.254"))
    assert decision is Decision.DENY


def test_resolution_failure_fails_closed():
    decision, reason = _evaluate(
        "http://nx.example.com",
        _resolver_raising(socket.gaierror("Name or service not known")),
    )
    assert decision is Decision.DENY
    assert "could not be resolved" in reason


def test_empty_answer_fails_closed():
    decision, reason = _evaluate("http://void.example.com", _resolver_returning())
    assert decision is Decision.DENY
    assert "no addresses" in reason


def test_no_resolution_without_the_flag():
    """Without resolve_targets, a hostname passes: the flag is opt-in."""
    decision, _ = _evaluate(
        "http://internal.example.com",
        _resolver_returning("192.168.1.10"),
        resolve_targets=False,
    )
    assert decision is Decision.ALLOW


def test_ip_literals_never_call_the_resolver():
    calls = []

    def resolve(host: str) -> tuple[str, ...]:
        calls.append(host)
        return ("93.184.216.34",)

    decision, _ = _evaluate("http://192.168.1.5/", resolve)
    assert decision is Decision.DENY
    assert calls == []


def test_scope_rejection_short_circuits_resolution():
    calls = []

    def resolve(host: str) -> tuple[str, ...]:
        calls.append(host)
        return ("93.184.216.34",)

    policy = EngagementPolicy(
        mode="allow",
        scope=[r"example\.com"],
        deny_private_targets=True,
        resolve_targets=True,
        resolver=resolve,
    )
    decision, _ = policy.evaluate("httpx_server__http_probe", {"url": "http://other.test"})
    assert decision is Decision.DENY
    assert calls == []


def test_from_dict_roundtrip():
    policy = EngagementPolicy.from_dict({"deny_private_targets": True, "resolve_targets": True})
    assert policy.resolve_targets is True
    assert "hostnames resolved" in policy.render()


@pytest.mark.parametrize("value", [None, False])
def test_resolve_targets_defaults_off(value):
    policy = EngagementPolicy.from_dict({} if value is None else {"resolve_targets": value})
    assert policy.resolve_targets is False
