"""Tests for the memory distillation layer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.memory import Memory


def test_distils_nmap_output():
    m = Memory()
    nmap_out = """
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
    80/tcp   open  http    nginx 1.18.0
    """
    m.record(1, "nmap_scan", {"target": "x"}, nmap_out)

    assert "22" in m.findings["open_ports"]
    assert "80" in m.findings["open_ports"]
    assert "ssh" in m.findings["services"]
    assert any("nginx" in s for s in m.findings["services"])


def test_distils_headers_and_paths():
    m = Memory()
    m.record(
        1,
        "check_security_headers",
        {},
        '{"missing": ["content-security-policy", "x-frame-options"]}',
    )
    m.record(2, "check_robots", {}, '{"entries": ["/admin", "/backup"]}')

    assert "content-security-policy" in m.findings["missing_headers"]
    assert "/admin" in m.findings["interesting_paths"]


def test_captures_flags():
    m = Memory()
    m.record(1, "http_probe", {}, 'body: flag{sql_1nj3ct10n_g3t_fl4g_succ3ss}')
    assert m.findings["flags"] == {"flag{sql_1nj3ct10n_g3t_fl4g_succ3ss}"}


def test_truncates_long_output():
    m = Memory(max_result_chars=100)
    m.record(1, "nmap_scan", {}, "A" * 5000)
    assert len(m.observations[0].result) < 300
    assert "truncated" in m.observations[0].result


def test_summary_shape():
    m = Memory()
    m.record(1, "nmap_scan", {}, "80/tcp open http nginx 1.18.0")
    s = m.summary()
    assert "Open ports" in s
    assert "80" in s
