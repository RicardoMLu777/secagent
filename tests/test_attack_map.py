"""Tests for ATT&CK mapping and report rendering."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.attack_map import map_findings
from agent import report


FINDINGS = {
    "open_ports": ["22", "80"],
    "services": ["ssh", "nginx 1.18.0"],
    "technologies": ["nginx/1.18.0"],
    "missing_headers": ["content-security-policy", "x-frame-options"],
    "interesting_paths": ["/admin"],
    "flags": [],
}


def test_maps_nmap_to_t1046():
    obs = [{"tool": "nmap_server__nmap_scan", "result": "22/tcp open ssh\n80/tcp open http"}]
    m = map_findings(FINDINGS, obs)
    ids = [t["id"] for t in m["techniques"]]
    assert "T1046" in ids


def test_maps_http_probe_to_t1592():
    obs = [{"tool": "httpx_server__http_probe", "result": '"server": "nginx"'}]
    m = map_findings(FINDINGS, obs)
    assert "T1592" in [t["id"] for t in m["techniques"]]


def test_sqlmap_injectable_maps_to_t1190():
    obs = [{"tool": "sqlmap_server__sqlmap_scan", "result": '{"injectable": true}'}]
    m = map_findings(FINDINGS, obs)
    assert "T1190" in [t["id"] for t in m["techniques"]]


def test_no_false_positive_when_not_injectable():
    obs = [{"tool": "sqlmap_server__sqlmap_scan", "result": '{"injectable": false}'}]
    m = map_findings(FINDINGS, obs)
    assert "T1190" not in [t["id"] for t in m["techniques"]]


def test_weaknesses_from_missing_headers():
    m = map_findings(FINDINGS, [])
    headers = [w["header"] for w in m["weaknesses"]]
    assert "content-security-policy" in headers
    assert "x-frame-options" in headers


def test_report_contains_key_sections():
    obs = [{"tool": "nmap_server__nmap_scan", "result": "22/tcp open ssh"}]
    md = report.to_markdown(
        {
            "findings": FINDINGS,
            "attack_mapping": map_findings(FINDINGS, obs),
            "report": "body text",
            "steps": 3,
            "observations": 7,
            "plan": [{"id": 1, "task": "scan", "status": "done", "intrusive": False}],
        }
    )
    for section in [
        "# SecAgent Assessment Report",
        "## Summary",
        "## Plan execution",
        "## MITRE ATT&CK techniques observed",
        "## Configuration weaknesses",
        "## Agent report",
    ]:
        assert section in md


def test_report_omits_attack_section_when_no_techniques():
    md = report.to_markdown(
        {
            "findings": FINDINGS,
            "attack_mapping": map_findings(FINDINGS, []),  # weaknesses yes, techniques no
            "report": "body",
            "steps": 1,
            "observations": 0,
            "plan": [],
        }
    )
    assert "## MITRE ATT&CK techniques observed" not in md
    assert "## Configuration weaknesses" in md


def test_report_surfaces_flags():
    f = dict(FINDINGS, flags=["flag{test_value}"])
    md = report.to_markdown(
        {"findings": f, "attack_mapping": {}, "report": "x", "steps": 1,
         "observations": 1, "plan": []}
    )
    assert "flag{test_value}" in md
