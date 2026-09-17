"""Tests for SQLite persistence and engagement diffing."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.store import Store


def _store(tmp_path) -> Store:
    return Store(tmp_path / "test.db")


def test_start_and_retrieve(tmp_path):
    s = _store(tmp_path)
    eid = s.start_engagement("example.com", "do recon", {"mode": "ask"})
    assert eid > 0

    rec = s.get(eid)
    assert rec is not None
    assert rec["target"] == "example.com"
    assert rec["objective"] == "do recon"
    assert rec["policy"]["mode"] == "ask"


def test_records_tool_calls(tmp_path):
    s = _store(tmp_path)
    eid = s.start_engagement("x", "obj")
    s.record_tool_call(eid, 1, "nmap_server__nmap_scan", {"target": "x"}, "22/tcp open ssh")
    s.record_tool_call(eid, 2, "sqlmap_server__sqlmap_scan", {"url": "u"},
                       '{"blocked": true}', blocked=True)

    rec = s.get(eid)
    assert len(rec["tool_calls"]) == 2
    assert rec["tool_calls"][0]["tool"] == "nmap_server__nmap_scan"
    assert rec["tool_calls"][1]["blocked"] == 1


def test_finish_persists_findings(tmp_path):
    s = _store(tmp_path)
    eid = s.start_engagement("x", "obj")
    s.finish_engagement(
        eid,
        {
            "steps": 4,
            "observations": 9,
            "report": "the report",
            "findings": {"open_ports": ["22", "80"], "flags": ["flag{a}"]},
            "attack_mapping": {"techniques": []},
            "plan": [],
        },
    )
    rec = s.get(eid)
    assert rec["steps"] == 4
    assert rec["report"] == "the report"
    assert rec["findings"]["open_ports"] == ["22", "80"]


def test_history_filters_by_target(tmp_path):
    s = _store(tmp_path)
    s.start_engagement("a.com", "o1")
    s.start_engagement("b.com", "o2")
    s.start_engagement("a.com", "o3")

    assert len(s.history()) == 3
    a_only = s.history(target="a.com")
    assert len(a_only) == 2
    assert all(r["target"] == "a.com" for r in a_only)


def test_history_surfaces_flags(tmp_path):
    s = _store(tmp_path)
    eid = s.start_engagement("x", "o")
    s.finish_engagement(eid, {"findings": {"flags": ["flag{z}"]}})
    rows = s.history(target="x")
    assert rows[0]["flags"] == ["flag{z}"]


def test_targets_groups_runs(tmp_path):
    s = _store(tmp_path)
    s.start_engagement("a.com", "o")
    s.start_engagement("a.com", "o")
    s.start_engagement("b.com", "o")
    targets = {t["target"]: t["runs"] for t in s.targets()}
    assert targets["a.com"] == 2
    assert targets["b.com"] == 1


def test_diff_detects_changes(tmp_path):
    s = _store(tmp_path)
    a = s.start_engagement("x", "o")
    s.finish_engagement(a, {"findings": {"open_ports": ["22"], "flags": []}})
    b = s.start_engagement("x", "o")
    s.finish_engagement(b, {"findings": {"open_ports": ["22", "80"], "flags": ["flag{n}"]}})

    d = s.diff(a, b)
    assert "80" in d["changes"]["ports"]["added"]
    assert d["changes"]["ports"]["unchanged"] == 1
    assert "flag{n}" in d["changes"]["flags"]["added"]


def test_diff_missing_engagement(tmp_path):
    s = _store(tmp_path)
    assert "error" in s.diff(1, 2)
