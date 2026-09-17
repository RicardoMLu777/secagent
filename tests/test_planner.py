"""Tests for the Planner's JSON parsing and plan state machine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.planner import Plan, Planner, Task


def _planner() -> Planner:
    return Planner(model="dummy", base_url="http://localhost", api_key="dummy")


def test_parses_clean_json():
    p = _planner()
    data = p._json('{"target": "x", "tasks": []}')
    assert data["target"] == "x"


def test_parses_json_in_markdown_fence():
    p = _planner()
    data = p._json('```json\n{"action": "done"}\n```')
    assert data["action"] == "done"


def test_parses_json_with_surrounding_prose():
    p = _planner()
    data = p._json('Here is my answer: {"action": "continue"} — hope that helps')
    assert data["action"] == "continue"


def test_unparseable_returns_empty():
    p = _planner()
    assert p._json("total nonsense, no object here") == {}


def test_plan_state_machine():
    plan = Plan(
        target="x",
        tasks=[
            Task(1, "recon", status="pending"),
            Task(2, "probe", status="pending"),
            Task(3, "exploit", status="pending"),
        ],
    )
    assert plan.next_task().id == 1

    plan.mark(1, "done")
    assert plan.next_task().id == 2
    assert len(plan.pending()) == 2

    plan.mark(2, "done")
    plan.mark(3, "skipped")
    assert plan.next_task() is None
    assert plan.pending() == []


def test_plan_renders_icons():
    plan = Plan(target="t", tasks=[Task(1, "a", status="done"), Task(2, "b", status="pending")])
    rendered = plan.render()
    assert "● 1." in rendered
    assert "○ 2." in rendered


def test_plan_marks_intrusive():
    plan = Plan(target="t", tasks=[Task(1, "exploit", intrusive=True)])
    assert "[intrusive]" in plan.render()
