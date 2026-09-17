"""Planner — explicit Plan-and-Execute layer on top of the ReAct loop.

Two-phase design:
  1. plan()    — decompose the objective into an ordered task list once.
  2. revise()  — after each phase, let the model re-plan given new evidence.

This is deliberately separate from the acting loop in core.py: planning is a
LLM call with no tools attached, so the model reasons about *what* to do
without being tempted to just start firing tools.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from openai import OpenAI

PLANNER_SYSTEM = """You are the planning module of a security assessment agent.

Given an objective and any findings so far, produce a short ordered task list.

Rules:
- 3 to 6 tasks. No more. Prefer depth over breadth.
- Each task is one concrete action achievable with the available tools.
- Order by dependency: reconnaissance before probing, probing before exploitation.
- Mark which tasks are read-only reconnaissance vs. potentially intrusive.
- Respond with ONLY a JSON object, no prose, no markdown fences.

JSON schema:
{
  "target": "<primary target>",
  "tasks": [
    {"id": 1, "task": "<what to do>", "tools": ["<tool names>"], "intrusive": false},
    ...
  ]
}
"""

REVISE_SYSTEM = """You are the planning module of a security assessment agent.

You previously made a plan. New evidence has arrived. Decide whether the
remaining plan still makes sense.

Respond with ONLY a JSON object:
{
  "action": "continue" | "revise" | "done",
  "reason": "<one sentence>",
  "tasks": [ ... full updated task list, omit if action=continue ... ]
}

Use "done" when the objective is satisfied or no further productive action exists.
"""


@dataclass
class Task:
    id: int
    task: str
    tools: list[str] = field(default_factory=list)
    intrusive: bool = False
    status: str = "pending"  # pending | running | done | skipped


@dataclass
class Plan:
    target: str
    tasks: list[Task] = field(default_factory=list)

    def pending(self) -> list[Task]:
        return [t for t in self.tasks if t.status == "pending"]

    def next_task(self) -> Task | None:
        p = self.pending()
        return p[0] if p else None

    def mark(self, task_id: int, status: str) -> None:
        for t in self.tasks:
            if t.id == task_id:
                t.status = status
                return

    def render(self) -> str:
        icons = {"pending": "○", "running": "◐", "done": "●", "skipped": "✕"}
        lines = [f"Plan for {self.target}:"]
        for t in self.tasks:
            flag = " [intrusive]" if t.intrusive else ""
            tool_str = f" ({', '.join(t.tools)})" if t.tools else ""
            lines.append(f"  {icons.get(t.status, '?')} {t.id}. {t.task}{tool_str}{flag}")
        return "\n".join(lines)


class Planner:
    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.model = model or os.getenv("SECAGENT_MODEL", "deepseek-chat")
        self.client = OpenAI(
            api_key=api_key or os.getenv("SECAGENT_API_KEY") or os.getenv("DEEPSEEK_API_KEY", ""),
            base_url=base_url or os.getenv("SECAGENT_BASE_URL", "https://api.deepseek.com/v1"),
        )

    def _json(self, raw: str) -> dict[str, Any]:
        raw = raw.strip()
        raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", raw, re.S)
            if m:
                try:
                    return json.loads(m.group(0))
                except json.JSONDecodeError:
                    pass
        return {}

    def plan(self, objective: str, tools: list[str]) -> Plan:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": PLANNER_SYSTEM},
                {
                    "role": "user",
                    "content": (
                        f"## Objective\n{objective}\n\n"
                        f"## Available tools\n{', '.join(tools)}"
                    ),
                },
            ],
            temperature=0.2,
        )
        data = self._json(resp.choices[0].message.content or "")

        tasks = [
            Task(
                id=int(t.get("id", i + 1)),
                task=str(t.get("task", "")).strip(),
                tools=list(t.get("tools", []) or []),
                intrusive=bool(t.get("intrusive", False)),
            )
            for i, t in enumerate(data.get("tasks", []))
            if t.get("task")
        ]
        return Plan(target=data.get("target", "unknown"), tasks=tasks)

    def revise(self, objective: str, plan: Plan, findings: str) -> tuple[str, Plan]:
        """Returns ("continue"|"revise"|"done", plan)."""
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": REVISE_SYSTEM},
                {
                    "role": "user",
                    "content": (
                        f"## Objective\n{objective}\n\n"
                        f"## Current plan\n{plan.render()}\n\n"
                        f"## Findings so far\n{findings}"
                    ),
                },
            ],
            temperature=0.2,
        )
        data = self._json(resp.choices[0].message.content or "")
        action = data.get("action", "continue")

        if action == "revise" and data.get("tasks"):
            tasks = [
                Task(
                    id=int(t.get("id", i + 1)),
                    task=str(t.get("task", "")).strip(),
                    tools=list(t.get("tools", []) or []),
                    intrusive=bool(t.get("intrusive", False)),
                )
                for i, t in enumerate(data["tasks"])
                if t.get("task")
            ]
            plan = Plan(target=plan.target, tasks=tasks)

        return action, plan
