"""ReAct agent loop — reason, act via MCP tools, observe, repeat.

v0.2 adds:
  - explicit Planner (Plan-and-Execute) alongside the reactive loop
  - parallel tool execution when the model requests multiple calls
  - MITRE ATT&CK mapping in the final report
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from openai import OpenAI
from rich.console import Console
from rich.panel import Panel

from .attack_map import map_findings
from .memory import Memory
from .mcp_client import MCPManager
from .planner import Planner, Plan

console = Console()

SYSTEM_PROMPT = """You are SecAgent, an autonomous security assessment assistant.

You operate through MCP tools that wrap real security utilities
(nmap, sqlmap, ffuf, HTTP probing).

## Rules of engagement
- Only act against targets the user has explicitly authorized in their objective.
- Prefer non-intrusive reconnaissance first: port scan, HTTP probe, header audit,
  robots.txt, directory discovery. Escalate to injection testing only when the
  objective calls for it.
- Never fabricate tool output. If a tool fails, say so in your final report.
- If a task in the plan is marked [intrusive], confirm the objective permits it
  before proceeding.

## How you work
You are given a PLAN with numbered tasks. Work through them in order.
For each step:
  1. THINK about what the current task needs and what you already know.
  2. CALL the tools that accomplish it. You may call several tools in one turn
     when they are independent.
  3. OBSERVE the results and update your understanding.

Do not repeat a tool call that already succeeded with the same arguments.
When the plan is complete, stop calling tools and produce the final report.

## Final report format
### Target
### Objective
### Findings
(bullet list of concrete, evidence-backed observations)
### Risk assessment
(severity per finding: Critical / High / Medium / Low / Info, with one-line justification)
### Recommended next steps
"""


class SecAgent:
    def __init__(
        self,
        servers: list[str],
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        max_steps: int = 20,
        verbose: bool = True,
        use_planner: bool = True,
        parallel: bool = True,
    ) -> None:
        self.servers = servers
        self.model = model or os.getenv("SECAGENT_MODEL", "deepseek-chat")
        self.base_url = base_url or os.getenv(
            "SECAGENT_BASE_URL", "https://api.deepseek.com/v1"
        )
        self.api_key = api_key or os.getenv("SECAGENT_API_KEY") or os.getenv(
            "DEEPSEEK_API_KEY", ""
        )
        self.max_steps = max_steps
        self.verbose = verbose
        self.use_planner = use_planner
        self.parallel = parallel

        if not self.api_key:
            raise RuntimeError(
                "No API key. Set DEEPSEEK_API_KEY (or SECAGENT_API_KEY) in the environment."
            )

        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def _log(self, msg: str, style: str = "dim") -> None:
        if self.verbose:
            console.print(msg, style=style)

    async def _execute_calls(
        self, mcp: MCPManager, tool_calls: list[Any]
    ) -> list[tuple[Any, dict[str, Any], str]]:
        """Run tool calls — in parallel when enabled, else sequentially."""
        parsed: list[tuple[Any, dict[str, Any]]] = []
        for tc in tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            parsed.append((tc, args))

        if self.parallel and len(parsed) > 1:
            self._log(f"  [dim]running {len(parsed)} tool calls in parallel[/dim]")
            results = await asyncio.gather(
                *(mcp.call(tc.function.name, args) for tc, args in parsed),
                return_exceptions=True,
            )
            out: list[tuple[Any, dict[str, Any], str]] = []
            for (tc, args), res in zip(parsed, results):
                text = (
                    f"error: {type(res).__name__}: {res}"
                    if isinstance(res, BaseException)
                    else str(res)
                )
                out.append((tc, args, text))
            return out

        out = []
        for tc, args in parsed:
            out.append((tc, args, await mcp.call(tc.function.name, args)))
        return out

    async def run(self, objective: str, plan: Plan | None = None) -> dict[str, Any]:
        memory = Memory()
        steps_used = 0

        async with MCPManager(self.servers) as mcp:
            tools = mcp.openai_tools()
            if not tools:
                return {"error": "no MCP tools available", "objective": objective}

            tool_names = [t["function"]["name"] for t in tools]
            self._log(
                f"[dim]loaded {len(tools)} tool(s) from {len(self.servers)} server(s)[/dim]"
            )

            # ---- Phase 1: explicit planning ----
            if plan is None and self.use_planner:
                planner = Planner(
                    model=self.model, base_url=self.base_url, api_key=self.api_key
                )
                try:
                    plan = planner.plan(objective, tool_names)
                    if self.verbose and plan.tasks:
                        self._log(
                            Panel(
                                plan.render(),
                                title="plan",
                                border_style="yellow",
                            )
                        )
                except Exception as e:  # noqa: BLE001
                    self._log(f"[yellow]planner failed, running react-only: {e}[/yellow]")

            plan_text = plan.render() if plan and plan.tasks else "(no explicit plan)"

            messages: list[dict[str, Any]] = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"## Objective\n{objective}\n\n## Plan\n{plan_text}",
                },
            ]

            # ---- Phase 2: reactive execution loop ----
            for step in range(1, self.max_steps + 1):
                steps_used = step

                messages.append(
                    {
                        "role": "system",
                        "content": (
                            f"## Current state (step {step}/{self.max_steps})\n"
                            f"{memory.summary()}\n\n"
                            f"## Recent observations\n{memory.recent(2)}"
                        ),
                    }
                )

                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=0.2,
                )
                msg = response.choices[0].message

                if msg.content and self.verbose:
                    self._log(
                        Panel(
                            msg.content.strip()[:1200],
                            title=f"step {step} · reasoning",
                            border_style="cyan",
                        )
                    )

                if not msg.tool_calls:
                    report = (msg.content or "").strip()
                    attack = map_findings(
                        {k: sorted(v) for k, v in memory.findings.items()},
                        [
                            {"tool": o.tool, "result": o.result}
                            for o in memory.observations
                        ],
                    )
                    return {
                        "objective": objective,
                        "steps": steps_used,
                        "report": report,
                        "findings": {k: sorted(v) for k, v in memory.findings.items()},
                        "attack_mapping": attack,
                        "plan": (
                            [
                                {"id": t.id, "task": t.task, "status": t.status,
                                 "intrusive": t.intrusive}
                                for t in plan.tasks
                            ]
                            if plan
                            else []
                        ),
                        "observations": len(memory.observations),
                    }

                messages.append(
                    {
                        "role": "assistant",
                        "content": msg.content,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                },
                            }
                            for tc in msg.tool_calls
                        ],
                    }
                )

                # Execute (possibly in parallel), then record + feed back.
                for tc, args, result in await self._execute_calls(mcp, msg.tool_calls):
                    self._log(
                        f"  → [bold]{tc.function.name}[/bold] "
                        f"{json.dumps(args, ensure_ascii=False)}"
                    )
                    short = result.replace("\n", " ")[:160]
                    self._log(f"     [green]✓[/green] {short}", style="dim")

                    memory.record(step, tc.function.name, args, result)
                    messages.append(
                        {"role": "tool", "tool_call_id": tc.id, "content": result}
                    )

                # ---- Phase 3: periodic re-planning ----
                if self.use_planner and plan and step % 3 == 0 and step < self.max_steps:
                    try:
                        planner = Planner(
                            model=self.model, base_url=self.base_url, api_key=self.api_key
                        )
                        action, new_plan = planner.revise(
                            objective, plan, memory.summary()
                        )
                        plan = new_plan
                        if action == "revise":
                            self._log(
                                Panel(
                                    plan.render(),
                                    title="plan revised",
                                    border_style="yellow",
                                )
                            )
                            messages.append(
                                {
                                    "role": "system",
                                    "content": f"## Revised plan\n{plan.render()}",
                                }
                            )
                        elif action == "done":
                            self._log("[green]planner says objective satisfied[/green]")
                    except Exception as e:  # noqa: BLE001
                        self._log(f"[dim]re-plan skipped: {e}[/dim]")

        attack = map_findings(
            {k: sorted(v) for k, v in memory.findings.items()},
            [{"tool": o.tool, "result": o.result} for o in memory.observations],
        )
        return {
            "objective": objective,
            "steps": steps_used,
            "report": "(max steps reached without a final report)",
            "findings": {k: sorted(v) for k, v in memory.findings.items()},
            "attack_mapping": attack,
            "plan": (
                [{"id": t.id, "task": t.task, "status": t.status} for t in plan.tasks]
                if plan
                else []
            ),
            "observations": len(memory.observations),
        }
