#!/usr/bin/env python3
"""CLI entry point for SecAgent.

Usage:
    python secagent.py --target 192.168.1.10
    python secagent.py "Assess example.com web security"
    python secagent.py --target x --policy ask --report out/report.md
    python secagent.py history --target example.com
    python secagent.py diff 3 7
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent.core import SecAgent  # noqa: E402
from agent.policy import EngagementPolicy  # noqa: E402
from agent.store import Store  # noqa: E402
from agent import report as report_mod  # noqa: E402

console = Console()

ALL_SERVERS = [
    "nmap_server.py",
    "httpx_server.py",
    "sqlmap_server.py",
    "ffuf_server.py",
]
DEFAULT_SERVERS = ALL_SERVERS


def _load_dotenv() -> None:
    env_file = Path(__file__).resolve().parent / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _interactive_approver(req) -> bool:
    """Prompt on the terminal for intrusive actions."""
    console.print()
    console.print(
        Panel(
            f"[bold]{req.tool}[/bold]\n{json.dumps(req.arguments, ensure_ascii=False)}\n\n"
            f"[yellow]{req.reason}[/yellow]",
            title="⚠ approval required",
            border_style="yellow",
        )
    )
    try:
        answer = input("  Allow this action? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("y", "yes")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secagent",
        description="Autonomous security assessment agent powered by MCP tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python secagent.py --target 192.168.1.10\n"
            "  python secagent.py 'Audit example.com security headers'\n"
            "  python secagent.py --target x --policy passive\n"
            "  python secagent.py history --target example.com\n"
            "  python secagent.py diff 3 7\n"
        ),
    )
    sub = p.add_subparsers(dest="command")

    # ---- history ----
    hist = sub.add_parser("history", help="List past engagements")
    hist.add_argument("--target", "-t", help="Filter by target")
    hist.add_argument("--limit", type=int, default=20)

    # ---- diff ----
    diff = sub.add_parser("diff", help="Compare two engagements")
    diff.add_argument("a", type=int, help="Older engagement id")
    diff.add_argument("b", type=int, help="Newer engagement id")

    # ---- targets ----
    sub.add_parser("targets", help="List all assessed targets")

    # NOTE: no positional `objective` here — an argparse subparser would swallow
    # any first word, so "python secagent.py scan foo.com" would fail with
    # "invalid choice: 'scan'". Instead main() peels off a non-subcommand first
    # token before argparse sees it.
    p.add_argument("--target", "-t", help="Shorthand: build a recon objective for this target")
    p.add_argument(
        "--servers",
        nargs="+",
        default=DEFAULT_SERVERS,
        help=f"MCP server scripts (default: {' '.join(DEFAULT_SERVERS)})",
    )
    p.add_argument("--all-servers", action="store_true", help="Load every bundled server")
    p.add_argument("--model", help="LLM model name")
    p.add_argument("--max-steps", type=int, default=20, help="Max ReAct iterations")
    p.add_argument("--json", action="store_true", help="Emit the raw result as JSON")
    p.add_argument("--report", metavar="PATH", help="Write a Markdown report to PATH")
    p.add_argument("--no-planner", action="store_true", help="Disable the planning phase")
    p.add_argument("--no-parallel", action="store_true", help="Run tool calls sequentially")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress step-by-step output")

    # policy
    p.add_argument(
        "--policy",
        choices=["passive", "ask", "allow"],
        default="ask",
        help="Engagement policy mode (default: ask)",
    )
    p.add_argument(
        "--scope",
        nargs="+",
        default=[],
        help="Regex allowlist of in-scope targets; anything else is denied",
    )
    p.add_argument(
        "--deny-tools",
        nargs="+",
        default=[],
        help="Tool names to block outright",
    )
    p.add_argument(
        "--deny-private",
        action="store_true",
        help="Deny loopback/private-address targets (guards against SSRF-style mistakes)",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Auto-approve intrusive actions (only for authorized engagements)",
    )

    # persistence
    p.add_argument("--db", help="SQLite path for engagement history")
    p.add_argument("--no-store", action="store_true", help="Disable persistence")
    return p


def cmd_history(args) -> int:
    store = Store(args.db) if args.db else Store()
    rows = store.history(target=args.target, limit=args.limit)
    if not rows:
        console.print("[dim]no engagements recorded[/dim]")
        return 0

    t = Table(title="Engagement history")
    for col in ("ID", "Target", "Started", "Steps", "Calls", "Flags"):
        t.add_column(col)
    for r in rows:
        t.add_row(
            str(r["id"]),
            r["target"][:32],
            (r["started_at"] or "")[:19],
            str(r["steps"]),
            str(r["observations"]),
            ",".join(r["flags"])[:40] or "-",
        )
    console.print(t)
    return 0


def cmd_targets(args) -> int:
    store = Store(args.db) if getattr(args, "db", None) else Store()
    rows = store.targets()
    if not rows:
        console.print("[dim]no targets recorded[/dim]")
        return 0
    t = Table(title="Assessed targets")
    for col in ("Target", "Runs", "Last run"):
        t.add_column(col)
    for r in rows:
        t.add_row(r["target"][:40], str(r["runs"]), (r["last_run"] or "")[:19])
    console.print(t)
    return 0


def cmd_diff(args) -> int:
    store = Store(args.db) if getattr(args, "db", None) else Store()
    d = store.diff(args.a, args.b)
    if "error" in d:
        console.print(f"[red]{d['error']}[/red]")
        return 1

    console.print(
        f"[bold]{d['a']['target']}[/bold]  "
        f"#{d['a']['id']} ({d['a']['started_at'][:19]}) → "
        f"#{d['b']['id']} ({d['b']['started_at'][:19]})"
    )
    for key, ch in d["changes"].items():
        if ch["added"]:
            console.print(f"  [green]+ {key}:[/green] {', '.join(ch['added'])}")
        if ch["removed"]:
            console.print(f"  [red]- {key}:[/red] {', '.join(ch['removed'])}")
        if not ch["added"] and not ch["removed"]:
            console.print(f"  [dim]= {key}: no change ({ch['unchanged']})[/dim]")
    return 0


async def cmd_assess(args) -> int:
    servers = ALL_SERVERS if args.all_servers else args.servers

    objective = args.objective
    if not objective and args.target:
        objective = (
            f"Perform a security assessment of {args.target}. "
            "Enumerate open ports and services, probe any web service found, "
            "audit its security headers, review robots.txt, and discover hidden "
            "directories. Report concrete findings with evidence, a risk "
            "assessment, and recommended next steps."
        )
    if not objective:
        console.print("[red]error:[/red] provide an objective or --target")
        return 2

    policy = EngagementPolicy(
        mode=args.policy,
        allowed_tools=set(),
        denied_tools=set(args.deny_tools),
        scope=list(args.scope),
        deny_private_targets=args.deny_private,
        approver=(lambda _req: True) if args.yes else _interactive_approver,
    )
    store = None if args.no_store else (Store(args.db) if args.db else Store())

    agent = SecAgent(
        servers=servers,
        model=args.model,
        max_steps=args.max_steps,
        verbose=not args.quiet,
        use_planner=not args.no_planner,
        parallel=not args.no_parallel,
        policy=policy,
        store=store,
    )

    if not args.quiet:
        console.print(f"[dim]{policy.render()}[/dim]")

    try:
        result = await agent.run(objective)
    except RuntimeError as e:
        console.print(f"[red]error:[/red] {e}")
        return 1

    if args.report:
        path = report_mod.save(result, args.report, fmt="md")
        console.print(f"[green]report written:[/green] {path}")

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    console.print()
    console.print(
        Panel(
            result.get("report", "(no report)"),
            title=f"SecAgent report · {result.get('steps', 0)} step(s)",
            border_style="green",
        )
    )

    findings = result.get("findings", {})
    flags = findings.get("flags") or []
    if flags:
        console.print(f"[bold yellow]Flags:[/bold yellow] {', '.join(flags)}")

    attack = result.get("attack_mapping", {})
    techs = attack.get("techniques") or []
    if techs:
        console.print(f"[dim]ATT&CK: {', '.join(t['id'] for t in techs)}[/dim]")

    audit = result.get("tool_audit") or []
    blocked = [a for a in audit if a.get("decision") in ("deny", "ask-denied")]
    if blocked:
        console.print(
            f"[yellow]{len(blocked)} action(s) blocked by policy[/yellow]"
        )

    if result.get("engagement_id"):
        console.print(f"[dim]saved as engagement #{result['engagement_id']}[/dim]")

    return 0


def _split_objective(argv: list[str]) -> tuple[list[str], str | None]:
    """Peel a non-subcommand leading token out of argv as the objective.

    argparse subparsers consume the first positional and reject anything that
    isn't a known command, so `secagent.py "scan foo.com"` would die with
    "invalid choice". Extracting the objective first keeps both forms working.
    """
    subcommands = {"history", "diff", "targets"}
    if not argv:
        return argv, None

    first = argv[0]
    if first in subcommands or first.startswith("-"):
        return argv, None

    return argv[1:], first


def main() -> int:
    _load_dotenv()
    argv, objective = _split_objective(sys.argv[1:])
    args = build_parser().parse_args(argv)
    args.objective = objective

    if args.command == "history":
        return cmd_history(args)
    if args.command == "targets":
        return cmd_targets(args)
    if args.command == "diff":
        return cmd_diff(args)

    return asyncio.run(cmd_assess(args))


if __name__ == "__main__":
    raise SystemExit(main())
