#!/usr/bin/env python3
"""CLI entry point for SecAgent.

Usage:
    python secagent.py --target 192.168.1.10
    python secagent.py "Assess example.com web security"
    python secagent.py --target example.com --report out/report.md
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

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent.core import SecAgent  # noqa: E402
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
    """Minimal .env loader so the CLI works without python-dotenv installed."""
    env_file = Path(__file__).resolve().parent / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secagent",
        description="Autonomous security assessment agent powered by MCP tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python secagent.py --target 192.168.1.10\n"
            "  python secagent.py 'Audit example.com security headers'\n"
            "  python secagent.py --target site.com --report out/site.md\n"
        ),
    )
    p.add_argument("objective", nargs="?", help="Natural-language objective for the agent")
    p.add_argument("--target", "-t", help="Shorthand: build a recon objective for this target")
    p.add_argument(
        "--servers",
        nargs="+",
        default=DEFAULT_SERVERS,
        help=f"MCP server scripts to load (default: {' '.join(DEFAULT_SERVERS)})",
    )
    p.add_argument("--all-servers", action="store_true", help="Load every bundled server")
    p.add_argument("--model", help="LLM model name (default: $SECAGENT_MODEL)")
    p.add_argument("--max-steps", type=int, default=20, help="Max ReAct iterations")
    p.add_argument("--json", action="store_true", help="Emit the raw result as JSON")
    p.add_argument(
        "--report", metavar="PATH", help="Write a Markdown report to PATH (.md)"
    )
    p.add_argument(
        "--no-planner", action="store_true", help="Disable the explicit planning phase"
    )
    p.add_argument(
        "--no-parallel", action="store_true", help="Execute tool calls sequentially"
    )
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress step-by-step output")
    return p


async def main() -> int:
    _load_dotenv()
    args = build_parser().parse_args()

    servers = ALL_SERVERS if args.all_servers else args.servers

    objective = args.objective
    if not objective and args.target:
        objective = (
            f"Perform a security assessment of {args.target}. "
            "Enumerate open ports and services, probe any web service found, "
            "audit its security headers, review robots.txt, and discover hidden "
            "directories. If you find web parameters, test for injection. "
            "Report concrete findings with evidence, a risk assessment, and "
            "recommended next steps."
        )
    if not objective:
        console.print("[red]error:[/red] provide an objective or --target")
        return 2

    agent = SecAgent(
        servers=servers,
        model=args.model,
        max_steps=args.max_steps,
        verbose=not args.quiet,
        use_planner=not args.no_planner,
        parallel=not args.no_parallel,
    )

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
        console.print(
            f"[dim]ATT&CK: {', '.join(t['id'] for t in techs)}[/dim]"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
