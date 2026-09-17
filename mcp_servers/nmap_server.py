"""Nmap MCP Server — exposes nmap as MCP tools for AI agents."""

import asyncio
import json
import re
import shutil
import subprocess
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("nmap-server")


def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a command safely (list form, no shell) and return (code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd[0]}"


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="nmap_scan",
            description=(
                "Scan a target host/port range with nmap and return open ports and "
                "service versions. Use for reconnaissance against AUTHORIZED targets only."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "IP address, hostname, or CIDR range (e.g. 192.168.1.10)",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port spec, e.g. '80,443' or '1-1000'. Default: top 100 ports",
                        "default": "",
                    },
                    "service_detection": {
                        "type": "boolean",
                        "description": "Enable -sV version detection (slower)",
                        "default": True,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="nmap_vuln_scan",
            description=(
                "Run nmap NSE vulnerability scripts against a target to find known CVEs. "
                "Slow. Use only on authorized targets."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                    "ports": {"type": "string", "description": "Port spec", "default": ""},
                },
                "required": ["target"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if not shutil.which("nmap"):
        return [TextContent(type="text", text="error: nmap is not installed")]

    target = arguments.get("target", "").strip()
    if not target:
        return [TextContent(type="text", text="error: 'target' is required")]

    # Basic input hardening: reject shell metacharacters outright.
    if re.search(r"[;&|`$><\n]", target):
        return [TextContent(type="text", text="error: invalid characters in target")]

    ports = arguments.get("ports", "").strip()

    if name == "nmap_scan":
        cmd = ["nmap", "-Pn", "-T4", "--open"]
        if arguments.get("service_detection", True):
            cmd.append("-sV")
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)

    elif name == "nmap_vuln_scan":
        cmd = ["nmap", "-Pn", "-T4", "--script", "vuln"]
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)

    else:
        return [TextContent(type="text", text=f"error: unknown tool '{name}'")]

    code, out, err = _run(cmd, timeout=600)

    if code != 0 and not out:
        return [TextContent(type="text", text=f"nmap failed (exit {code}): {err}")]

    return [
        TextContent(
            type="text",
            text=json.dumps(
                {
                    "tool": name,
                    "target": target,
                    "command": " ".join(cmd),
                    "exit_code": code,
                    "output": out,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
    ]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
