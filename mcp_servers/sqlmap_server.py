"""sqlmap MCP Server — SQL injection detection for AI agents.

Wrapper around sqlmap with strict output parsing. Only detects; never
auto-exploits data unless the caller explicitly asks for dump.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("sqlmap-server")

SAFE_URL = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd[0]}"


def _parse(output: str) -> dict[str, Any]:
    """Pull the structured signal out of sqlmap's chatty log."""
    info: dict[str, Any] = {
        "injectable": False,
        "injection_types": [],
        "dbms": None,
        "databases": [],
        "parameters": [],
    }

    if "is vulnerable" in output or "appears to be injectable" in output:
        info["injectable"] = True

    for m in re.finditer(r"Type:\s*(.+)", output):
        t = m.group(1).strip()
        if t not in info["injection_types"]:
            info["injection_types"].append(t)

    for m in re.finditer(r"Parameter:\s*(\S+)", output):
        p = m.group(1).strip()
        if p not in info["parameters"]:
            info["parameters"].append(p)

    m = re.search(r"back-end DBMS:\s*(.+)", output)
    if m:
        info["dbms"] = m.group(1).strip()

    db_block = re.search(r"available databases \[\d+\]:\n((?:\[\*\] .+\n?)+)", output)
    if db_block:
        info["databases"] = re.findall(r"\[\*\]\s*(\S+)", db_block.group(1))

    # table listings
    tables = re.findall(r"^\|\s*(\w+)\s*\|", output, re.M)
    if tables:
        info["possible_tables"] = sorted(set(tables))[:50]

    return info


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="sqlmap_scan",
            description=(
                "Test a URL parameter for SQL injection using sqlmap. Returns injection "
                "type, backend DBMS, and (if found) the database list. "
                "Only use on AUTHORIZED targets."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Full URL with parameter, e.g. http://site/news.php?id=1",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST"],
                        "default": "GET",
                        "description": "HTTP method for the injection point",
                    },
                    "data": {
                        "type": "string",
                        "description": "POST body when method=POST, e.g. 'user=1&pass=2'",
                        "default": "",
                    },
                    "level": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5,
                        "default": 2,
                        "description": "sqlmap --level (higher = more tests, slower)",
                    },
                    "enumerate_dbs": {
                        "type": "boolean",
                        "default": True,
                        "description": "Enumerate database names if injection is confirmed",
                    },
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="sqlmap_tables",
            description=(
                "List tables in a specific database after sqlmap_scan confirmed injection."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Injection URL"},
                    "database": {"type": "string", "description": "Target database name"},
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                    "data": {"type": "string", "default": ""},
                },
                "required": ["url", "database"],
            },
        ),
        Tool(
            name="sqlmap_dump",
            description=(
                "Dump a table's contents. Requires explicit column/table names. "
                "Use only when the engagement permits data extraction."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Injection URL"},
                    "database": {"type": "string", "description": "Database name"},
                    "table": {"type": "string", "description": "Table name"},
                    "columns": {
                        "type": "string",
                        "description": "Optional comma-separated columns to limit the dump",
                        "default": "",
                    },
                    "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                    "data": {"type": "string", "default": ""},
                },
                "required": ["url", "database", "table"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if not shutil.which("sqlmap"):
        return [TextContent(type="text", text="error: sqlmap is not installed")]

    url = arguments.get("url", "").strip()
    if not url or not SAFE_URL.match(url):
        return [TextContent(type="text", text="error: invalid or missing 'url'")]

    method = arguments.get("method", "GET").upper()
    data = arguments.get("data", "").strip()

    cmd = ["sqlmap", "-u", url, "--batch", "--flush-session", "--disable-coloring"]

    if method == "POST":
        if not data:
            return [TextContent(type="text", text="error: method=POST requires 'data'")]
        cmd += ["--data", data]

    if name == "sqlmap_scan":
        cmd += [f"--level={int(arguments.get('level', 2))}", "--risk=1"]
        if arguments.get("enumerate_dbs", True):
            cmd.append("--dbs")
        timeout = 600

    elif name == "sqlmap_tables":
        db = arguments.get("database", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_$]+", db):
            return [TextContent(type="text", text="error: invalid database name")]
        cmd += ["-D", db, "--tables"]
        timeout = 600

    elif name == "sqlmap_dump":
        db = arguments.get("database", "").strip()
        tbl = arguments.get("table", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_$]+", db) or not re.fullmatch(r"[A-Za-z0-9_$]+", tbl):
            return [TextContent(type="text", text="error: invalid database/table name")]
        cmd += ["-D", db, "-T", tbl, "--dump"]
        cols = arguments.get("columns", "").strip()
        if cols:
            if not re.fullmatch(r"[A-Za-z0-9_,]+", cols):
                return [TextContent(type="text", text="error: invalid column list")]
            cmd += ["-C", cols]
        timeout = 900

    else:
        return [TextContent(type="text", text=f"error: unknown tool '{name}'")]

    code, out, err = _run(cmd, timeout)
    combined = out + "\n" + err

    payload = {
        "tool": name,
        "url": url,
        "exit_code": code,
        "parsed": _parse(combined),
        "raw_tail": combined[-3000:],
    }
    return [TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))]


async def main() -> None:
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
