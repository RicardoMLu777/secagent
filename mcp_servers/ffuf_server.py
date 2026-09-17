"""Web fuzzer MCP Server — ffuf wrapper for directory and parameter discovery."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("ffuf-server")

SAFE_HOST = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")

# Bundled mini wordlist so the server works without SecLists installed.
MINI_WORDLIST = [
    "admin", "admin.php", "login", "login.php", "config", "config.php",
    "backup", "backup.zip", "www.zip", "robots.txt", "sitemap.xml",
    "api", "api/v1", "uploads", "upload", "files", "download", "download.php",
    "test", "test.php", "info.php", "phpinfo.php", "status", "health",
    "phpmyadmin", "server-status", "db", "database", "sql", "dump.sql",
    ".git", ".env", ".htaccess", "backup.sql", "old", "dev", "staging",
]


def _write_wordlist(words: list[str]) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    f.write("\n".join(words))
    f.close()
    return f.name


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ffuf_dirs",
            description=(
                "Brute-force directories and files on a web server using ffuf. "
                "Returns discovered paths with HTTP status codes and sizes. "
                "Use the built-in mini wordlist or supply your own word list path."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Base URL containing FUZZ, e.g. http://site/FUZZ or http://site/FUZZ.php",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to a wordlist file. If omitted, uses the built-in mini list.",
                        "default": "",
                    },
                    "extensions": {
                        "type": "string",
                        "description": "Comma-separated extensions to append, e.g. 'php,html,txt'",
                        "default": "",
                    },
                    "filter_status": {
                        "type": "string",
                        "description": "Comma-separated status codes to filter out, e.g. '404'",
                        "default": "404",
                    },
                },
                "required": ["url"],
            },
        ),
    ]


def _parse_ffuf(output: str) -> list[dict[str, Any]]:
    """Extract hits from ffuf's log output."""
    hits: list[dict[str, Any]] = []
    # Format: word [Status: 200, Size: 1234, Words: 56, Lines: 7, Duration: 12ms]
    for m in re.finditer(
        r"([^\s]+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),.*?Duration:\s*([^\]]+)\]",
        output,
    ):
        hits.append(
            {
                "path": m.group(1),
                "status": int(m.group(2)),
                "size": int(m.group(3)),
                "duration": m.group(4).strip(),
            }
        )
    return hits


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if not shutil.which("ffuf"):
        return [TextContent(type="text", text="error: ffuf is not installed")]

    if name != "ffuf_dirs":
        return [TextContent(type="text", text=f"error: unknown tool '{name}'")]

    url = arguments.get("url", "").strip()
    if not url or "FUZZ" not in url or not SAFE_HOST.match(url.replace("FUZZ", "x")):
        return [
            TextContent(
                type="text", text="error: url must be http(s) and contain the FUZZ keyword"
            )
        ]

    wordlist = arguments.get("wordlist", "").strip()
    tmp_wl = None
    if wordlist:
        if not Path(wordlist).is_file():
            return [TextContent(type="text", text=f"error: wordlist not found: {wordlist}")]
    else:
        wl_path = _write_wordlist(MINI_WORDLIST)
        tmp_wl = wl_path
        wordlist = wl_path

    cmd = [
        "ffuf", "-u", url, "-w", wordlist,
        "-mc", "200,201,204,301,302,307,401,403,405,500",
        "-fc", arguments.get("filter_status", "404"),
        "-t", "40", "-timeout", "10", "-noninteractive", "-s",
    ]

    exts = arguments.get("extensions", "").strip()
    if exts:
        if not re.fullmatch(r"[A-Za-z0-9,]+", exts):
            return [TextContent(type="text", text="error: invalid extensions")]
        cmd += ["-e", ",".join("." + e for e in exts.split(","))]

    try:
        code, out, err = (lambda r: (r.returncode, r.stdout, r.stderr))(
            subprocess.run(cmd, capture_output=True, text=True, timeout=420, check=False)
        )
    except subprocess.TimeoutExpired:
        return [TextContent(type="text", text="error: ffuf timed out after 420s")]
    finally:
        if tmp_wl:
            Path(tmp_wl).unlink(missing_ok=True)

    hits = _parse_ffuf(out)
    payload = {
        "tool": "ffuf_dirs",
        "url": url,
        "exit_code": code,
        "hits_found": len(hits),
        "hits": hits[:60],
        "interesting": [
            h for h in hits
            if re.search(r"(admin|backup|config|sql|\.git|\.env|upload|api|dump)",
                         h["path"], re.I)
        ][:20],
    }
    if not hits and err:
        payload["stderr_tail"] = err[-800:]

    return [TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, indent=2))]


async def main() -> None:
    async with stdio_server() as (r, w):
        await app.run(r, w, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
