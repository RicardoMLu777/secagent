"""HTTP probe MCP Server — lightweight web reconnaissance for AI agents."""

import asyncio
import json
import re
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

app = Server("httpx-server")

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _normalize(url: str) -> str:
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="http_probe",
            description=(
                "Fetch an HTTP(S) URL and return status code, response headers, page title, "
                "and detected server technology. Useful for web reconnaissance."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL or hostname"},
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds",
                        "default": 10,
                    },
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="check_security_headers",
            description=(
                "Audit a web response for missing security headers "
                "(HSTS, CSP, X-Frame-Options, etc.) and report which are absent."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL or hostname"}
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="check_robots",
            description="Fetch /robots.txt and return Disallow/Allow entries, which often reveal hidden paths.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target base URL or hostname"}
                },
                "required": ["url"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    url = _normalize(arguments.get("url", "").strip())
    if not url or url == "http://":
        return [TextContent(type="text", text="error: 'url' is required")]

    timeout = int(arguments.get("timeout", 10))

    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, verify=False
        ) as client:
            if name == "http_probe":
                r = await client.get(url)
                title_match = re.search(
                    r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S
                )
                server = r.headers.get("server", "unknown")
                powered = r.headers.get("x-powered-by", "")
                result = {
                    "url": str(r.url),
                    "status_code": r.status_code,
                    "server": server,
                    "x_powered_by": powered or None,
                    "content_type": r.headers.get("content-type"),
                    "content_length": len(r.content),
                    "title": title_match.group(1).strip()[:200] if title_match else None,
                    "redirected": str(r.url) != url,
                }

            elif name == "check_security_headers":
                r = await client.get(url)
                present = {
                    h: r.headers.get(h) for h in SECURITY_HEADERS if h in r.headers
                }
                missing = [h for h in SECURITY_HEADERS if h not in r.headers]
                result = {
                    "url": str(r.url),
                    "status_code": r.status_code,
                    "present": present,
                    "missing": missing,
                    "score": f"{len(present)}/{len(SECURITY_HEADERS)}",
                }

            elif name == "check_robots":
                base = re.match(r"^(https?://[^/]+)", url, re.I).group(1)
                r = await client.get(base + "/robots.txt")
                if r.status_code != 200:
                    result = {"url": base + "/robots.txt", "found": False,
                              "status_code": r.status_code}
                else:
                    paths = [
                        ln.strip()
                        for ln in r.text.splitlines()
                        if ln.strip() and not ln.strip().startswith("#")
                    ]
                    interesting = [
                        p for p in paths
                        if re.search(r"(admin|backup|config|private|secret|api|test|old)",
                                     p, re.I)
                    ]
                    result = {
                        "url": base + "/robots.txt",
                        "found": True,
                        "entries": paths[:100],
                        "interesting": interesting,
                    }

            else:
                return [TextContent(type="text", text=f"error: unknown tool '{name}'")]

    except httpx.RequestError as e:
        return [TextContent(type="text", text=f"request failed: {type(e).__name__}: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"error: {type(e).__name__}: {e}")]

    return [
        TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))
    ]


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
