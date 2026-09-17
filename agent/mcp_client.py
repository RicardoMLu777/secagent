"""MCP client manager — spawns MCP servers and exposes their tools to the agent."""

from __future__ import annotations

import json
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = PROJECT_ROOT / "mcp_servers"


@dataclass
class ToolSpec:
    """A tool discovered from an MCP server, in OpenAI function-calling shape."""

    name: str
    description: str
    parameters: dict[str, Any]
    server: str

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class MCPManager:
    """Owns the lifecycle of every MCP server subprocess and their sessions."""

    server_scripts: list[str] = field(default_factory=list)
    _sessions: dict[str, ClientSession] = field(default_factory=dict, init=False)
    _tools: dict[str, ToolSpec] = field(default_factory=dict, init=False)
    _stack: AsyncExitStack | None = field(default=None, init=False)

    async def __aenter__(self) -> "MCPManager":
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()

        for script in self.server_scripts:
            path = SERVER_DIR / script
            if not path.exists():
                print(f"[mcp] warning: {path} not found, skipping", file=sys.stderr)
                continue

            params = StdioServerParameters(
                command=sys.executable, args=[str(path)], env=None
            )
            try:
                read, write = await self._stack.enter_async_context(stdio_client(params))
                session = await self._stack.enter_async_context(
                    ClientSession(read, write)
                )
                await session.initialize()

                server_name = script.replace(".py", "")
                self._sessions[server_name] = session

                listed = await session.list_tools()
                for t in listed.tools:
                    # Namespace tool names by server to avoid collisions.
                    qualified = f"{server_name}__{t.name}"
                    self._tools[qualified] = ToolSpec(
                        name=qualified,
                        description=t.description or "",
                        parameters=t.inputSchema or {"type": "object", "properties": {}},
                        server=server_name,
                    )
                print(
                    f"[mcp] {server_name}: {len(listed.tools)} tool(s)", file=sys.stderr
                )
            except Exception as e:  # noqa: BLE001 - keep other servers alive
                print(f"[mcp] failed to start {script}: {e}", file=sys.stderr)

        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._stack:
            await self._stack.__aexit__(*exc)

    @property
    def tools(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def openai_tools(self) -> list[dict[str, Any]]:
        return [t.to_openai() for t in self._tools.values()]

    async def call(self, qualified_name: str, arguments: dict[str, Any]) -> str:
        """Invoke a tool by its namespaced name and return its text result."""
        spec = self._tools.get(qualified_name)
        if spec is None:
            return f"error: unknown tool '{qualified_name}'"

        session = self._sessions[spec.server]
        raw_name = qualified_name.split("__", 1)[1]

        try:
            result = await session.call_tool(raw_name, arguments)
        except Exception as e:  # noqa: BLE001
            return f"error calling {qualified_name}: {type(e).__name__}: {e}"

        chunks: list[str] = []
        for block in result.content:
            text = getattr(block, "text", None)
            if text:
                chunks.append(text)

        return "\n".join(chunks) if chunks else json.dumps({"status": "no output"})
