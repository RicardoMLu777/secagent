"""Tests for the ReAct loop using a mocked LLM and mocked MCP layer.

These cover the control flow — parallel dispatch, policy gating, memory
recording, and final-result assembly — without touching a real model or
spawning MCP subprocesses.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.core import SecAgent
from agent.policy import EngagementPolicy


def _tool_call(name: str, args: str, call_id: str = "c1"):
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=args),
    )


def _response(content: str | None, tool_calls=None):
    msg = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def _agent(**kw) -> SecAgent:
    defaults = dict(
        servers=["nmap_server.py"],
        model="test-model",
        base_url="http://localhost",
        api_key="test-key",
        verbose=False,
        use_planner=False,
        policy=EngagementPolicy(mode="allow"),
        retry_attempts=1,
    )
    defaults.update(kw)
    return SecAgent(**defaults)


class FakeMCP:
    """Stand-in for MCPManager that records what was called."""

    def __init__(self, tools=None, results=None):
        self.calls: list[tuple[str, dict]] = []
        # NOTE: `tools or [...]` would turn [] into the default — check None explicitly.
        self._tools = ["nmap_server__nmap_scan"] if tools is None else tools
        self._results = results or {}

    def openai_tools(self):
        return [{"type": "function", "function": {"name": n, "description": "", "parameters": {}}}
                for n in self._tools]

    async def call(self, name, args):
        self.calls.append((name, args))
        return self._results.get(name, '{"status_code": 200}')

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


@pytest.mark.asyncio
async def test_single_tool_call_then_report():
    agent = _agent()
    fake = FakeMCP(results={"nmap_server__nmap_scan": "22/tcp open ssh\n80/tcp open http"})

    responses = [
        _response(None, [_tool_call("nmap_server__nmap_scan", '{"target": "x"}')]),
        _response("### Findings\nPorts 22 and 80 are open."),
    ]
    agent.client = MagicMock()
    agent.client.chat.completions.create = MagicMock(side_effect=responses)

    with patch("agent.core.MCPManager", return_value=fake):
        result = await agent.run("scan x")

    assert result["steps"] == 2
    assert "22" in result["findings"]["open_ports"]
    assert "Findings" in result["report"]
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_parallel_dispatch_of_multiple_tools():
    agent = _agent()
    fake = FakeMCP(
        tools=["httpx_server__http_probe", "httpx_server__check_robots"],
        results={
            "httpx_server__http_probe": '{"server": "nginx"}',
            "httpx_server__check_robots": '{"entries": ["/admin"]}',
        },
    )
    responses = [
        _response(None, [
            _tool_call("httpx_server__http_probe", '{"url": "http://x"}', "c1"),
            _tool_call("httpx_server__check_robots", '{"url": "http://x"}', "c2"),
        ]),
        _response("done"),
    ]
    agent.client = MagicMock()
    agent.client.chat.completions.create = MagicMock(side_effect=responses)

    with patch("agent.core.MCPManager", return_value=fake):
        result = await agent.run("probe x")

    assert len(fake.calls) == 2
    assert "nginx" in list(result["findings"]["technologies"])
    assert "/admin" in result["findings"]["interesting_paths"]


@pytest.mark.asyncio
async def test_policy_denies_and_feeds_back_to_model():
    agent = _agent(policy=EngagementPolicy(mode="passive"))
    fake = FakeMCP(tools=["sqlmap_server__sqlmap_scan"])

    responses = [
        _response(None, [_tool_call("sqlmap_server__sqlmap_scan", '{"url": "http://x"}')]),
        _response("blocked, reporting instead"),
    ]
    agent.client = MagicMock()
    agent.client.chat.completions.create = MagicMock(side_effect=responses)

    with patch("agent.core.MCPManager", return_value=fake):
        result = await agent.run("test injection")

    # The tool must never have been invoked.
    assert fake.calls == []
    # And the audit log should show the denial.
    assert any(a["decision"] == "deny" for a in result["tool_audit"])


@pytest.mark.asyncio
async def test_ask_mode_without_approver_fails_closed():
    agent = _agent(policy=EngagementPolicy(mode="ask"))  # no approver configured
    fake = FakeMCP(tools=["sqlmap_server__sqlmap_scan"])

    responses = [
        _response(None, [_tool_call("sqlmap_server__sqlmap_scan", '{"url": "http://x"}')]),
        _response("could not run"),
    ]
    agent.client = MagicMock()
    agent.client.chat.completions.create = MagicMock(side_effect=responses)

    with patch("agent.core.MCPManager", return_value=fake):
        result = await agent.run("test injection")

    assert fake.calls == []
    assert any(a["decision"] == "ask-denied" for a in result["tool_audit"])


@pytest.mark.asyncio
async def test_ask_mode_with_approver_proceeds():
    agent = _agent(policy=EngagementPolicy(mode="ask", approver=lambda req: True))
    fake = FakeMCP(
        tools=["sqlmap_server__sqlmap_scan"],
        results={"sqlmap_server__sqlmap_scan": '{"injectable": true}'},
    )

    responses = [
        _response(None, [_tool_call("sqlmap_server__sqlmap_scan", '{"url": "http://x"}')]),
        _response("found injection"),
    ]
    agent.client = MagicMock()
    agent.client.chat.completions.create = MagicMock(side_effect=responses)

    with patch("agent.core.MCPManager", return_value=fake):
        result = await agent.run("test injection")

    assert len(fake.calls) == 1
    assert any(t["id"] == "T1190" for t in result["attack_mapping"]["techniques"])


@pytest.mark.asyncio
async def test_max_steps_terminates_gracefully():
    agent = _agent(max_steps=2)
    fake = FakeMCP()

    # Model keeps asking for tools forever.
    agent.client = MagicMock()
    agent.client.chat.completions.create = MagicMock(
        return_value=_response(None, [_tool_call("nmap_server__nmap_scan", '{"target": "x"}')])
    )

    with patch("agent.core.MCPManager", return_value=fake):
        result = await agent.run("never finishes")

    assert result["steps"] == 2
    assert "max steps" in result["report"]
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_no_tools_available_returns_error():
    agent = _agent()
    fake = FakeMCP(tools=[])
    agent.client = MagicMock()  # should never be called

    with patch("agent.core.MCPManager", return_value=fake):
        result = await agent.run("nothing to do")

    assert "error" in result
    agent.client.chat.completions.create.assert_not_called()


@pytest.mark.asyncio
async def test_store_persists_engagement(tmp_path):
    from agent.store import Store

    store = Store(tmp_path / "t.db")
    agent = _agent(store=store)
    fake = FakeMCP(results={"nmap_server__nmap_scan": "443/tcp open https"})

    responses = [
        _response(None, [_tool_call("nmap_server__nmap_scan", '{"target": "example.com"}')]),
        _response("report body"),
    ]
    agent.client = MagicMock()
    agent.client.chat.completions.create = MagicMock(side_effect=responses)

    with patch("agent.core.MCPManager", return_value=fake):
        result = await agent.run("scan example.com")

    assert result.get("engagement_id")
    rec = store.get(result["engagement_id"])
    assert rec["steps"] == 2
    assert len(rec["tool_calls"]) == 1
