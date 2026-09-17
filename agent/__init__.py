"""SecAgent — an autonomous security assessment agent built on MCP."""

from .attack_map import map_findings
from .core import SecAgent
from .mcp_client import MCPManager, ToolSpec
from .memory import Memory, Observation
from .planner import Plan, Planner, Task
from . import report

__version__ = "0.2.0"
__all__ = [
    "SecAgent",
    "MCPManager",
    "ToolSpec",
    "Memory",
    "Observation",
    "Planner",
    "Plan",
    "Task",
    "map_findings",
    "report",
]
