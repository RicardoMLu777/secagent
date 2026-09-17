"""Engagement policy — gates intrusive actions behind explicit approval.

The agent should never decide on its own to run an intrusive tool (sqlmap,
vulnerability scripts, directory brute-forcing) against a target. Planning may
*propose* intrusive tasks, but execution requires a policy decision.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"
    """Pause and surface the request to a human."""


# Tools considered intrusive by default — they send attack traffic, not probes.
INTRUSIVE_TOOLS: set[str] = {
    "sqlmap_scan",
    "sqlmap_tables",
    "sqlmap_dump",
    "nmap_vuln_scan",
    "ffuf_dirs",
    "nmap_scan",  # port scanning is intrusive on production targets
}

# Read-only / passive tools that never need approval.
PASSIVE_TOOLS: set[str] = {
    "http_probe",
    "check_security_headers",
    "check_robots",
}


@dataclass
class ApprovalRequest:
    """A pending decision about whether to run an intrusive tool."""

    tool: str
    arguments: dict[str, Any]
    reason: str


@dataclass
class EngagementPolicy:
    """Decides whether a tool call is permitted.

    Modes
    -----
    passive   — only PASSIVE_TOOLS allowed; everything else denied
    ask       — passive auto-allowed, intrusive raises an approval request (default)
    allow     — everything allowed (requires an explicitly scoped engagement)
    """

    mode: str = "ask"
    allowed_tools: set[str] = field(default_factory=set)
    denied_tools: set[str] = field(default_factory=set)
    scope: list[str] = field(default_factory=list)
    deny_private_targets: bool = False
    approver: Callable[[ApprovalRequest], bool] | None = None

    def _is_intrusive(self, tool: str) -> bool:
        bare = tool.split("__", 1)[-1]
        return bare in INTRUSIVE_TOOLS

    def _target_in_scope(self, arguments: dict[str, Any]) -> tuple[bool, str]:
        """If a scope list is configured, every target must match it."""
        if not self.scope:
            return True, ""
        target = str(
            arguments.get("url") or arguments.get("target") or ""
        ).strip()
        if not target:
            return True, ""
        for pattern in self.scope:
            if re.search(pattern, target, re.I):
                return True, ""
        return False, f"target '{target}' is outside the declared scope"

    def _hits_denied_network(self, arguments: dict[str, Any]) -> tuple[bool, str]:
        if not self.deny_private_targets:
            return False, ""
        target = str(arguments.get("url") or arguments.get("target") or "")
        if re.search(
            r"(127\.|localhost|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)",
            target,
            re.I,
        ):
            return True, f"target '{target}' is a private/loopback address"
        return False, ""

    def evaluate(self, tool: str, arguments: dict[str, Any]) -> tuple[Decision, str]:
        """Returns (decision, reason)."""
        bare = tool.split("__", 1)[-1]

        if tool in self.denied_tools or bare in self.denied_tools:
            return Decision.DENY, f"'{bare}' is explicitly denied"

        in_scope, scope_reason = self._target_in_scope(arguments)
        if not in_scope:
            return Decision.DENY, scope_reason

        denied_net, net_reason = self._hits_denied_network(arguments)
        if denied_net:
            return Decision.DENY, net_reason

        if bare in PASSIVE_TOOLS:
            return Decision.ALLOW, "passive reconnaissance"

        if tool in self.allowed_tools or bare in self.allowed_tools:
            return Decision.ALLOW, "explicitly allowed"

        if self.mode == "passive":
            return Decision.DENY, f"policy mode 'passive' blocks '{bare}'"

        if self.mode == "allow":
            return Decision.ALLOW, "policy mode 'allow'"

        # mode == "ask"
        if self._is_intrusive(bare):
            return Decision.ASK, f"'{bare}' sends intrusive traffic and needs approval"

        # Unknown tools are treated conservatively.
        return Decision.ASK, f"'{bare}' is not classified as passive"

    def request_approval(self, tool: str, arguments: dict[str, Any], reason: str) -> bool:
        """Ask the configured approver. Returns True if the action may proceed."""
        req = ApprovalRequest(tool=tool, arguments=arguments, reason=reason)
        if self.approver is not None:
            return bool(self.approver(req))
        return False  # no approver configured -> fail closed

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EngagementPolicy":
        return cls(
            mode=data.get("mode", "ask"),
            allowed_tools=set(data.get("allowed_tools", [])),
            denied_tools=set(data.get("denied_tools", [])),
            scope=list(data.get("scope", [])),
            deny_private_targets=bool(data.get("deny_private_targets", False)),
        )

    def render(self) -> str:
        lines = [f"Engagement policy: mode={self.mode}"]
        if self.scope:
            lines.append(f"  scope: {', '.join(self.scope)}")
        if self.denied_tools:
            lines.append(f"  denied: {', '.join(sorted(self.denied_tools))}")
        if self.deny_private_targets:
            lines.append("  private/loopback targets: denied")
        return "\n".join(lines)


def render_denial(tool: str, reason: str) -> str:
    """The text fed back to the model when a tool call is blocked."""
    return json.dumps(
        {
            "blocked": True,
            "tool": tool,
            "reason": reason,
            "guidance": (
                "This action was blocked by the engagement policy. Do not retry it. "
                "Either continue with passive techniques or state in your report that "
                "the action requires explicit authorization."
            ),
        },
        ensure_ascii=False,
        indent=2,
    )
