"""Engagement policy — gates intrusive actions behind explicit approval.

The agent should never decide on its own to run an intrusive tool (sqlmap,
vulnerability scripts, directory brute-forcing) against a target. Planning may
*propose* intrusive tasks, but execution requires a policy decision.
"""

from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from ipaddress import ip_address, ip_network
from typing import Any, Callable
from urllib.parse import urlsplit


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


# Loopback and RFC1918 ranges rejected by --deny-private.
PRIVATE_NETWORKS: tuple = (
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
)


def _as_ip(host: str):
    """Return an ip_address object, or None when the string is not an IP literal."""
    try:
        return ip_address(host)
    except ValueError:
        return None


def _is_private_addr(ip) -> bool:
    return any(ip in net for net in PRIVATE_NETWORKS)


@lru_cache(maxsize=256)
def _default_resolve(host: str) -> tuple[str, ...]:
    """Resolve a hostname to its addresses.

    Cached for the life of the process: the policy gate runs on every tool call
    and there is no point re-resolving the same name within one engagement.
    Failures are not cached, so a transient DNS error gets retried.
    """
    infos = socket.getaddrinfo(host, None)
    return tuple(sorted({info[4][0] for info in infos}))


def _extract_host(target: str) -> str:
    """Pull the hostname out of a URL or a bare ``host[:port]`` target.

    Scope checks must run against the hostname, not the raw string: matching a
    pattern anywhere inside a full URL lets ``http://example.com.attacker.net``
    satisfy a scope entry of ``example.com``, because the authorised name also
    appears as a prefix of the attacker-controlled host.

    Returns an empty string when the target cannot be parsed, which callers
    treat as "not in scope" rather than "in scope".
    """
    t = target.strip()
    if not t:
        return ""
    if "://" not in t:
        t = "//" + t
    try:
        return (urlsplit(t).hostname or "").lower()
    except ValueError:
        return ""


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
    resolve_targets: bool = False
    resolver: Callable[[str], tuple[str, ...]] | None = None
    approver: Callable[[ApprovalRequest], bool] | None = None

    def _is_intrusive(self, tool: str) -> bool:
        bare = tool.split("__", 1)[-1]
        return bare in INTRUSIVE_TOOLS

    def _target_in_scope(self, arguments: dict[str, Any]) -> tuple[bool, str]:
        """If a scope list is configured, the target hostname must match one entry fully.

        Patterns are matched against the hostname alone (never the full URL) and
        must match the whole host, so ``example.com`` does not authorise
        ``example.com.attacker.net`` or ``evilexample.com``. Use
        ``.*\\.example\\.com`` to permit subdomains.
        """
        if not self.scope:
            return True, ""

        raw = str(arguments.get("url") or arguments.get("target") or "").strip()
        if not raw:
            return True, ""

        host = _extract_host(raw)
        if not host:
            return False, f"target '{raw}' could not be parsed as a hostname"

        for pattern in self.scope:
            if re.fullmatch(pattern, host, re.I):
                return True, ""
        return False, f"target '{host}' is outside the declared scope"

    def _hits_denied_network(self, arguments: dict[str, Any]) -> tuple[bool, str]:
        """Reject loopback and RFC1918 targets when private targets are banned.

        IP literals are range-checked directly. Hostnames are only checked when
        ``resolve_targets`` is on, in which case *every* address the name resolves
        to has to be public. Resolution is injectable so tests never touch the
        network, and it fails closed: an unresolvable name is denied rather than
        waved through.

        This cannot stop DNS rebinding. The tools resolve the name again when
        they connect, so a name whose answer changes after this check still
        reaches the private address. Pinning the checked IP for the connection
        would be the real fix, and that requires controlling the tool's sockets.
        """
        if not self.deny_private_targets:
            return False, ""

        raw = str(arguments.get("url") or arguments.get("target") or "")
        host = _extract_host(raw) or raw.strip().lower()
        if not host:
            return False, ""

        if host == "localhost":
            return True, f"target '{host}' is a loopback address"

        literal = _as_ip(host)
        if literal is not None:
            if _is_private_addr(literal):
                return True, f"target '{host}' is a private/loopback address"
            return False, ""

        if not self.resolve_targets:
            return False, ""

        resolve = self.resolver or _default_resolve
        try:
            addresses = resolve(host)
        except (OSError, ValueError) as exc:
            return True, f"'{host}' could not be resolved to confirm it is public ({exc})"

        if not addresses:
            return True, f"'{host}' resolved to no addresses"

        for addr in addresses:
            ip = _as_ip(addr)
            if ip is not None and _is_private_addr(ip):
                return True, f"'{host}' resolves to the private address {addr}"
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
            resolve_targets=bool(data.get("resolve_targets", False)),
        )

    def render(self) -> str:
        lines = [f"Engagement policy: mode={self.mode}"]
        if self.scope:
            lines.append(f"  scope: {', '.join(self.scope)}")
        if self.denied_tools:
            lines.append(f"  denied: {', '.join(sorted(self.denied_tools))}")
        if self.deny_private_targets:
            suffix = ", hostnames resolved" if self.resolve_targets else ""
            lines.append(f"  private/loopback targets: denied{suffix}")
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
