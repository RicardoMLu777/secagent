"""Agent memory — keeps the observation trail and summarises findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Observation:
    step: int
    tool: str
    arguments: dict[str, Any]
    result: str


@dataclass
class Memory:
    """Short-term working memory for a single engagement.

    Two tiers:
      - raw observations (full tool output, trimmed to a budget)
      - distilled findings (ports, services, missing headers, paths)
    """

    max_result_chars: int = 4000
    observations: list[Observation] = field(default_factory=list)
    findings: dict[str, set[str]] = field(
        default_factory=lambda: {
            "open_ports": set(),
            "services": set(),
            "technologies": set(),
            "missing_headers": set(),
            "interesting_paths": set(),
            "flags": set(),
        }
    )

    def record(self, step: int, tool: str, arguments: dict[str, Any], result: str) -> None:
        trimmed = result[: self.max_result_chars]
        if len(result) > self.max_result_chars:
            trimmed += f"\n... [truncated {len(result) - self.max_result_chars} chars]"
        self.observations.append(Observation(step, tool, arguments, trimmed))
        self._distil(tool, result)

    def _distil(self, tool: str, result: str) -> None:
        """Pull structured facts out of raw tool output."""
        # nmap: "80/tcp   open  http    nginx 1.18.0"
        for m in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?", result):
            port, service, version = m.group(1), m.group(2), m.group(3)
            self.findings["open_ports"].add(port)
            self.findings["services"].add(service)
            if version:
                self.findings["services"].add(version.strip()[:60])

        # server / x-powered-by style fingerprints
        for m in re.finditer(r'"(?:server|x_powered_by|content_type)"\s*:\s*"([^"]+)"', result):
            self.findings["technologies"].add(m.group(1))

        # missing security headers list
        for m in re.finditer(r'"(strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy)"', result):
            self.findings["missing_headers"].add(m.group(1))

        # robots.txt / directory paths
        for m in re.finditer(r'"/([A-Za-z0-9_\-./]{1,60})"', result):
            self.findings["interesting_paths"].add("/" + m.group(1))

        # capture any flags (ctf-style and generic key patterns)
        for m in re.finditer(r"flag\{[^}]{1,120}\}", result, re.I):
            self.findings["flags"].add(m.group(0))

    def summary(self) -> str:
        """Compact state block injected into the system prompt each turn."""
        f = self.findings
        lines = ["### Accumulated findings"]

        def fmt(key: str, limit: int = 12) -> str:
            vals = sorted(f[key])
            if not vals:
                return "(none)"
            shown = ", ".join(vals[:limit])
            if len(vals) > limit:
                shown += f" ... (+{len(vals) - limit} more)"
            return shown

        lines.append(f"- Open ports: {fmt('open_ports')}")
        lines.append(f"- Services/versions: {fmt('services')}")
        lines.append(f"- Technologies: {fmt('technologies', 8)}")
        lines.append(f"- Missing security headers: {fmt('missing_headers', 8)}")
        lines.append(f"- Interesting paths: {fmt('interesting_paths', 10)}")
        if f["flags"]:
            lines.append(f"- **FLAGS FOUND: {fmt('flags', 5)}**")

        lines.append(f"- Tool calls so far: {len(self.observations)}")
        return "\n".join(lines)

    def recent(self, n: int = 3) -> str:
        """The last n observations, so the model sees its immediate context."""
        if not self.observations:
            return "(no tool calls yet)"
        out = []
        for obs in self.observations[-n:]:
            out.append(f"[step {obs.step}] {obs.tool}({obs.arguments})\n-> {obs.result[:800]}")
        return "\n\n".join(out)
