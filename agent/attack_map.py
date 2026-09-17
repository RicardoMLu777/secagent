"""MITRE ATT&CK mapping — turns raw findings into framework-referenced techniques.

Keeps a compact local table of the techniques a reconnaissance/exploitation
agent realistically observes, so reports can cite ATT&CK IDs without a network
round-trip to the ATT&CK API.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


# Signal (tool + regex on output) -> ATT&CK technique
RULES: list[tuple[str, str, Technique]] = [
    # T1046 Network Service Discovery
    (r"nmap_scan", r"/tcp\s+open", Technique("T1046", "Network Service Discovery", "Discovery")),
    (r"nmap_scan", r"Host is up", Technique("T1046", "Network Service Discovery", "Discovery")),
    # T1595 Active Scanning
    (r"nmap_vuln_scan", r".", Technique("T1595", "Active Scanning", "Reconnaissance")),
    # T1592 Gather Victim Host Information
    (r"http_probe", r'"server"', Technique("T1592", "Gather Victim Host Information", "Reconnaissance")),
    (r"http_probe", r'"x_powered_by"', Technique("T1592", "Gather Victim Host Information", "Reconnaissance")),
    # T1590 Gather Victim Network Information
    (r"check_robots", r'"entries"', Technique("T1590", "Gather Victim Network Information", "Reconnaissance")),
    # T1083 File and Directory Discovery
    (r"ffuf_dirs", r'"hits_found":\s*[1-9]', Technique("T1083", "File and Directory Discovery", "Discovery")),
    # T1190 Exploit Public-Facing Application
    (r"sqlmap_scan", r'"injectable":\s*true', Technique("T1190", "Exploit Public-Facing Application", "Initial Access")),
    # T1213 Data from Information Repositories (dump)
    (r"sqlmap_dump", r"\|", Technique("T1213", "Data from Information Repositories", "Collection")),
    # T1123/T1059-adjacent — command execution observed via injection
    (r"check\.php", r"", Technique("T1059", "Command and Scripting Interpreter", "Execution")),
]

# Weak-configuration indicators found by header audit -> mitigations, not techniques
WEAKNESS_NOTES = {
    "strict-transport-security": "No HSTS: traffic can be downgraded to plaintext HTTP.",
    "content-security-policy": "No CSP: reflected/stored XSS has no browser-level mitigation.",
    "x-frame-options": "No X-Frame-Options: pages can be framed for clickjacking.",
    "x-content-type-options": "No nosniff: MIME confusion attacks become possible.",
    "referrer-policy": "No Referrer-Policy: URLs may leak to third parties.",
    "permissions-policy": "No Permissions-Policy: browser features are unrestricted.",
}


def map_findings(findings: dict[str, list[str]], observations: list[dict]) -> dict:
    """Return {techniques: [...], weaknesses: [...], summary: {...}}."""
    seen: dict[str, Technique] = {}

    for obs in observations:
        tool = obs.get("tool", "")
        result = obs.get("result", "")
        for tool_pat, out_pat, tech in RULES:
            if re.search(tool_pat, tool) and re.search(out_pat, result, re.I):
                seen[tech.id] = tech

    # header weaknesses
    weaknesses = [
        {"header": h, "note": WEAKNESS_NOTES[h]}
        for h in findings.get("missing_headers", [])
        if h in WEAKNESS_NOTES
    ]

    by_tactic: dict[str, list[str]] = {}
    for t in seen.values():
        by_tactic.setdefault(t.tactic, []).append(f"{t.id} {t.name}")

    return {
        "techniques": [
            {"id": t.id, "name": t.name, "tactic": t.tactic}
            for t in sorted(seen.values(), key=lambda x: x.id)
        ],
        "by_tactic": by_tactic,
        "weaknesses": weaknesses,
        "summary": {
            "technique_count": len(seen),
            "tactics_covered": sorted(by_tactic.keys()),
            "has_flag": bool(findings.get("flags")),
        },
    }
