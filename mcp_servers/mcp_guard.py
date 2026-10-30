"""Input validation shared by the MCP tool servers.

The servers spawn real security tools as subprocesses. Arguments are always
passed as a list and never through a shell, which removes *shell* injection.
That does not remove *argument* injection: a value beginning with "-" is parsed
by the underlying tool as an option, so a target of ``-iL /etc/passwd`` makes
nmap read a file, and ``-oN /tmp/out`` makes it write one.

Every value that reaches argv therefore has to be shape-checked first. These
helpers are deliberately conservative: hosts, IPs, CIDR ranges and bracketed
IPv6 literals pass, everything else is rejected with a message the model can
act on.
"""

from __future__ import annotations

import re

# Hostnames, IPv4, IPv6, CIDR and bracketed IPv6 literals.
_TARGET_RE = re.compile(r"[A-Za-z0-9_.:/\-\[\]]{1,255}")

# nmap port specs: "80", "80,443", "1-1000", "22,80,8000-8100".
_PORTS_RE = re.compile(r"[0-9,\-]{1,512}")

# Defence in depth: characters that have no business in a host or a port spec.
_FORBIDDEN_RE = re.compile(r"[\s;&|`$><\\'\"(){}*?!~^]")


def validate_target(target: str) -> str | None:
    """Return an error message, or None when the target is safe for argv."""
    if not target:
        return "target is required"
    if target.startswith("-"):
        return "target must not start with '-' (would be parsed as an option)"
    if _FORBIDDEN_RE.search(target):
        return "target contains forbidden characters"
    if not _TARGET_RE.fullmatch(target):
        return "target may only contain letters, digits and . : / - [ ]"
    if ".." in target:
        return "target must not contain '..'"
    return None


def validate_ports(ports: str) -> str | None:
    """Return an error message, or None when the port spec is acceptable."""
    if not ports:
        return None
    if not _PORTS_RE.fullmatch(ports):
        return "ports must look like '80,443' or '1-1000'"
    return None
