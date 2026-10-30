# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.2] - 2026-10-30

### Security

- **Argument injection in `nmap_scan` and `nmap_vuln_scan`.** The `target`
  argument was appended to argv without a shape check. Arguments never go
  through a shell, so shell metacharacters were not the risk — a leading `-`
  was: a model-supplied target of `-iL /etc/passwd` made nmap read an arbitrary
  file, and `-oN /tmp/out` made it write one. Targets are now validated against
  a conservative character set, must not start with `-`, must not contain `..`,
  and are capped at 255 characters (`mcp_servers/mcp_guard.py`).
- The `ports` argument gets the same treatment: it must match `[0-9,-]`.

### Added

- `mcp_servers/mcp_guard.py` — shared argv shape checks, pure standard library.
- `tests/test_mcp_guard.py` — 34 cases covering option-like targets, shell
  metacharacters, path traversal and malformed port specs.

## [0.3.1] - 2026-10-29

### Security

- **Scope allowlist bypass.** `--scope` used `re.search` against the full target
  string, so `--scope 'example\.com'` also authorised `example.com.attacker.net`,
  `evilexample.com` and `example.com@attacker.net`. The check now extracts the
  hostname with `urlsplit` and requires a full match. Subdomains must be
  requested explicitly with `--scope '.*\.example\.com'`.
- `--deny-private` matched private-network prefixes anywhere in the string, so
  `10.example.com` and `notlocalhost.com` were misclassified as private
  addresses. It now range-checks IP literals via `ipaddress`.

### Added

- `Dockerfile` — runtime image with nmap and sqlmap preinstalled and ffuf
  fetched from its release tarball, running as a non-root user.
- `tests/test_policy_scope.py` — 28 cases for lookalike hosts and private-address
  detection.
- Authorization warning at the top of the README, plus a `Disclaimer` section.

### Changed

- Documented five known limitations instead of implying completeness.
- Replaced the hand-written test badge with the live Actions badge.
- The demo command now spells out `--policy allow` and explains why.

### Fixed

- Clone URL still contained the `<your-username>` placeholder.
- Truncated project tree in the README.

## [0.3.0] - 2026-09-17

### Added

- Engagement policy gate: passive / ask / allow modes, per-tool denial, target
  scope and private-network controls, fail-closed approval.
- SQLite engagement history with per-target diffs.
- GitHub Actions: pytest on Python 3.11/3.12/3.13, ruff, byte-compile.

### Fixed

- Dependency ranges were lower-bound only, which let `mcp` 1.9.4 resolve against
  a pydantic that no longer exports `eval_type_backport`, breaking every test at
  import time. `pydantic` is now pinned below 2.12, and `openai`, `httpx`, `rich`
  and the test tooling carry upper bounds.

## [0.2.0] - 2026-09-17

### Added

- Initial release: MCP-based autonomous security assessment agent with a
  plan-and-execute planner, parallel tool calls, tiered memory, MITRE ATT&CK
  mapping and Markdown reports.
- Four MCP servers: nmap (2 tools), httpx (3), sqlmap (3), ffuf (1).

[Unreleased]: https://github.com/RicardoMLu777/secagent/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/RicardoMLu777/secagent/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/RicardoMLu777/secagent/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/RicardoMLu777/secagent/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/RicardoMLu777/secagent/releases/tag/v0.2.0
