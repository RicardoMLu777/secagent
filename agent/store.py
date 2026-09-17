"""SQLite persistence — stores engagements so results can be compared over time."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT NOT NULL,
    objective       TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    steps           INTEGER DEFAULT 0,
    observations    INTEGER DEFAULT 0,
    report          TEXT,
    findings_json   TEXT,
    attack_json     TEXT,
    plan_json       TEXT,
    policy_json     TEXT
);

CREATE INDEX IF NOT EXISTS idx_engagements_target ON engagements(target);
CREATE INDEX IF NOT EXISTS idx_engagements_started ON engagements(started_at DESC);

CREATE TABLE IF NOT EXISTS tool_calls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    step          INTEGER NOT NULL,
    tool          TEXT NOT NULL,
    arguments     TEXT,
    result        TEXT,
    blocked       INTEGER DEFAULT 0,
    created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_engagement ON tool_calls(engagement_id);
"""

DEFAULT_DB = Path.home() / ".secagent" / "engagements.db"


class Store:
    """Thin SQLite wrapper for engagement history."""

    def __init__(self, path: str | Path = DEFAULT_DB) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(SCHEMA)

    # ---- writes ----

    def start_engagement(
        self, target: str, objective: str, policy: dict[str, Any] | None = None
    ) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO engagements (target, objective, started_at, policy_json) "
                "VALUES (?, ?, ?, ?)",
                (
                    target,
                    objective,
                    datetime.now().isoformat(timespec="seconds"),
                    json.dumps(policy or {}, ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid or 0)

    def record_tool_call(
        self,
        engagement_id: int,
        step: int,
        tool: str,
        arguments: dict[str, Any],
        result: str,
        blocked: bool = False,
    ) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO tool_calls "
                "(engagement_id, step, tool, arguments, result, blocked, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    engagement_id,
                    step,
                    tool,
                    json.dumps(arguments, ensure_ascii=False),
                    result[:20000],
                    int(blocked),
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )

    def finish_engagement(self, engagement_id: int, result: dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE engagements SET finished_at=?, steps=?, observations=?, "
                "report=?, findings_json=?, attack_json=?, plan_json=? WHERE id=?",
                (
                    datetime.now().isoformat(timespec="seconds"),
                    result.get("steps", 0),
                    result.get("observations", 0),
                    result.get("report", ""),
                    json.dumps(result.get("findings", {}), ensure_ascii=False),
                    json.dumps(result.get("attack_mapping", {}), ensure_ascii=False),
                    json.dumps(result.get("plan", []), ensure_ascii=False),
                    engagement_id,
                ),
            )

    # ---- reads ----

    def history(self, target: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        q = (
            "SELECT id, target, objective, started_at, finished_at, steps, "
            "observations, findings_json FROM engagements "
        )
        params: tuple[Any, ...] = ()
        if target:
            q += "WHERE target = ? "
            params = (target,)
        q += "ORDER BY started_at DESC LIMIT ?"
        params = params + (limit,)

        with self._conn() as c:
            rows = c.execute(q, params).fetchall()

        out = []
        for r in rows:
            d = dict(r)
            findings = json.loads(d.pop("findings_json") or "{}")
            d["flags"] = findings.get("flags", [])
            d["open_ports"] = findings.get("open_ports", [])
            out.append(d)
        return out

    def get(self, engagement_id: int) -> dict[str, Any] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
            ).fetchone()
            if row is None:
                return None
            eng = dict(row)
            calls = c.execute(
                "SELECT step, tool, arguments, result, blocked, created_at "
                "FROM tool_calls WHERE engagement_id = ? ORDER BY id",
                (engagement_id,),
            ).fetchall()
        eng["tool_calls"] = [dict(x) for x in calls]
        for key in ("findings_json", "attack_json", "plan_json", "policy_json"):
            if key in eng:
                eng[key.replace("_json", "")] = json.loads(eng.pop(key) or "null")
        return eng

    def diff(self, id_a: int, id_b: int) -> dict[str, Any]:
        """Compare two engagements against the same target."""
        a, b = self.get(id_a), self.get(id_b)
        if not a or not b:
            return {"error": "engagement not found"}

        def flat(e: dict[str, Any]) -> dict[str, set[str]]:
            f = e.get("findings") or {}
            return {
                "ports": set(map(str, f.get("open_ports", []))),
                "services": set(map(str, f.get("services", []))),
                "headers": set(map(str, f.get("missing_headers", []))),
                "paths": set(map(str, f.get("interesting_paths", []))),
                "flags": set(map(str, f.get("flags", []))),
            }

        fa, fb = flat(a), flat(b)
        changes = {}
        for key in fa:
            changes[key] = {
                "added": sorted(fb[key] - fa[key]),
                "removed": sorted(fa[key] - fb[key]),
                "unchanged": len(fa[key] & fb[key]),
            }

        return {
            "a": {"id": id_a, "started_at": a["started_at"], "target": a["target"]},
            "b": {"id": id_b, "started_at": b["started_at"], "target": b["target"]},
            "changes": changes,
        }

    def targets(self) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT target, COUNT(*) as runs, MAX(started_at) as last_run "
                "FROM engagements GROUP BY target ORDER BY last_run DESC"
            ).fetchall()
        return [dict(r) for r in rows]
