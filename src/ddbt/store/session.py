"""Session-scoped persistent store (v4).

Claude Code hooks are stateless subprocesses: each invocation is a fresh process, so the
goal, the quarantine, and the audit trail must live on disk, keyed by ``session_id``.
SQLite in WAL mode tolerates Claude Code's parallel hook execution without corruption.

The store lives OUTSIDE the workspace (``~/.ddbt/sessions/<id>/``) so a compromised agent
working in the repo cannot tamper with its own quarantine or audit trail (same rationale
as Boundary 0's out-of-band baselines).
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path


def default_base_dir() -> Path:
    root = os.environ.get("DDBT_HOME") or os.path.join(os.path.expanduser("~"), ".ddbt")
    return Path(root) / "sessions"


class SessionStore:
    """One SQLite database per agent session."""

    def __init__(self, session_id: str, base_dir: Path | None = None):
        self.session_id = session_id
        base = Path(base_dir) if base_dir else default_base_dir()
        self.dir = base / _safe_id(session_id)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "store.db"
        self._conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, tool TEXT, content TEXT NOT NULL
            );
            """
        )

    # ---- meta (the standing goal, workspace root, etc.) ----

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ---- audit (append-only, lawful per-step trail) ----

    def append_audit(self, kind: str, payload: dict) -> int:
        cur = self._conn.execute(
            "INSERT INTO audit(ts,kind,payload) VALUES(?,?,?)",
            (time.time(), kind, json.dumps(payload, default=str)),
        )
        return int(cur.lastrowid)

    def read_audit(self) -> list[dict]:
        rows = self._conn.execute("SELECT id,ts,kind,payload FROM audit ORDER BY id").fetchall()
        out = []
        for r in rows:
            entry = {"id": r["id"], "ts": r["ts"], "kind": r["kind"]}
            entry.update(json.loads(r["payload"]))
            out.append(entry)
        return out

    # ---- quarantine: tool outputs held in isolation for the judge to inspect ----

    def add_quarantine(self, tool: str, content: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO quarantine(ts,tool,content) VALUES(?,?,?)", (time.time(), tool, content)
        )
        return int(cur.lastrowid)

    def recent_quarantine(self, n: int = 3) -> list[str]:
        rows = self._conn.execute(
            "SELECT tool, content FROM quarantine ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()
        return [f"[{r['tool']}] {r['content']}" for r in rows]

    def quarantine_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) AS n FROM quarantine").fetchone()["n"])

    def close(self) -> None:
        self._conn.close()


def _safe_id(session_id: str) -> str:
    keep = [c if (c.isalnum() or c in "-_") else "_" for c in str(session_id)]
    return "".join(keep) or "default"
