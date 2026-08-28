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
        # busy_timeout FIRST: the WAL-mode switch needs a brief exclusive lock, so under concurrent
        # opens (parallel hooks) it must WAIT, not error with "database is locked".
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("PRAGMA journal_mode=WAL")
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
            -- Every identifier seen in a tool result and WHERE IT SAT (see core/provenance.py):
            -- origin='field' → the producing system chose it; origin='content' → free text, its
            -- author chose it. A lookup, so it doesn't degrade over a long session.
            CREATE TABLE IF NOT EXISTS provenance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, value TEXT NOT NULL, kind TEXT NOT NULL,
                tool TEXT NOT NULL, path TEXT NOT NULL, origin TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_prov_value ON provenance(value);
            -- The TRAJECTORY LEDGER: one confirmed-executed step per row, the cheap tabular form of
            -- the "session action graph" the provenance-IDS / DLP literature scores over (Holmes,
            -- UNICORN, fraud-detection trajectory features). Every trajectory detector is a VIEW over
            -- this table; recorded by the engine on record_result so it reflects steps that ran.
            --   direction: 'egress' (data leaves) | 'read' (data enters) | 'other'
            --   destination: host / email domain / db endpoint the step reaches ('' if none)
            --   n_bytes/entropy: over the OUTBOUND payload for egress, the INBOUND content for reads
            --   extra: JSON — taint labels, secret markers, mitre hits, db row-ids (detector-specific)
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, step INTEGER NOT NULL, tool TEXT NOT NULL,
                direction TEXT NOT NULL, destination TEXT NOT NULL DEFAULT '',
                n_bytes INTEGER NOT NULL DEFAULT 0, entropy REAL NOT NULL DEFAULT 0.0,
                extra TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_ledger_dest ON ledger(destination);
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

    # ---- atomic counters ----
    #
    # Hooks run as parallel subprocesses, so a Python read-modify-write would lose increments
    # (both read 4, both write 5). These do the arithmetic inside one SQL statement (atomic), so
    # concurrent hooks can only over-count — never under-count, which is the unsafe direction.

    def increment_meta(self, key: str, delta: int) -> int:
        """Atomically add `delta` to an integer-valued meta key. Returns the new value."""
        row = self._conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(meta.value AS INTEGER)+? AS TEXT) "
            "RETURNING value",
            (key, str(int(delta)), int(delta)),
        ).fetchone()
        return int(row["value"])

    def raise_meta_floor(self, key: str, value: int) -> int:
        """Atomically raise an integer meta key to at least `value`, never lowering it — the
        ratchet in SQL, so a concurrent hook can't read a stale floor and undo a tightening."""
        row = self._conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=CAST(MAX(CAST(meta.value AS INTEGER),?) AS TEXT) "
            "RETURNING value",
            (key, str(int(value)), int(value)),
        ).fetchone()
        return int(row["value"])

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

    # ---- provenance: which values came from where ----

    def add_provenance(self, tool: str, rows: list[dict]) -> None:
        if not rows:
            return
        now = time.time()
        self._conn.executemany(
            "INSERT INTO provenance(ts,value,kind,tool,path,origin) VALUES(?,?,?,?,?,?)",
            [(now, r["value"].lower(), r["kind"], tool, r["path"], r["origin"]) for r in rows],
        )

    def lookup_provenance(self, value: str) -> list[dict]:
        """Every recorded sighting of `value`, newest first. Exact (lowercased) match."""
        rows = self._conn.execute(
            "SELECT value,kind,tool,path,origin FROM provenance WHERE value=? ORDER BY id DESC",
            (value.strip().lower(),),
        ).fetchall()
        return [dict(r) for r in rows]

    def quarantine_matching(self, values: list[str], limit: int = 3) -> list[str]:
        """Quarantined outputs that actually MENTION one of `values`, newest first — retrieval by
        relevance, not recency, so an injection ingested steps ago can't fall out of the window."""
        if not values:
            return []
        clauses = " OR ".join(["content LIKE ?"] * len(values))
        params = [f"%{v}%" for v in values] + [limit]
        rows = self._conn.execute(
            f"SELECT tool, content FROM quarantine WHERE {clauses} ORDER BY id DESC LIMIT ?",
            params,
        ).fetchall()
        return [f"[{r['tool']}] {r['content']}" for r in rows]

    def recent_quarantine(self, n: int = 3) -> list[str]:
        rows = self._conn.execute(
            "SELECT tool, content FROM quarantine ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()
        return [f"[{r['tool']}] {r['content']}" for r in rows]

    def quarantine_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) AS n FROM quarantine").fetchone()["n"])

    # ---- trajectory ledger: one confirmed-executed step per row ----

    def append_ledger(self, row: dict) -> int:
        """Append a confirmed step. `row` keys: step, tool, direction, destination, n_bytes,
        entropy, extra(dict). Missing keys default. `extra` is JSON-serialized."""
        cur = self._conn.execute(
            "INSERT INTO ledger(ts,step,tool,direction,destination,n_bytes,entropy,extra) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (time.time(), int(row.get("step", 0)), str(row.get("tool", "")),
             str(row.get("direction", "other")), str(row.get("destination", "")),
             int(row.get("n_bytes", 0)), float(row.get("entropy", 0.0)),
             json.dumps(row.get("extra", {}), default=str)),
        )
        return int(cur.lastrowid)

    def read_ledger(self) -> list[dict]:
        """Every ledger row, oldest first, with `extra` merged back into the dict."""
        rows = self._conn.execute(
            "SELECT ts,step,tool,direction,destination,n_bytes,entropy,extra FROM ledger ORDER BY id"
        ).fetchall()
        out = []
        for r in rows:
            d = {"ts": r["ts"], "step": r["step"], "tool": r["tool"], "direction": r["direction"],
                 "destination": r["destination"], "n_bytes": r["n_bytes"], "entropy": r["entropy"]}
            try:
                extra = json.loads(r["extra"]) if r["extra"] else {}
            except (ValueError, TypeError):
                extra = {}
            d["extra"] = extra if isinstance(extra, dict) else {}
            out.append(d)
        return out

    def close(self) -> None:
        self._conn.close()


def _safe_id(session_id: str) -> str:
    keep = [c if (c.isalnum() or c in "-_") else "_" for c in str(session_id)]
    return "".join(keep) or "default"
