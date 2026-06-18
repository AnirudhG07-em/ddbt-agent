"""Session-scoped persistent store (doc §4 — the cross-call state).

Claude Code hooks are stateless subprocesses: each ``PreToolUse`` / ``PostToolUse``
is a fresh process, so provenance labels, the staging queue, and the audit log must
live on disk, keyed by ``session_id``. We use SQLite in WAL mode because Claude Code
runs hooks on the same event **in parallel** — WAL tolerates concurrent readers and a
serialised writer without corrupting state.

The store lives OUTSIDE the workspace (``~/.ddbt/sessions/<id>/``) so a compromised
agent working in the repo cannot tamper with its own taint records or audit trail
(same rationale as Boundary 0's out-of-band baselines, doc §2).

Invariants enforced here:
  * ``set_label`` is **monotonic-down**: it only ever lowers trust (worst-label-wins
    join against what's already stored). Trust can never silently rise.
  * ``declassify`` is the *single* path that raises trust, and it always writes an
    audit event (doc §4: every declassify is logged).
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from ddbt.core.labels import Channel, Label, Origin


def default_base_dir() -> Path:
    root = os.environ.get("DDBT_HOME") or os.path.join(os.path.expanduser("~"), ".ddbt")
    return Path(root) / "sessions"


@dataclass(slots=True)
class StagedItem:
    id: int
    ts: float
    kind: str  # "network" | "fs"
    action: dict
    status: str  # "pending" | "released" | "dropped"


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
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS labels (
                resource TEXT PRIMARY KEY,
                origin INT NOT NULL, channel INT NOT NULL, sensitive INT NOT NULL,
                reason TEXT, updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS originals (
                token TEXT PRIMARY KEY, content TEXT NOT NULL,
                label TEXT NOT NULL, held_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS staged (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, kind TEXT NOT NULL,
                action TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS confirmed (
                sig TEXT PRIMARY KEY, ts REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS counters (
                key TEXT PRIMARY KEY, val INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS member_sets (
                setname TEXT NOT NULL, member TEXT NOT NULL,
                PRIMARY KEY (setname, member)
            );
            """
        )

    # ---- trajectory counters (cumulative session state for lookahead checks) ----

    def incr(self, key: str, by: int = 1) -> int:
        self._conn.execute(
            "INSERT INTO counters(key,val) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET val = val + excluded.val",
            (key, by),
        )
        row = self._conn.execute("SELECT val FROM counters WHERE key=?", (key,)).fetchone()
        return int(row["val"])

    def get_counter(self, key: str, default: int = 0) -> int:
        row = self._conn.execute("SELECT val FROM counters WHERE key=?", (key,)).fetchone()
        return int(row["val"]) if row else default

    def add_member(self, setname: str, member: str) -> bool:
        """Add to a session set; return True if it was newly added."""
        cur = self._conn.execute(
            "INSERT INTO member_sets(setname,member) VALUES(?,?) ON CONFLICT DO NOTHING",
            (setname, member),
        )
        return cur.rowcount > 0

    def set_size(self, setname: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM member_sets WHERE setname=?", (setname,)
        ).fetchone()
        return int(row["n"])

    # ---- human-confirmed action signatures (gate approvals; doc §3.2) ----

    def add_confirmed(self, sig: str) -> None:
        self._conn.execute(
            "INSERT INTO confirmed(sig,ts) VALUES(?,?) ON CONFLICT(sig) DO NOTHING",
            (sig, time.time()),
        )

    def is_confirmed(self, sig: str) -> bool:
        return self._conn.execute("SELECT 1 FROM confirmed WHERE sig=?", (sig,)).fetchone() is not None

    # ---- meta (envelope serialisation, workspace root, etc.) ----

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ---- provenance labels ----

    def get_label(self, resource: str) -> Label | None:
        row = self._conn.execute(
            "SELECT origin,channel,sensitive FROM labels WHERE resource=?", (resource,)
        ).fetchone()
        if not row:
            return None
        return Label(Origin(row["origin"]), Channel(row["channel"]), bool(row["sensitive"]))

    def set_label(self, resource: str, label: Label, reason: str = "") -> Label:
        """Monotonic-down: store worst-label-wins join of incoming with existing.

        Returns the effective (possibly more-tainted) label now in force.
        """
        existing = self.get_label(resource)
        effective = label.join(existing) if existing else label
        self._conn.execute(
            "INSERT INTO labels(resource,origin,channel,sensitive,reason,updated_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(resource) DO UPDATE SET "
            "origin=excluded.origin, channel=excluded.channel, sensitive=excluded.sensitive, "
            "reason=excluded.reason, updated_at=excluded.updated_at",
            (
                resource,
                int(effective.origin),
                int(effective.channel),
                int(effective.sensitive),
                reason,
                time.time(),
            ),
        )
        return effective

    def declassify(self, resource: str, new_label: Label, reason: str) -> None:
        """The ONLY trust-raising path. Always audited (doc §4)."""
        self._conn.execute(
            "INSERT INTO labels(resource,origin,channel,sensitive,reason,updated_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(resource) DO UPDATE SET "
            "origin=excluded.origin, channel=excluded.channel, sensitive=excluded.sensitive, "
            "reason=excluded.reason, updated_at=excluded.updated_at",
            (
                resource,
                int(new_label.origin),
                int(new_label.channel),
                int(new_label.sensitive),
                reason,
                time.time(),
            ),
        )
        self.append_audit("declassify", {"resource": resource, "reason": reason, "to": new_label.describe()})

    # ---- diff-against-known originals (round-trip declassify, doc §4 #3) ----

    def hold_original(self, token: str, content: str, label: Label) -> None:
        self._conn.execute(
            "INSERT INTO originals(token,content,label,held_at) VALUES(?,?,?,?) "
            "ON CONFLICT(token) DO UPDATE SET content=excluded.content, label=excluded.label",
            (token, content, label.describe(), time.time()),
        )

    def get_original(self, token: str) -> str | None:
        row = self._conn.execute("SELECT content FROM originals WHERE token=?", (token,)).fetchone()
        return row["content"] if row else None

    # ---- audit log (append-only) ----

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

    # ---- staging queue (network + fs ops awaiting commit) ----

    def stage(self, kind: str, action: dict) -> int:
        cur = self._conn.execute(
            "INSERT INTO staged(ts,kind,action,status) VALUES(?,?,?,'pending')",
            (time.time(), kind, json.dumps(action, default=str)),
        )
        return int(cur.lastrowid)

    def list_staged(self, status: str = "pending") -> list[StagedItem]:
        rows = self._conn.execute(
            "SELECT id,ts,kind,action,status FROM staged WHERE status=? ORDER BY id", (status,)
        ).fetchall()
        return [
            StagedItem(r["id"], r["ts"], r["kind"], json.loads(r["action"]), r["status"]) for r in rows
        ]

    def set_staged_status(self, item_id: int, status: str) -> None:
        self._conn.execute("UPDATE staged SET status=? WHERE id=?", (status, item_id))

    def close(self) -> None:
        self._conn.close()


def _safe_id(session_id: str) -> str:
    """Sanitise a session id for use as a directory name."""
    keep = [c if (c.isalnum() or c in "-_") else "_" for c in str(session_id)]
    return "".join(keep) or "default"
