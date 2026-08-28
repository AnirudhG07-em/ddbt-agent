"""Domain training packs — drop a JSONL of labelled action cases into sift/data/domains/ and it's
folded into training on the next `ddbt prepare`. This is how you teach the model a new work-system
(database, git, jira, cloud, …) so its SEMANTIC judgment generalises beyond keyword rules.

Each line is one action case:
    {"tool": "db_exec", "args": {"sql": "DROP TABLE x"}, "goal": "clean up",
     "label": 1, "domain": "database", "category": "destructive"}
label: 1 = bad, 0 = good. `category` is free-form (for the human-readable reason only).

Cases can be hand-written, exported from real logs, or generated once by an LLM offline
(sift/gen_cases.py) — the DEPLOYED system never calls an LLM; this is just data prep.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _bucket(rec: dict) -> int:
    """Deterministic 0-99 bucket for a case, from its content — so train/test are stable across runs
    and a case never leaks between them regardless of file order."""
    key = json.dumps({k: rec.get(k) for k in ("tool", "args", "goal", "label")}, sort_keys=True, default=str)
    return int(hashlib.blake2b(key.encode(), digest_size=4).hexdigest(), 16) % 100


def _dir() -> Path:
    # sift/data/domains/ — this file is sift/sift/data/domains.py
    here = Path(__file__).resolve()
    for up in here.parents:
        cand = up / "data" / "domains"
        if cand.is_dir():
            return cand
    return here.parent.parent.parent / "data" / "domains"


def load(only: list[str] | None = None, split: str = "all", test_ratio: float = 0.2) -> list[dict]:
    """Domain cases as sift records, with a deterministic per-case train/test split.

    split: "all" | "train" | "test". A case with content-bucket < test_ratio*100 is test, else train —
    stable across runs, no leakage. `only` restricts to named domains (file stems)."""
    d = _dir()
    if not d.is_dir():
        return []
    cut = int(test_ratio * 100)
    records: list[dict] = []
    for f in sorted(d.glob("*.jsonl")):
        if only and f.stem not in only:
            continue
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "tool" not in r or "label" not in r:
                continue
            r.setdefault("domain", f.stem)
            r.setdefault("goal", "")
            is_test = _bucket(r) < cut
            if split == "train" and is_test:
                continue
            if split == "test" and not is_test:
                continue
            records.append(r)
    return records


def domains() -> list[str]:
    d = _dir()
    return sorted(f.stem for f in d.glob("*.jsonl")) if d.is_dir() else []
