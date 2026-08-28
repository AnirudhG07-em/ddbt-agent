"""Workspace behaviors from ddbt.json → prototype texts for sift, with NO retraining.

The user declares, per workspace, what's bad (and optionally what's explicitly fine) in
``ddbt.json``::

    "behaviors": {
      "deny": [
        "push to git or open a PR without me explicitly asking",          # natural language
        {"domain": "database", "category": "exfiltration",                # or taxonomy form
         "text": "export table rows to any destination outside the workspace"}
      ],
      "allow": ["run the test suite and report results"]
    }

Each item — a plain string or a {domain, category, text} dict — is rendered to the same shape sift
embeds for actions/prototypes, so a declared rule is just another prototype: `deny` items become
extra BAD centroids (raise risk on matching actions), `allow` items become GOOD centroids (lower it).
Because it's pure embedding similarity, adding or editing a rule takes effect immediately — no
retrain. This is the "workspace-based" half; the deterministic allow/deny floor is the `policy` block.
"""

from __future__ import annotations

import json
from pathlib import Path

FILENAME = "ddbt.json"


def render_item(item) -> str | None:
    """Render one behavior entry to an embed-ready string, matching the action/prototype template."""
    if isinstance(item, str):
        text = item.strip()
        return f"ARGS: {text}" if text else None
    if isinstance(item, dict):
        text = str(item.get("text", "")).strip()
        if not text:
            return None
        dom = item.get("domain", "")
        cat = item.get("category", "")
        tag = " ".join(p for p in (f"DOMAIN={dom}" if dom else "", f"CATEGORY={cat}" if cat else "") if p)
        return f"{tag} ARGS: {text}".strip()
    return None


def parse(behaviors: dict) -> tuple[list[str], list[str]]:
    """(deny_texts, allow_texts) from a behaviors dict. Robust to missing keys / bad items."""
    if not isinstance(behaviors, dict):
        return [], []
    deny = [t for t in (render_item(i) for i in behaviors.get("deny", []) or []) if t]
    allow = [t for t in (render_item(i) for i in behaviors.get("allow", []) or []) if t]
    return deny, allow


def _find_ddbt_json(cwd: str | Path | None) -> Path | None:
    """ddbt.json in cwd or any parent, then ~/.ddbt/ddbt.json (mirrors ddbt.core.config)."""
    start = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    for d in (start, *start.parents):
        f = d / FILENAME
        if f.is_file():
            return f
    glob = Path.home() / ".ddbt" / FILENAME
    return glob if glob.is_file() else None


def load(cwd: str | Path | None = None) -> tuple[list[str], list[str]]:
    """Read the workspace ddbt.json and return (deny_texts, allow_texts). ([],[]) if none/invalid."""
    f = _find_ddbt_json(cwd)
    if not f:
        return [], []
    try:
        data = json.loads(f.read_text())
    except (OSError, json.JSONDecodeError):
        return [], []
    return parse(data.get("behaviors", {}) if isinstance(data, dict) else {})
