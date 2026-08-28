"""Reusable rule-packs — author once, reference from any project.

A rule-pack teaches ddbt what "good" and "bad" mean for a particular tool or workflow (a notion-cli,
an internal deploy script, an MCP server). It is NOT a trained model — it is a set of natural-language
deny/allow behaviors that sift embeds and compares LIVE (no gradient step, additive, instant). Packs
live in a SHARED place so they are reusable across projects:

    ~/.ddbt/rules/<name>/rules.json     # {name, description, behaviors:{deny,allow}, exemplars?}

A project opts in by referencing the pack by name in its ddbt.json:  "rulesets": ["notion-cli"].
config._fold_rulesets then folds the pack's behaviors into that project's effective policy. Write a
pack by hand, or generate one with `ddbt create-rules "<name>"` (offline, LLM-assisted).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ddbt.core.config import _home


def rules_dir() -> Path:
    return _home() / "rules"


def _safe(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", str(name).strip().lower()).strip("-") or "pack"


def pack_path(name: str) -> Path:
    return rules_dir() / _safe(name) / "rules.json"


def load_pack(name: str) -> dict | None:
    """Read a rule-pack by name, or None if it doesn't exist / is malformed."""
    try:
        data = json.loads(pack_path(name).read_text())
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def save_pack(name: str, pack: dict) -> Path:
    """Write a rule-pack (create/overwrite). Returns the path."""
    path = pack_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {"name": _safe(name), **{k: v for k, v in pack.items() if k != "name"}}
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n")
    return path


def list_packs() -> list[str]:
    """Names of all rule-packs available on this machine (shared across projects), sorted."""
    d = rules_dir()
    if not d.is_dir():
        return []
    return sorted(p.name for p in d.iterdir() if (p / "rules.json").is_file())


def counts(name: str) -> tuple[int, int]:
    """(deny, allow) behavior counts for a pack — for CLI summaries. (0,0) if absent."""
    pack = load_pack(name) or {}
    beh = pack.get("behaviors", {}) if isinstance(pack.get("behaviors"), dict) else {}
    return len(beh.get("deny") or []), len(beh.get("allow") or [])


# ---- authoring: draft a pack with an LLM (offline, one-time), or a hand-editable starter ----

_PROMPT = """You are configuring a deterministic security guard for an AI coding agent that can use the \
tool "{name}". {desc}

Enumerate concrete BAD actions on this tool that the guard should BLOCK or ASK a human to confirm, and \
concrete GOOD actions that are clearly fine. Write each as a short natural-language rule describing the \
ACTION and its intent — NOT code, no tool syntax. For the bad list, cover destructive/irreversible \
operations, data exfiltration or privacy leaks, privilege or sharing changes, and bulk operations.

Return ONLY minified JSON, no prose, exactly: {{"deny": ["...", "..."], "allow": ["...", "..."]}}
Give 12-20 deny rules and 8-15 allow rules, each specific to "{name}"."""


def _parse(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    data = json.loads(m.group(0)) if m else {}
    clean = lambda xs: [s.strip() for s in xs if isinstance(s, str) and s.strip()][:40]  # noqa: E731
    return {"deny": clean(data.get("deny") or []), "allow": clean(data.get("allow") or [])}


def draft(name: str, description: str = "", provider: str | None = None, model: str | None = None,
          rounds: int = 1) -> dict:
    """LLM-draft a rule-pack for a tool (offline authoring). `rounds` = how many generation requests to
    make (results de-duplicated and merged → broader coverage). Raises if the LLM call fails."""
    from ddbt.core import generate
    desc = description or f"It is a tool/CLI named {name}."
    deny: list[str] = []
    allow: list[str] = []
    for _ in range(max(1, rounds)):
        p = _parse(generate.generate(_PROMPT.format(name=name, desc=desc), provider=provider, model=model))
        deny += [x for x in p["deny"] if x not in deny]
        allow += [x for x in p["allow"] if x not in allow]
    return {"description": description or name, "behaviors": {"deny": deny, "allow": allow}}


def starter(name: str, description: str = "") -> dict:
    """A hand-editable starter pack for when no LLM key is available — the user fills it in."""
    return {"description": description or name, "behaviors": {
        "deny": [f"perform a destructive or irreversible {name} action I did not explicitly ask for",
                 f"use {name} to send, share, or expose private data outside the workspace",
                 f"change permissions or sharing on {name} resources without my approval"],
        "allow": [f"use {name} to read, list, or search information",
                  f"run a safe read-only {name} operation I asked for"]}}
