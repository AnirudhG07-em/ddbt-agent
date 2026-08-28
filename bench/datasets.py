"""Benchmark registry — one place that knows every dataset, how to load it, and how it's scored.

Two evaluation modes:
  * "replay"   — a dataset of tool-call sequences with attack/benign labels. We run each through the
                 full ddbt stack (grant + plugins + sift judge) and measure whether attacks are
                 stopped and benign flows pass. This is where the PLUGINS matter.
  * "classify" — a dataset of labelled items (trajectory / description). Scored by the sift judge as
                 a binary classifier (handled by sift's own harness; referenced here for the table).

agentdojo/agentdyn are deliberately absent — handled separately.

Each replay loader returns a list of `static_replay.Case`. Loaders are best-effort: if the data or a
usable adapter isn't present, they return [] and the runner skips with a note.
"""

from __future__ import annotations

import json
from pathlib import Path

import static_replay  # Case, load_injecagent

DATA = Path(__file__).resolve().parent / "data"
Case = static_replay.Case


# ---- replay loaders (→ list[Case]) ----

def load_injecagent() -> list:
    cases = []
    for kind in ("ds", "dh"):
        p = DATA / "injecagent" / f"{kind}_base.json"
        if p.is_file():
            cases += static_replay.load_injecagent(str(p))
    return cases


def load_agenttrust() -> list:
    """AgentTrust scenarios: expect a JSON list of {command|action, label|verdict, goal?}.
    label/verdict 'block'/'deny'/'unsafe'/1 → attack; 'allow'/'safe'/0 → benign."""
    p = _first_json(DATA / "agenttrust")
    if not p:
        return []
    rows = _load_list(p)
    cases = []
    for i, r in enumerate(rows):
        cmd = r.get("command") or r.get("action") or r.get("input") or ""
        if not cmd:
            continue
        v = str(r.get("label", r.get("verdict", ""))).lower()
        label = "attack" if v in ("block", "deny", "unsafe", "1", "true", "review", "warn") else "benign"
        cases.append(Case(id=f"at/{i}", goal=r.get("goal", "complete the task"),
                          calls=[("Bash", {"command": cmd})], label=label))
    return cases


def load_toolemu() -> list:
    """ToolEmu cases (assets/all_cases.json). Scenario-based; we extract the ground-truth risky
    tool call when present, else skip the case. Best-effort adapter."""
    p = DATA / "toolemu" / "all_cases.json"
    if not p.is_file():
        return []
    rows = _load_list(p)
    cases = []
    for i, r in enumerate(rows):
        goal = r.get("User Instruction") or r.get("input") or "complete the task"
        # ToolEmu marks risky outcomes but not always a single replayable call; take the first
        # expected risky action if the schema exposes one.
        risky = r.get("risky_actions") or r.get("expected_risky_tool_calls")
        if not risky:
            continue
        call = risky[0]
        tool = call.get("tool") or call.get("name") or "Bash"
        args = call.get("arguments") or call.get("args") or {}
        cases.append(Case(id=f"te/{i}", goal=goal, calls=[(tool, args)], label="attack", tainted=True,
                          taint_text=json.dumps(call)[:400]))
    return cases


def load_agentsafetybench() -> list:
    """Agent-SafetyBench scenarios. Best-effort: replay a ground-truth unsafe tool call if present."""
    p = _first_json(DATA / "agentsafetybench")
    if not p:
        return []
    rows = _load_list(p)
    cases = []
    for i, r in enumerate(rows):
        calls = r.get("unsafe_tool_calls") or r.get("risky_actions")
        if not calls:
            continue
        c = calls[0]
        cases.append(Case(id=f"asb/{i}", goal=r.get("instruction", "complete the task"),
                          calls=[(c.get("tool", "Bash"), c.get("args", {}))], label="attack"))
    return cases


# name -> (mode, loader, needs_fetch)
REGISTRY = {
    "injecagent": ("replay", load_injecagent, False),
    "agenttrust": ("replay", load_agenttrust, True),
    "toolemu": ("replay", load_toolemu, True),
    "agentsafetybench": ("replay", load_agentsafetybench, True),
    # rjudge / mcptox are classification of the judge — evaluated by sift/bench_bakeoff.py.
}


# ---- helpers ----

def _first_json(d: Path):
    if not d.is_dir():
        return None
    js = sorted(d.glob("*.json"))
    return js[0] if js else None


def _load_list(p: Path) -> list:
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):  # some sets wrap in {"data": [...]} or {"cases": [...]}
        for k in ("data", "cases", "test", "scenarios"):
            if isinstance(data.get(k), list):
                return data[k]
        return []
    return data if isinstance(data, list) else []
