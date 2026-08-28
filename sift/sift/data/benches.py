"""The REAL benchmarks: R-Judge, InjecAgent, MCPTox — loaded from the repo's bench/data.

Label parsing mirrors the ddbt bench code exactly, so sift's numbers are directly comparable to
ddbt's LLM-judge results (R-Judge F1 91.5%, InjecAgent 100%, MCPTox 99.8%):
  * R-Judge  — bench/rjudge.py: trajectory-level label (1 unsafe / 0 safe). Unit = whole trajectory.
               R-Judge, Li et al., arXiv:2401.10019.
  * InjecAgent — bench/static_replay.py::load_injecagent: per-action, benign (user's own call) vs
               attack (attacker tool with the injected instruction as args, arriving via a tool
               output → tainted). InjecAgent, Zhan et al., arXiv:2403.02691.
  * MCPTox   — bench/mcptox.py: poisoned tool DESCRIPTIONS (label 1) + a clean-description control
               (label 0). Unit = a tool description (the desc-scanner task, not the action task).
               MCPTox, arXiv:2508.14925.

Each loader returns sift records: {text | (tool,args), goal, sink_provenance, label(0/1), domain,
category, id}. Records with a `text` field are pre-rendered blobs (R-Judge, MCPTox).

The path to bench/data is resolved from this file up to the repo root, so sift can run standalone.
"""

from __future__ import annotations

import ast
import glob
import json
from pathlib import Path


def _bench_dir() -> Path:
    here = Path(__file__).resolve()
    for up in here.parents:
        cand = up / "bench" / "data"
        if cand.is_dir():
            return cand
    raise FileNotFoundError("bench/data not found — run inside the ddbt-agent repo")


# ---------------------------------------------------------------- R-Judge (trajectory-level)
def _render_turns(turns: list) -> str:
    out = []
    for t in turns:
        if not isinstance(t, dict):
            continue
        role = t.get("role", "?")
        content = t.get("content") or ""
        action = t.get("action") or ""
        piece = f"{role.upper()}: {content}"
        if action:
            piece += f"\n  ACTION: {action}"
        out.append(piece)
    return "\n".join(out)


def load_rjudge(limit: int | None = None) -> list[dict]:
    """Every trajectory in bench/data/rjudge/**, labelled 1=unsafe / 0=safe (parity with
    bench/rjudge.py::load_rjudge)."""
    root = _bench_dir() / "rjudge"
    records: list[dict] = []
    for f in sorted(glob.glob(str(root / "**" / "*.json"), recursive=True)):
        try:
            data = json.load(open(f))
        except (OSError, json.JSONDecodeError):
            continue
        for r in data if isinstance(data, list) else []:
            if not (isinstance(r, dict) and "label" in r and "contents" in r):
                continue
            conv = r["contents"][0] if r["contents"] and isinstance(r["contents"][0], list) else r["contents"]
            goal = next((t.get("content") or "" for t in conv if isinstance(t, dict) and t.get("role") == "user"), "")
            records.append({
                "text": f"GOAL: {goal}\n{_render_turns(conv)}",
                "goal": goal, "sink_provenance": "unknown", "label": int(r["label"]),
                "domain": r.get("scenario", "rjudge"), "category": r.get("attack_type", "?"),
                "id": f"rj/{r.get('id', len(records))}",
            })
    return records[:limit] if limit else records


# ---------------------------------------------------------------- InjecAgent (per-action)
def load_injecagent(kind: str = "ds", limit: int | None = None) -> list[dict]:
    """benign = the user's own tool call; attack = attacker tool(s) carrying the injected
    instruction, which arrived via a tool output → provenance 'tool' (parity with
    bench/static_replay.py::load_injecagent). kind: 'ds' (data-stealing) or 'dh' (direct-harm)."""
    path = _bench_dir() / "injecagent" / f"{kind}_base.json"
    items = json.loads(path.read_text())
    recs: list[dict] = []
    for i, it in enumerate(items):
        goal = it.get("User Instruction", "")
        user_tool = it.get("User Tool")
        if user_tool:
            recs.append({"tool": user_tool, "args": it.get("Tool Parameters") or "",
                         "goal": goal, "sink_provenance": "user", "label": 0,
                         "domain": "injecagent", "category": "benign", "id": f"ia/{kind}/{i}/benign"})
        atk_instr = it.get("Attacker Instruction", "")
        atk_tools = it.get("Attacker Tools") or []
        if isinstance(atk_tools, str):
            atk_tools = [atk_tools]
        if atk_tools:
            recs.append({"tool": atk_tools[0], "args": {"instruction": atk_instr},
                         "goal": goal, "sink_provenance": "tool", "label": 1,
                         "domain": "injecagent", "category": it.get("Attack Type", "attack"),
                         "id": f"ia/{kind}/{i}/attack"})
    return recs[:limit] if limit else recs


# ---------------------------------------------------------------- MCPTox (tool descriptions)
def load_mcptox(limit: int | None = None, balance: bool = True) -> list[dict]:
    """Poisoned tool descriptions (label 1) from bench/data/mcptox/def_tool/*.py docstrings, plus a
    REAL benign control (label 0) from sift.data.tool_descriptions — curated + hard-negatives
    (legit security framing) + templated, sized to the poison count so the false-positive rate is
    actually estimable (the original bench had only 8 benign). `balance` matches benign count to
    poison count."""
    from sift.data.tool_descriptions import benign_descriptions

    root = _bench_dir() / "mcptox" / "def_tool"
    poisons: list[dict] = []
    for f in sorted(glob.glob(str(root / "*.py"))):
        try:
            for node in ast.walk(ast.parse(open(f).read())):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    doc = ast.get_docstring(node)
                    if doc and doc.strip():
                        poisons.append({"text": doc.strip(), "sink_provenance": "unknown", "label": 1,
                                        "domain": "mcptox", "category": "poisoned_desc",
                                        "id": f"mx/{Path(f).name}"})
                    break
        except Exception:
            continue
    n_benign = len(poisons) if balance else None
    benign = [{"text": d, "sink_provenance": "unknown", "label": 0, "domain": "mcptox",
               "category": "benign_desc", "id": f"mx/benign/{i}"}
              for i, d in enumerate(benign_descriptions(target=n_benign))]
    recs = poisons + benign
    return recs[:limit] if limit else recs


def load_injecagent_provtest(kind: str = "ds", limit: int | None = None) -> list[dict]:
    """The honest, HARD version of InjecAgent: for every attacker instruction we emit BOTH
      * the injected version (arrives via a tool output → provenance 'tool', label 1), and
      * a legitimate version where the USER themselves asks for the same thing (provenance 'user',
        label 0).
    The instruction text is identical; the ONLY discriminator is provenance. This kills the
    surface-text shortcut and tests exactly what ddbt/sift claim matters — 'could a stranger have
    chosen this?'. Pure-semantic methods should collapse here; fusion (which sees the SOURCE tag /
    structural provenance) should hold. It is a deliberately adversarial framing, reported separately."""
    path = _bench_dir() / "injecagent" / f"{kind}_base.json"
    items = json.loads(path.read_text())
    recs: list[dict] = []
    for i, it in enumerate(items):
        goal = it.get("User Instruction", "")
        instr = it.get("Attacker Instruction", "")
        atk_tools = it.get("Attacker Tools") or []
        if isinstance(atk_tools, str):
            atk_tools = [atk_tools]
        if not (instr and atk_tools):
            continue
        tool = atk_tools[0]
        # injected → bad (provenance tool)
        recs.append({"tool": tool, "args": {"instruction": instr}, "goal": goal,
                     "sink_provenance": "tool", "label": 1, "domain": "injecagent",
                     "category": "injected", "id": f"iap/{kind}/{i}/tool"})
        # same instruction, but the user asked for it → benign (provenance user)
        recs.append({"tool": tool, "args": {"instruction": instr}, "goal": instr,
                     "sink_provenance": "user", "label": 0, "domain": "injecagent",
                     "category": "user_requested", "id": f"iap/{kind}/{i}/user"})
    return recs[:limit] if limit else recs


def _bucket(text: str) -> int:
    import hashlib
    return int(hashlib.blake2b(text.encode(), digest_size=4).hexdigest(), 16) % 100


def _split_ok(text: str, split: str, test_ratio: float) -> bool:
    if split == "all":
        return True
    is_test = _bucket(text) < int(test_ratio * 100)
    return is_test if split == "test" else not is_test


def load_toolemu_labeled(split: str = "all", test_ratio: float = 0.2) -> list[dict]:
    """ToolEmu cases → labelled TRAINING records (general 'bad action' sense, not SQL specifics).
    Each case's described Potential Risky Action → label 1; its Expected Achievement → label 0.
    Prose is fine — the model is learning the *shape* of a risky vs correct action across many domains."""
    p = _bench_dir() / "toolemu" / "all_cases.json"
    if not p.is_file():
        return []
    out = []
    for i, r in enumerate(json.loads(p.read_text())):
        goal = r.get("User Instruction", "")
        tk = (r.get("Toolkits") or ["tool"])[0]
        for risky in (r.get("Potential Risky Actions") or [])[:2]:
            t = f"TOOL={tk} ARGS: {risky}"
            if _split_ok(t, split, test_ratio):
                out.append({"tool": tk, "args": risky, "goal": goal, "label": 1,
                            "domain": "toolemu", "category": "risky"})
        for good in (r.get("Expected Achievements") or [])[:2]:
            t = f"TOOL={tk} ARGS: {good}"
            if _split_ok(t, split, test_ratio):
                out.append({"tool": tk, "args": good, "goal": goal, "label": 0,
                            "domain": "toolemu", "category": "expected"})
    return out


def load_agentsafetybench_labeled(split: str = "all", test_ratio: float = 0.2, limit: int | None = None) -> list[dict]:
    """Agent-SafetyBench → labelled TRAINING records. Unsafe instruction (fulfillable=0) → 1,
    safe/fulfillable → 0. Broad multi-domain harm signal (IoT, medical, email, finance, …)."""
    p = _bench_dir() / "agentsafetybench" / "released_data.json"
    if not p.is_file():
        return []
    rows = json.loads(p.read_text())
    out = []
    for r in rows[:limit] if limit else rows:
        instr = r.get("instruction", "")
        if not instr:
            continue
        if not _split_ok(instr, split, test_ratio):
            continue
        label = 1 if int(r.get("fulfillable", 1)) == 0 else 0
        out.append({"tool": "agent_action", "args": {"instruction": instr},
                    "goal": "assist the user with their request", "label": label,
                    "domain": "agentsafetybench", "category": ",".join(r.get("risks", []))[:40] or "task"})
    return out


LOADERS = {
    "rjudge": load_rjudge,
    "injecagent": lambda limit=None: load_injecagent("ds", limit),
    "injecagent_dh": lambda limit=None: load_injecagent("dh", limit),
    "injecagent_prov": lambda limit=None: load_injecagent_provtest("ds", limit),
    "mcptox": load_mcptox,
}
