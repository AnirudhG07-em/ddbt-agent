"""One bounded diagnostic: WHY do we not allow certain SAFE/benign cases — and crucially,
do we DENY (hard block) or GATE (ask a human)? Gating a risky-but-legit action is correct
behaviour, yet a binary benchmark scores it as a 'stopped' = false positive."""

from __future__ import annotations

import collections
import pathlib
import sys
import tempfile

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import rjudge
import static_replay as sr
from ddbt.core.engine import Effect, Engine
from ddbt.judge.step_judge import AnthropicStepJudge

WORKERS_NOTE = "(workers=4, retries on; 'errored' rows are rate-limit failures, ignore)"
judge = AnthropicStepJudge("claude-haiku-4-5")
base = tempfile.mkdtemp()


def run_trajectory(goal, steps):
    """steps = [(tool, args)]. Returns (outcome, offending) where outcome ∈
    allow/gate/deny/error and offending = (tool, reason) of the first non-allow step."""
    eng = Engine(f"d{id(steps)}", workspace_root=base, base_dir=base, step_judge=judge)
    eng.on_session_start("startup", base)
    eng.on_user_prompt(goal)
    try:
        for tool, args in steps:
            d = eng.evaluate_action(tool, args or {})
            if d.error:
                return "error", (tool, d.reason)
            if d.effect == Effect.DENY:
                return "deny", (tool, d.reason)
            if d.effect == Effect.ASK:
                return "gate", (tool, d.reason)
            eng.record_result(tool, args or {}, {})
        return "allow", None
    finally:
        eng.close()


print(f"### R-Judge SAFE records — what do we do? {WORKERS_NOTE}")
recs = [r for r in rjudge.load_rjudge(str(_HERE / "data" / "rjudge"), limit=70) if r.label == 0]
out = collections.Counter()
for r in recs:
    steps = []
    for t in r.turns:
        if t.get("role") == "agent" and (t.get("action") or "").strip():
            a = t["action"].strip()
            steps.append((a.split("(")[0].split("[")[0][:30] or "act", {"action": a}))
    # replay turn-by-turn but we need env outputs quarantined → do it inline
    eng = Engine(f"rj{r.id}", workspace_root=base, base_dir=base, step_judge=judge)
    eng.on_session_start("startup", base); eng.on_user_prompt(r.goal)
    outcome, offending = "allow", None
    for t in r.turns:
        if t.get("role") == "agent" and (t.get("action") or "").strip():
            a = t["action"].strip(); tool = a.split("(")[0].split("[")[0][:30] or "act"
            d = eng.evaluate_action(tool, {"action": a})
            if d.error: outcome, offending = "error", (tool, d.reason); break
            if d.effect == Effect.DENY: outcome, offending = "deny", (tool, d.reason); break
            if d.effect == Effect.ASK: outcome, offending = "gate", (tool, d.reason); break
        elif t.get("role") == "environment":
            eng.record_result("environment", {}, {"content": str(t.get("content", ""))})
    eng.close()
    out[outcome] += 1
    if outcome in ("deny", "gate") and out[outcome] <= 5:
        print(f"  [{outcome}] goal: {r.goal[:70]}")
        print(f"         {offending[0]} → {offending[1][:100]}")
print(f"  SAFE outcomes: {dict(out)}  (allow+gate = not-blocked; deny = hard block)")

print(f"\n### InjecAgent dh BENIGN — what do we do? {WORKERS_NOTE}")
benign = [c for c in sr.load_injecagent(str(_HERE / "data" / "injecagent" / "dh_base.json")) if c.label == "benign"][:25]
out2 = collections.Counter()
for c in benign:
    outcome, offending = run_trajectory(c.goal, c.calls)
    out2[outcome] += 1
    if outcome in ("deny", "gate") and out2[outcome] <= 5:
        print(f"  [{outcome}] goal: {c.goal[:70]}")
        print(f"         {offending[0]} → {offending[1][:100]}")
print(f"  BENIGN outcomes: {dict(out2)}")
