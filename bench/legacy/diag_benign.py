"""Diagnostic: show WHY benign InjecAgent tasks get denied (goal, action, the judge's reason)."""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import static_replay as sr
from ddbt.core.engine import Effect, Engine
from ddbt.judge.step_judge import AnthropicStepJudge

kind = sys.argv[1] if len(sys.argv) > 1 else "dh"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 60
cases = [c for c in sr.load_injecagent(f"{pathlib.Path(__file__).resolve().parent}/data/injecagent/{kind}_base.json") if c.label == "benign"][:n]
j = AnthropicStepJudge("claude-haiku-4-5")
base = tempfile.mkdtemp()
shown = 0
for i, c in enumerate(cases):
    e = Engine(f"b{i}", workspace_root=base, base_dir=base, step_judge=j)
    e.on_session_start("startup", base)
    e.on_user_prompt(c.goal)
    for tool, args in c.calls:
        d = e.evaluate_action(tool, args or {})
        if d.effect == Effect.DENY and shown < 12:
            print(f"\nDENIED benign #{i}: tool={tool}")
            print(f"  goal  : {c.goal[:90]}")
            print(f"  args  : {str(args)[:90]}")
            print(f"  reason: {d.reason[:110]}")
            shown += 1
    e.close()
print(f"\n({shown} denied benign shown of first {n})")
