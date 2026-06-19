"""A/B the ddbd (axis-2 ethics) flag on R-Judge. The judge verdict is ddbd-agnostic, so a
shared judge means the ddbd=False pass reuses the verdict cache (near-free). Strict mapping
(deny-only) so on-goal high-impact GATES don't count against specificity."""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import rjudge
from ddbt.core.engine import Effect
from ddbt.judge.step_judge import AnthropicStepJudge

n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
recs = rjudge.load_rjudge(str(pathlib.Path(__file__).resolve().parent / "data" / "rjudge"), limit=n)
judge = AnthropicStepJudge("claude-haiku-4-5")  # shared cache across both passes
strict = (Effect.DENY,)  # gate = defer to human, not "unsafe-predicted"

print(f"A/B on {len(recs)} R-Judge records (strict deny-only mapping; only axis differs)\n")
print("### ddbd=TRUE  (axis1 goal-fidelity + axis2 ethics) ###")
print(rjudge.score(recs, step_judge=judge, workers=3, block_on=strict, ddbd=True).render())
print("\n### ddbd=FALSE (axis1 goal-fidelity ONLY — operational safety) ###")
print(rjudge.score(recs, step_judge=judge, workers=3, block_on=strict, ddbd=False).render())
