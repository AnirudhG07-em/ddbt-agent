"""Intent judge interface (doc §3.4, §5.2) — the privilege-separated relevance judge.

The whole reason an intent judge is safe here: it receives ONLY a trusted goal and
typed STRUCTURAL facts about an action (tool, op, target domain/path, stakes). It
never sees tool outputs, file contents, fetched pages, or the agent's free-text
reasoning — all of which can carry an injection. So the attacker cannot talk to the
judge; the most they can do is make the model emit a plausible-looking target, which
the deterministic data-flow / sensitive guards still cover underneath.

A judge may only ever refine the *judgeable* middle tier. It can never rescue the hard
tier (sensitive source, toxic flow, out-of-envelope destruction) — that gate is
deterministic and the engine never consults the judge for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class IntentFacts:
    """Exactly what the judge is allowed to see. No untrusted bytes, by construction."""

    goal: str  # the trusted user goal (from the pristine prompt)
    tool: str  # tool name, e.g. "Bash", "WebFetch"
    op: str  # "read" | "write" | "send" | "delete" | ...
    targets: list[str]  # structural targets: domains / paths (NOT their contents)
    stakes: str  # "low" | "high"

    def render(self) -> str:
        tgt = ", ".join(self.targets) or "(none)"
        return (
            f"USER GOAL (trusted): {self.goal}\n"
            f"PROPOSED ACTION (structural facts only):\n"
            f"  tool   = {self.tool}\n"
            f"  op     = {self.op}\n"
            f"  target = {tgt}\n"
            f"  stakes = {self.stakes}"
        )


@dataclass(slots=True)
class Verdict:
    relevant: bool
    reason: str


class IntentJudge(Protocol):
    def judge(self, facts: IntentFacts) -> Verdict:
        """Decide whether the action plausibly serves the goal. Structural facts only."""
        ...
