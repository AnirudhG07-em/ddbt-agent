"""Deterministic intent judge — for CI / offline use (no API key).

Two flavours:
  * KeywordIntentJudge — a crude but deterministic relevance heuristic: an action is
    on-task if a meaningful token of its target appears in the goal. Good enough to
    exercise the wiring without an LLM.
  * FixedIntentJudge — always returns a preset verdict; handy for testing the engine's
    on-task / off-task branches in isolation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ddbt.judge.base import IntentFacts, Verdict

_WORD = re.compile(r"[a-z0-9]{3,}")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.lower()))


@dataclass(slots=True)
class KeywordIntentJudge:
    def judge(self, facts: IntentFacts) -> Verdict:
        goal_tokens = _tokens(facts.goal)
        target_tokens: set[str] = set()
        for t in facts.targets:
            target_tokens |= _tokens(t)
        overlap = goal_tokens & target_tokens
        if overlap:
            return Verdict(True, f"target shares terms with the goal: {sorted(overlap)}")
        return Verdict(False, "no structural relationship between target and goal")


@dataclass(slots=True)
class FixedIntentJudge:
    relevant: bool = True
    reason: str = "fixed verdict"

    def judge(self, facts: IntentFacts) -> Verdict:
        return Verdict(self.relevant, self.reason)
