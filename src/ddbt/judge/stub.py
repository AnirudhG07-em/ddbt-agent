"""Deterministic step-judge stubs — for CI/offline (the real judge needs an API key)."""

from __future__ import annotations

from dataclasses import dataclass

from ddbt.judge.step_judge import StepFacts, Verdict


@dataclass(slots=True)
class FixedStepJudge:
    """Always returns the same decision — for testing the engine's allow/gate/deny branches."""

    decision: str = "allow"
    reason: str = "fixed verdict"

    def judge(self, facts: StepFacts) -> Verdict:
        return Verdict(
            decision=self.decision,
            relevant=self.decision != "deny",
            harmful=self.decision == "deny",
            stray=self.decision == "deny",
            reason=self.reason,
        )


@dataclass(slots=True)
class ScriptedStepJudge:
    """Returns decisions by tool name from a mapping (default 'allow'); deterministic.

    e.g. ScriptedStepJudge({"send_money": "deny", "rm": "gate"}) — lets a test express the
    judge's verdicts without an LLM, while exercising real engine wiring."""

    by_tool: dict | None = None
    default: str = "allow"

    def judge(self, facts: StepFacts) -> Verdict:
        decision = (self.by_tool or {}).get(facts.tool, self.default)
        return Verdict(
            decision=decision,
            relevant=decision != "deny",
            harmful=decision == "deny",
            stray=decision == "deny",
            reason=f"scripted:{decision}",
        )
