"""Deterministic step-judge stubs — for CI/offline (the real judge needs an API key)."""

from __future__ import annotations

from dataclasses import dataclass

from ddbt.judge.step_judge import StepFacts, Verdict


def _verdict_for(decision: str, reason: str) -> Verdict:
    """Map a simple allow/gate/deny intent onto the two-axis Verdict (for deterministic stubs).
    'deny' → deviation (axis 1); 'gate' → high_impact; 'allow' → clean."""
    return Verdict(
        serves_goal=decision != "deny",
        deviation=decision == "deny",
        harmful=False,
        high_impact=decision == "gate",
        reason=reason,
    )


@dataclass(slots=True)
class FixedStepJudge:
    """Always returns the same decision — for testing the engine's allow/gate/deny branches."""

    decision: str = "allow"
    reason: str = "fixed verdict"

    def judge(self, facts: StepFacts) -> Verdict:
        return _verdict_for(self.decision, self.reason)


@dataclass(slots=True)
class ScriptedStepJudge:
    """Returns decisions by tool name from a mapping (default 'allow'); deterministic.

    e.g. ScriptedStepJudge({"send_money": "deny", "rm": "gate"}) — lets a test express the
    judge's verdicts without an LLM, while exercising real engine wiring.

    'harm:<tool>' as a value marks the axis-2 harm flag (to test the ddbt ethics knob)."""

    by_tool: dict | None = None
    default: str = "allow"

    def judge(self, facts: StepFacts) -> Verdict:
        decision = (self.by_tool or {}).get(facts.tool, self.default)
        if decision == "harm":  # axis-2 only: on-goal but intrinsically harmful
            return Verdict(serves_goal=True, deviation=False, harmful=True, reason="scripted:harm")
        return _verdict_for(decision, f"scripted:{decision}")
