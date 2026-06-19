"""Adaptive strictness (progressive enforcement): the judge's per-step checklist feeds a
session suspicion score; a session that shows malicious signals tightens (gate→deny→lock),
while a clean session stays permissive. Deterministic stub judge, no API."""

from __future__ import annotations

from ddbt.core.engine import Effect, Engine
from ddbt.judge.step_judge import Verdict


class SeqJudge:
    """Returns a preset sequence of verdicts (last one repeats)."""

    def __init__(self, verdicts):
        self.verdicts = list(verdicts)
        self.i = 0

    def judge(self, facts):
        v = self.verdicts[min(self.i, len(self.verdicts) - 1)]
        self.i += 1
        return v


def _eng(make_engine, judge):
    eng, _ = make_engine(judge=judge, goal="do the task")
    return eng


def test_clean_session_high_impact_only_gates(make_engine):
    eng = _eng(make_engine, SeqJudge([Verdict(serves_goal=True, high_impact=True)]))
    d = eng.evaluate_action("Bash", {"command": "rm build"})
    assert d.effect == Effect.ASK and d.checkpoint == "gate"  # normal: high-impact → gate
    assert eng._suspicion() == 0
    eng.close()


def test_soft_signals_raise_suspicion_then_tighten(make_engine):
    # step 1: soft signals (secrecy + side-task) → allowed at strict 0, but raises suspicion
    # step 2: an on-goal high-impact action that would normally GATE is now hard-DENIED
    eng = _eng(make_engine, SeqJudge([
        Verdict(serves_goal=True, requests_secrecy=True, side_task=True),  # +2 +1 = 3 → strict 1
        Verdict(serves_goal=True, high_impact=True),
    ]))
    d1 = eng.evaluate_action("Read", {"file_path": "a"})
    assert d1.effect == Effect.ALLOW          # soft signals don't block at strict 0
    assert eng._suspicion() == 3 and eng._strictness() == 1
    d2 = eng.evaluate_action("Bash", {"command": "rm build"})
    assert d2.effect == Effect.DENY and d2.checkpoint == "elevated"  # was gate, now denied
    eng.close()


def test_session_locks_down(make_engine):
    # accumulate suspicion past the lockdown threshold → even a soft-signal step is denied
    eng = _eng(make_engine, SeqJudge([
        Verdict(serves_goal=True, requests_secrecy=True, injection_suspected=True),  # +4 → strict 1
        Verdict(serves_goal=True, requests_secrecy=True, injection_suspected=True),  # +4 → 8 → strict 2
        Verdict(serves_goal=True, side_task=True),                                   # soft → locked
    ]))
    eng.evaluate_action("Read", {"file_path": "a"})
    eng.evaluate_action("Read", {"file_path": "b"})
    assert eng._strictness() == 2
    d3 = eng.evaluate_action("Read", {"file_path": "c"})
    assert d3.effect == Effect.DENY and d3.checkpoint == "locked"
    eng.close()


def test_checklist_is_recorded_in_audit(make_engine):
    eng = _eng(make_engine, SeqJudge([Verdict(serves_goal=True, requests_secrecy=True, accesses_secrets=True)]))
    eng.evaluate_action("Read", {"file_path": "a"})
    dec = [e for e in eng.audit.trail() if e["kind"] == "decision"][-1]
    # the full diagnostic checklist is gathered in the audit log
    assert dec["requests_secrecy"] is True and dec["accesses_secrets"] is True
    assert "suspicion" in dec and "strictness" in dec
    eng.close()
