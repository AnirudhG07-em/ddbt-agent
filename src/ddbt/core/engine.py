"""The enforcement engine — v4 judge-centric (see ARCHITECTURE.md).

The decider is an LLM step-judge, not a keyword pipeline. For every system-touching step
the engine builds content-aware facts (trusted goal + proposed action + provenance labels
+ quarantined tool outputs) and asks the judge: relevant? harmful? stray? → allow/gate/deny.
Every tool output is quarantined so nothing leaks except via a judged-and-approved flow,
and every step is written to a lawful audit trail. No wordlists anywhere.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass

from ddbt.core import bootstrap
from ddbt.core.audit import AuditLogger
from ddbt.judge.provider import make_step_judge
from ddbt.judge.step_judge import StepFacts
from ddbt.store.session import SessionStore

_CONTINUATION = {"continue", "keep going", "go on", "next", "proceed", "yes", "do it", "go ahead", "resume"}
# tools with no system effect — pure bookkeeping/chat, never judged (doc: chat flows free)
_NOOP_TOOLS = {"TodoWrite"}


class Effect(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


_DECISION_TO_EFFECT = {"allow": Effect.ALLOW, "gate": Effect.ASK, "deny": Effect.DENY}


@dataclass(slots=True)
class Decision:
    effect: Effect
    state: str  # the judge's raw decision ("allow"|"gate"|"deny")
    checkpoint: str  # "judge" | "noop" | "judge-error"
    reason: str
    relevant: bool = True
    harmful: bool = False
    stray: bool = False
    error: bool = False  # judge couldn't decide (infra failure) — denied defensively, but flagged
    audit_id: int = 0

    @property
    def overridable(self) -> bool:
        return self.effect != Effect.DENY

    def to_dict(self) -> dict:
        return {
            "effect": self.effect.value,
            "decision": self.state,
            "reason": self.reason,
            "relevant": self.relevant,
            "harmful": self.harmful,
            "stray": self.stray,
        }


@dataclass(slots=True)
class CommitResult:
    ok: bool = True
    released: int = 0
    held: list = None

    def summary(self) -> str:
        return "commit: per-step judging applied; quarantined outputs released only on approval"


def _is_substantive_goal(prompt: str) -> bool:
    # tolerate None/non-str: this is the security path, and a crash here takes the whole
    # engine down. Anything that isn't real text simply isn't a substantive goal.
    if not isinstance(prompt, str):
        return False
    p = prompt.strip().lower().rstrip(".!")
    if p in _CONTINUATION:
        return False
    return len(re.findall(r"[a-z0-9]{3,}", p)) >= 3


def _string_values(obj) -> list[str]:
    """Flatten the string leaves of a tool-input structure (for provenance matching)."""
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_string_values(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_string_values(v))
    return out


def _summarize(tool: str, tool_input: dict) -> str:
    """A short, structural one-liner for the audit log (not a decision input)."""
    if not isinstance(tool_input, dict):
        return f"{tool}: {str(tool_input)[:80]}"
    if tool == "Bash":
        return f"Bash: {str(tool_input.get('command',''))[:80]}"
    key = tool_input.get("file_path") or tool_input.get("url") or tool_input.get("path") or ""
    return f"{tool}: {key}"[:90]


class Engine:
    def __init__(self, session_id, workspace_root, base_dir=None, step_judge=None, ddbd=True, **_legacy):
        # ddbd=True enables AXIS 2 (the "Don't Do Bad Things" ethics/harm layer). Axis 1
        # (goal-fidelity / anti-injection) is ALWAYS on. Benchmarks measuring operational
        # safety (e.g. R-Judge) set ddbd=False to isolate axis 1.
        self.session_id = session_id
        self.workspace_root = workspace_root
        self.ddbd = ddbd
        self.store = SessionStore(session_id, base_dir=base_dir)
        self.audit = AuditLogger(self.store)
        self.step_judge = step_judge or make_step_judge()
        self.goal = self.store.get_meta("goal", "") or ""

    # ---- lifecycle ----

    def on_session_start(self, source: str, cwd: str, named_grants=None) -> bootstrap.BootstrapResult:
        self.workspace_root = cwd or self.workspace_root
        result = bootstrap.verify(self.workspace_root)
        self.audit.event("bootstrap", status=result.status, detail=result.summary())
        return result

    def verify_config(self, cwd: str | None = None) -> bootstrap.BootstrapResult:
        result = bootstrap.verify(cwd or self.workspace_root)
        self.audit.event("bootstrap", status=result.status, detail=result.summary())
        return result

    def on_user_prompt(self, prompt: str) -> str:
        # the trusted goal anchors every relevance judgment; "continue" keeps the standing goal
        if _is_substantive_goal(prompt):
            self.goal = prompt.strip()
            self.store.set_meta("goal", self.goal)
        denials = [e for e in self.audit.trail() if e.get("kind") == "decision" and e.get("state") == "deny"]
        if denials:
            return f"[ddbt] note: a prior step was blocked ({denials[-1].get('reason')}). Stay on the stated task."
        return ""

    # ---- per-step decision (the judge is the decider) ----

    def evaluate_action(self, tool_name: str, tool_input: dict, cwd: str | None = None) -> Decision:
        tool_input = tool_input or {}
        if not isinstance(tool_input, dict):
            tool_input = {"value": tool_input}  # tolerate string/list args from varied agents
        if tool_name in _NOOP_TOOLS:
            aid = self.audit.decision(checkpoint="noop", state="allow", tool=tool_name, summary="no system effect", reason="pure tool")
            return Decision(Effect.ALLOW, "allow", "noop", "pure tool, no system effect", audit_id=aid)

        facts = StepFacts(
            goal=self.goal,
            tool=tool_name,
            args=tool_input,
            input_labels=self._labels(tool_input),
            quarantined=self.store.recent_quarantine(3),
            history=self._history(),
        )
        verdict = self.step_judge.judge(facts)
        strictness = self._strictness()  # derived from suspicion accumulated by PRIOR steps
        effect, checkpoint = self._combine(verdict, strictness)
        if not verdict.error:
            self._bump_suspicion(verdict)  # this step's checklist tightens FUTURE steps

        aid = self.audit.decision(
            checkpoint=checkpoint,
            state=effect.value,
            tool=tool_name,
            summary=_summarize(tool_name, tool_input),
            reason=verdict.reason,
            error=verdict.error,
            strictness=strictness,
            suspicion=self._suspicion(),
            **verdict.signals(),  # the full diagnostic checklist (data-gathering)
        )
        return Decision(
            effect, effect.value, checkpoint, verdict.reason,
            relevant=verdict.serves_goal, harmful=verdict.harmful, stray=verdict.deviation,
            error=verdict.error, audit_id=aid,
        )

    def _combine(self, verdict, strictness: int = 0) -> tuple[Effect, str]:
        """Combine the checklist into a decision. Axis 1 (deviation) ALWAYS hard-denies; axis 2
        (harm) denies when ddbd is on; then adaptive strictness — a session that has shown
        malicious signals (high suspicion) progressively tightens toward lockdown."""
        if verdict.error:
            return Effect.DENY, "judge-error"
        if verdict.deviation:
            return Effect.DENY, "goal-fidelity"  # axis 1 — anti-injection, non-negotiable
        if self.ddbd and verdict.harmful:
            return Effect.DENY, "ethics"  # axis 2 — only when ddbd enabled
        soft = verdict.requests_secrecy or verdict.side_task or verdict.injection_suspected
        if strictness >= 2:  # LOCKED — the session looks compromised
            if verdict.high_impact or soft:
                return Effect.DENY, "locked"
            return Effect.ALLOW, "judge"
        if strictness == 1:  # ELEVATED — tighten the gates
            if verdict.high_impact:
                return Effect.DENY, "elevated"  # was gate, now hard-deny
            if soft:
                return Effect.ASK, "elevated-gate"
            return Effect.ALLOW, "judge"
        # NORMAL
        if verdict.high_impact:
            return Effect.ASK, "gate"  # on-goal but high-impact → ask a human
        return Effect.ALLOW, "judge"

    # ---- adaptive session suspicion (progressive enforcement) ----

    _SUSPICION_WEIGHTS = {"harmful": 3, "deviation": 2, "requests_secrecy": 2,
                          "injection_suspected": 2, "external_exfil": 1, "side_task": 1}

    def _suspicion(self) -> int:
        return int(self.store.get_meta("suspicion", "0") or "0")

    def _strictness(self) -> int:
        s = self._suspicion()
        computed = 0 if s < 3 else (1 if s < 7 else 2)
        # RATCHET: strictness only ever rises. Once a session has tightened, a continuation
        # ("continue with operation") or any future suspicion-decay can never lower the guard.
        # Done as one atomic SQL max() — hooks run as parallel subprocesses, and a Python-side
        # read-max-write would let a stale reader undo another hook's tightening.
        return self.store.raise_meta_floor("strictness_floor", computed)

    def _bump_suspicion(self, verdict) -> None:
        w = sum(wt for sig, wt in self._SUSPICION_WEIGHTS.items() if getattr(verdict, sig, False))
        if w:
            self.store.increment_meta("suspicion", w)  # atomic: concurrent hooks can't lose it

    def _labels(self, tool_input: dict) -> list[str]:
        """Keyword-free provenance: flag any argument value that traces to quarantined
        (untrusted) tool output rather than the user's goal — the decisive 'is this value
        user-named or injection-derived?' signal. Mechanical string matching, no wordlists."""
        labels: list[str] = []
        n = self.store.quarantine_count()
        if n:
            labels.append(f"session has ingested {n} quarantined (untrusted) tool output(s)")
        quarantined = " ".join(self.store.recent_quarantine(5)).lower()
        goal = (self.goal or "").lower()
        for val in _string_values(tool_input):
            v = val.strip().lower()
            if len(v) < 4:
                continue
            if v in goal:
                labels.append(f"arg value {val[:60]!r} is named in the user goal → user-named")
            elif quarantined and v in quarantined:
                labels.append(
                    f"arg value {val[:60]!r} traces to untrusted tool output, NOT the user goal → injection-derived"
                )
        return labels

    def _history(self, n: int = 6) -> list[str]:
        """Recent prior steps this session (trajectory context for the judge): what the
        agent has already done, so the judge can tell a consistent continuation from a drift."""
        decisions = [e for e in self.audit.trail() if e.get("kind") == "decision"]
        return [f"{e.get('tool','')} {e.get('summary','')} → {e.get('state','')}" for e in decisions[-n:]]

    def record_result(self, tool_name: str, tool_input: dict, tool_response: dict, cwd: str | None = None) -> None:
        # every tool output is quarantined (untrusted-by-default) so the judge can inspect
        # later steps for injected/stray behaviour — and so it never leaks to a live sink.
        content = ""
        if isinstance(tool_response, dict):
            content = str(tool_response.get("content") or tool_response.get("output") or tool_response.get("stdout") or "")
        elif tool_response:
            content = str(tool_response)
        if content:
            self.store.add_quarantine(tool_name, content[:2000])
            self.audit.event("quarantined", tool=tool_name, bytes=len(content))

    def commit_batch(self) -> CommitResult:
        return CommitResult(ok=True)

    def audit_trail(self) -> str:
        return self.audit.render()

    def close(self) -> None:
        self.store.close()
