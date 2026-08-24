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
import time
from dataclasses import dataclass

from ddbt.core import bootstrap, chromatics, provenance
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
    risk: str = "none"  # chromatic band (chromatics.classify): none|low|med|high — telemetry only
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
            "risk": self.risk,
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


def _who(labels: list[str]) -> str:
    """Collapse the provenance labels to who chose this step's consequential value — the input
    the chromatic band needs. 'stranger' = injection-derived, 'unknown' = no known origin."""
    t = " ".join(labels)
    if "INJECTION-DERIVED" in t:
        return "stranger"
    if "UNKNOWN origin" in t:
        return "unknown"
    return "you"


def _summarize(tool: str, tool_input: dict) -> str:
    """A short, structural one-liner for the audit log (not a decision input)."""
    if not isinstance(tool_input, dict):
        return f"{tool}: {str(tool_input)[:80]}"
    if tool == "Bash":
        return f"Bash: {str(tool_input.get('command',''))[:80]}"
    key = tool_input.get("file_path") or tool_input.get("url") or tool_input.get("path") or ""
    return f"{tool}: {key}"[:90]


class Engine:
    def __init__(self, session_id, workspace_root, base_dir=None, step_judge=None, ddbd=True,
                 error_effect="ask", grant=None, gate_offgoal=False, **_legacy):
        self.session_id = session_id
        self.workspace_root = workspace_root
        self.ddbd = ddbd  # axis 2 (harm/ethics). Axis 1 (goal-fidelity) is always on. Benchmarks isolating axis 1 set False.
        # judge infra failure → ask (human decides) interactively, or deny (fail-closed) for benchmarks.
        self.error_effect = Effect.DENY if str(error_effect).lower() == "deny" else Effect.ASK
        self.store = SessionStore(session_id, base_dir=base_dir)
        self.audit = AuditLogger(self.store)
        self.step_judge = step_judge or make_step_judge()
        # the agent's own capability ticket: a deterministic floor checked BEFORE the judge (un-foolable by injection). None = judge-only.
        self.grant = grant
        # True → benign off-goal steps (clean provenance, no exfil) gate for a human instead of hard-denying.
        # Injection-linked deviation still hard-denies. On in the hook; off in benchmarks (preserves measured behaviour).
        self.gate_offgoal = gate_offgoal
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

        # provenance labels — computed once, reused for the chromatic "who" and the judge facts
        labels = self._labels(tool_input)
        who = _who(labels)

        # HARD FLOOR: the capability ticket, checked deterministically before the judge — policy +
        # arithmetic, not an LLM reading text, so injection can't talk past it. Also the fast path:
        # an in-scope read is allowed here with no model call.
        gcheck = None
        if self.grant is not None:
            gcheck = self.grant.check(tool_name, tool_input, now=time.time(), used=self._grant_used())
            if gcheck.effect == "deny":
                # a floor breach means the session is being probed — ratchet suspicion (atomic).
                self.store.increment_meta("suspicion", 3)
                aid = self.audit.decision(checkpoint="out-of-scope", state="deny", tool=tool_name,
                                          summary=_summarize(tool_name, tool_input), reason=gcheck.reason,
                                          suspicion=self._suspicion())
                return Decision(Effect.DENY, "deny", "out-of-scope", gcheck.reason,
                                relevant=False, stray=False,
                                risk=chromatics.classify("deny", "out-of-scope", False, False, False, who),
                                audit_id=aid)
            if gcheck.effect == "allow":
                aid = self.audit.decision(checkpoint="grant-fastpath", state="allow", tool=tool_name,
                                          summary=_summarize(tool_name, tool_input), reason=gcheck.reason)
                return Decision(Effect.ALLOW, "allow", "grant-fastpath", gcheck.reason,
                                risk=chromatics.classify("allow", "grant-fastpath", True, False, False, who),
                                audit_id=aid)
            # gcheck.effect == "defer" → in scope but consequential; fall through to the judge

        # show the judge the quarantined output that MENTIONS this step's arguments (not merely the
        # most recent) — else an injection ingested steps ago drops out of the window before it acts.
        values = [v for v, is_id in self._consequential_values(tool_input) if is_id]
        evidence = self.store.quarantine_matching(values, limit=2) or self.store.recent_quarantine(2)

        facts = StepFacts(
            goal=self.goal,
            tool=tool_name,
            args=tool_input,
            input_labels=labels,
            quarantined=evidence,
            history=self._history(),
        )
        verdict = self.step_judge.judge(facts)
        strictness = self._strictness()  # derived from suspicion accumulated by PRIOR steps
        effect, checkpoint = self._combine(verdict, strictness, who)
        if not verdict.error:
            # this step's evidence tightens FUTURE steps (see _bump_suspicion)
            self._bump_suspicion(verdict, blocked=effect is Effect.DENY)

        # a call going ahead spends one unit of grant quota (atomic). ASK counts too — debit at
        # decision time so a spent ticket denies the next step.
        if gcheck is not None and gcheck.quota_key and effect in (Effect.ALLOW, Effect.ASK):
            self.store.increment_meta(f"grant_used:{gcheck.quota_key}", 1)

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
            error=verdict.error,
            risk=chromatics.classify(effect.value, checkpoint, verdict.serves_goal,
                                     verdict.harmful, verdict.deviation, who),
            audit_id=aid,
        )

    def _combine(self, verdict, strictness: int = 0, who: str = "you") -> tuple[Effect, str]:
        """Checklist → decision. Axis 1 (deviation) hard-denies injection-linked steps; axis 2
        (harm) denies when ddbd is on; then adaptive strictness tightens a suspicious session."""
        if verdict.error:
            # infra failure (429, timeout, dead key) is not a security finding — ask a human,
            # don't hard-deny (that would brick a tool call in your editor). Benchmarks set "deny".
            return self.error_effect, "judge-error"
        if verdict.deviation:
            # Off-goal + injection-linked (stranger/unknown provenance, suspected injection, or
            # exfil) is a hard DENY. A benign off-goal step on the agent's own initiative gates
            # for a human when gate_offgoal is on. Keying on provenance keeps real injections denied.
            injection_linked = (verdict.injection_suspected or verdict.external_exfil
                                or who in ("stranger", "unknown"))
            if self.gate_offgoal and not injection_linked:
                return Effect.ASK, "off-goal-gate"
            return Effect.DENY, "goal-fidelity"  # axis 1
        if self.ddbd and verdict.harmful:
            return Effect.DENY, "ethics"  # axis 2 — only when ddbd enabled
        soft = verdict.requests_secrecy or verdict.side_task or verdict.injection_suspected
        if strictness >= 2:  # LOCKED — session looks compromised; only basic work passes
            if verdict.high_impact or soft:
                return Effect.DENY, "locked"
            return Effect.ALLOW, "judge"
        if strictness == 1:  # ELEVATED — tighten, but keep a human in the loop (gate, don't deny)
            if verdict.high_impact or soft:
                return Effect.ASK, "elevated-gate"
            return Effect.ALLOW, "judge"
        # NORMAL
        if verdict.high_impact:
            return Effect.ASK, "gate"  # on-goal but high-impact → ask a human
        return Effect.ALLOW, "judge"

    # ---- adaptive session suspicion (progressive enforcement) ----

    _SUSPICION_WEIGHTS = {"harmful": 3, "deviation": 2, "requests_secrecy": 2,
                          "injection_suspected": 2, "external_exfil": 1, "side_task": 1}
    # accrue suspicion only from a blocked step, or when ≥2 signals corroborate — one soft flag on
    # an allowed step is the judge noticing, not proof, and treating it as proof brought false positives.
    _MIN_CORROBORATING_SIGNALS = 2

    def _grant_used(self) -> dict:
        """Current spend per quota key, read from the durable store (survives across steps)."""
        if not self.grant or not self.grant.quotas:
            return {}
        return {pat: int(self.store.get_meta(f"grant_used:{pat}", "0") or "0") for pat in self.grant.quotas}

    def _suspicion(self) -> int:
        return int(self.store.get_meta("suspicion", "0") or "0")

    def _strictness(self) -> int:
        # ELEVATED ≈ two blocked deviations, LOCKED ≈ four (sized against the weights above).
        s = self._suspicion()
        computed = 0 if s < 6 else (1 if s < 12 else 2)
        # RATCHET: strictness only rises. No continuation or decay lowers it — only `ddbt clear`.
        # Atomic SQL max() because hooks run as parallel subprocesses.
        return self.store.raise_meta_floor("strictness_floor", computed)

    def _bump_suspicion(self, verdict, blocked: bool) -> None:
        """Accrue suspicion from evidence only: a blocked step, or ≥2 corroborating signals."""
        fired = [sig for sig in self._SUSPICION_WEIGHTS if getattr(verdict, sig, False)]
        if not fired:
            return
        if not blocked and len(fired) < self._MIN_CORROBORATING_SIGNALS:
            return
        w = sum(self._SUSPICION_WEIGHTS[sig] for sig in fired)
        self.store.increment_meta("suspicion", w)  # atomic: concurrent hooks can't lose it

    def clear_suspicion(self, reason: str) -> int:
        """Audited human clearance — the only way the guard comes down (the trusted user says so,
        on the record). Nothing an attacker can trigger; the alternative to this is losing context."""
        before = self._suspicion()
        self.store.set_meta("suspicion", "0")
        self.store.set_meta("strictness_floor", "0")
        self.audit.event("suspicion_cleared", previous=before, reason=reason)
        return before

    def _labels(self, tool_input: dict) -> list[str]:
        """Where did each argument come from? — the decisive anti-injection signal. Not "did this
        value appear in output" (legitimate values do) but "could an attacker have chosen it?":

          user-named        appears in the trusted goal
          grounded          was a FIELD in a tool result — the producing system chose it
          injection-derived appears only inside free text — its author chose it
          unknown           never seen before this step

        A structural lookup (core/provenance.py) — no wordlists, no model, no decay.
        """
        labels: list[str] = []
        n = self.store.quarantine_count()
        if n:
            labels.append(f"session has ingested {n} quarantined (untrusted) tool output(s)")
        goal = (self.goal or "").lower()

        for val, is_identifier in self._consequential_values(tool_input):
            v = val.strip().lower()
            if v in goal:
                labels.append(f"arg {val[:60]!r} is named in the user goal → USER-NAMED")
                continue
            sightings = self.store.lookup_provenance(v)
            if not sightings:
                # only worth saying for a destination; "unknown origin" on prose (a subject, a body) is noise.
                if is_identifier:
                    labels.append(
                        f"arg {val[:60]!r} is a destination that appears neither in the goal "
                        f"nor in any tool result → UNKNOWN origin"
                    )
                continue
            field = [s for s in sightings if s["origin"] == provenance.FIELD]
            if field:
                labels.append(
                    f"arg {val[:60]!r} was a structured field ({field[0]['path']}) returned by "
                    f"{field[0]['tool']} → GROUNDED (the tool's own data, not attacker-written text)"
                )
            else:
                s = sightings[0]
                labels.append(
                    f"arg {val[:60]!r} appears ONLY inside untrusted free text ({s['path']}) from "
                    f"{s['tool']} → INJECTION-DERIVED (whoever wrote that text chose this value)"
                )
        return labels

    def _consequential_values(self, tool_input: dict) -> list[tuple[str, bool]]:
        """Argument values as (value, is_identifier). Identifiers (addresses, URLs, paths, handles)
        decide where an effect lands. Other short values are looked up but not reported when unknown."""
        out: list[tuple[str, bool]] = []
        seen: set[str] = set()
        for val in _string_values(tool_input):
            identifiers = provenance.extract(val)
            for _, text in identifiers:
                if text.lower() not in seen:
                    seen.add(text.lower())
                    out.append((text, True))
            v = val.strip()
            if 4 <= len(v) <= 120 and v.lower() not in seen and not identifiers:
                seen.add(v.lower())
                out.append((v, False))
        return out

    def _history(self, n: int = 6) -> list[str]:
        """Recent prior steps — trajectory context so the judge can tell a continuation from a drift."""
        decisions = [e for e in self.audit.trail() if e.get("kind") == "decision"]
        return [f"{e.get('tool','')} {e.get('summary','')} → {e.get('state','')}" for e in decisions[-n:]]

    def record_result(self, tool_name: str, tool_input: dict, tool_response: dict, cwd: str | None = None) -> None:
        """Quarantine a step's returned text and index where its values sat. The quarantine keeps
        raw content as later evidence; the provenance index records, per identifier, whether it was
        a structured FIELD or embedded in free text — what lets the next step tell "reply to the
        sender" from "mail the address the sender's message told me to mail"."""
        # index the STRUCTURED response first — the shape is the signal, so index before flattening
        payload = tool_response
        if isinstance(tool_response, dict):
            inner = tool_response.get("content") or tool_response.get("output") or tool_response.get("stdout")
            payload = tool_response if inner is None else inner
        try:
            rows = provenance.index_response(payload)
        except Exception:  # indexing is best-effort; never break a tool call over it
            rows = []
        if rows:
            self.store.add_provenance(tool_name, rows)

        content = ""
        if isinstance(tool_response, dict):
            content = str(tool_response.get("content") or tool_response.get("output") or tool_response.get("stdout") or "")
        elif tool_response:
            content = str(tool_response)
        if content:
            self.store.add_quarantine(tool_name, content[:8000])
            self.audit.event(
                "quarantined", tool=tool_name, bytes=len(content),
                indexed=len(rows), embedded=sum(1 for r in rows if r["origin"] == provenance.CONTENT),
            )

    def commit_batch(self) -> CommitResult:
        return CommitResult(ok=True)

    def audit_trail(self) -> str:
        return self.audit.render()

    def close(self) -> None:
        self.store.close()
