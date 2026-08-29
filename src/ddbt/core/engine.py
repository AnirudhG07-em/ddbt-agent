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
# Operator-facing messages: no external side-effect (the human sees them by construction), so
# they are never a silent hard-block. Surfacing/quoting injected content back to the user is
# transparency, not a dangerous deviation — and a message can't exfiltrate (the user is trusted).
_MESSAGE_TOOLS = {"respond_to_user"}
# read-only tools / shell commands — reading a secret FILE locally is not exfil; it can be shown with
# its sensitive values redacted (ddbt screen) instead of hard-denied. Egress of a secret is still denied.
_READ_TOOLS = {"Read", "LS", "Grep", "Glob", "NotebookRead"}
_READ_CMD = re.compile(r"^\s*(cat|head|tail|less|more|bat|xxd|strings|grep|rg|nl|od|sort|uniq|wc)\b", re.I)
# The session-trajectory gate only fires once a session has at least this many agent steps — a single
# action is not a "trajectory" (that's the per-step judge's job), and scoring one prose action against
# a session threshold just re-flags benign prose. This confines the gate to multi-step attacks.
_TRAJ_MIN_STEPS = 2
# session-trajectory gate default (impact risk over the whole session-so-far → ASK). 0.85 lifts
# held-out R-Judge F1 to ~67 with no change to the single-action benchmarks; 0 disables it.
TRAJ_GATE = 0.85


class Effect(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"
    # a would-be DENY that a human MAY force through — only when deny_mode="override". Distinct from a
    # normal ASK: it means "ddbt wanted to BLOCK this; the session may be dangerous", carrying a loud,
    # layer-specific warning. Nothing is silently un-blockable, but overriding one is a deliberate act.
    ASK_OVERRIDE = "ask_override"


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
    rewritten_input: dict | None = None  # SANITIZE: the redacted args the caller should run instead
    redactable: bool = False  # a sensitive READ: the caller may run it and screen the OUTPUT (ddbt screen)
                              # instead of denying — the basis of a "redact / show raw / cancel" prompt

    @property
    def overridable(self) -> bool:
        return self.effect is not Effect.DENY   # ASK and ASK_OVERRIDE can be forced; a hard DENY cannot

    # convenience for integrators: `if d.denied: block; elif d.needs_confirmation: confirm; else: run`
    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @property
    def asked(self) -> bool:
        return self.effect is Effect.ASK

    @property
    def denied(self) -> bool:
        return self.effect is Effect.DENY       # a HARD block (deny_mode="block")

    @property
    def danger(self) -> bool:
        return self.effect is Effect.ASK_OVERRIDE   # a would-be block, overridable — warn loudly

    @property
    def needs_confirmation(self) -> bool:
        return self.effect in (Effect.ASK, Effect.ASK_OVERRIDE)

    def to_dict(self) -> dict:
        """The integration contract — a stable, machine-readable decision. `effect` is the key field:
        'allow' | 'ask' | 'deny' | 'ask_override'. On a sanitize-allow, `rewritten_input` holds the
        redacted args to run INSTEAD of the caller's. `reason` leads with a plain-language headline."""
        return {
            "effect": self.effect.value,            # allow | ask | deny | ask_override
            "reason": self.reason,                  # human-readable (plugin headline + detail)
            "layer": self.checkpoint,               # which gate decided: "plugin:net_filter", "judge", "out-of-scope", …
            "overridable": self.overridable,        # can a human force it? (False only for a hard DENY)
            "danger": self.danger,                  # ask_override — a downgraded block; warn loudly
            "needs_confirmation": self.needs_confirmation,
            "risk": self.risk,                      # telemetry band: none | low | med | high
            "rewritten_input": self.rewritten_input,  # sanitize: redacted args to run instead, else null
            "redactable": self.redactable,          # sensitive read: offer redact-output / show-raw / cancel
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


def _is_read(tool: str, tool_input: dict) -> bool:
    """A read-only action: a read tool, or a Bash command that just reads (cat/head/grep/…). Used to
    offer redaction on a sensitive file instead of a hard block — reading locally is not exfil."""
    if tool in _READ_TOOLS:
        return True
    if tool == "Bash" and isinstance(tool_input, dict):
        cmd = str(tool_input.get("command", ""))
        return bool(_READ_CMD.match(cmd)) and not (">" in cmd or "|" in cmd or "curl" in cmd or "scp" in cmd)
    return False


def _summarize(tool: str, tool_input: dict) -> str:
    """A short, structural one-liner for the audit log (not a decision input)."""
    if not isinstance(tool_input, dict):
        return f"{tool}: {str(tool_input)[:80]}"
    if tool == "Bash":
        return f"Bash: {str(tool_input.get('command',''))[:80]}"
    key = tool_input.get("file_path") or tool_input.get("url") or tool_input.get("path") or ""
    return f"{tool}: {key}"[:90]


class Engine:
    def __init__(self, session_id, workspace_root, base_dir=None, step_judge=None, ddbt=True,
                 error_effect="ask", grant=None, gate_offgoal=False, plugins=None, deny_mode="block",
                 traj_gate=0.85, goal_shift="deny", sensitive_read="deny", **_legacy):
        from ddbt.plugins.base import PluginManager
        self.session_id = session_id
        self.workspace_root = workspace_root
        # optional pluggable defenses (shell-deobfuscation, dataflow-taint, destructive-guard, …).
        # Empty by default → pure core behaviour; the hook builds this from ddbt.json "plugins".
        self.plugins = plugins if plugins is not None else PluginManager([])
        # "block" (default) → a DENY is a hard, un-forceable block. "override" → a DENY becomes
        # ASK_OVERRIDE: a human MAY force it through, but with a loud, layer-specific danger warning.
        self.deny_mode = "override" if str(_legacy.get("deny_mode", deny_mode)).lower() == "override" else "block"
        # axis 2 (harm/ethics). Axis 1 (goal-fidelity) is always on; benchmarks isolating axis 1 set
        # False. "ddbd" is accepted as a legacy alias — it's a security flag, so never silently drop it.
        self.ddbt = bool(_legacy.get("ddbd", ddbt))
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
        # SESSION-TRAJECTORY gate: score the whole session-so-far (not just this step) with the judge's
        # trajectory head, and ASK (human confirm) when the accumulated pattern crosses this risk — this
        # catches a slow attack whose individual steps each look fine, which the per-step judge can't see.
        # It's an ASK, not a DENY: a session-level pattern is a "worth a look", not a certainty (the per-
        # step judge still hard-DENYs concrete injection/exfil), so a benign-but-unusual multi-step session
        # isn't silently blocked. Default 0.85 (module TRAJ_GATE); held-out R-Judge F1 64→67, other five
        # benchmarks unchanged. 0 disables. Only fires if the judge exposes trajectory_risk.
        try:
            self.traj_gate = float(_legacy.get("traj_gate", traj_gate))
        except (TypeError, ValueError):
            self.traj_gate = TRAJ_GATE
        # GOAL SHIFT: what to do when an action is off-goal but CLEAN-provenance (the user chose it, not
        # injected content) — i.e. the user moved on to a new task, not an attack. "allow" (shell: follow
        # them, re-anchor the goal), "ask" (confirm the new direction — the deployment default from config),
        # "deny" (strict single-task). The engine default is "deny"; config/Guard(shell=True) set the rest.
        gs = str(_legacy.get("goal_shift", goal_shift)).lower()
        self.goal_shift = gs if gs in ("allow", "ask", "deny") else "deny"
        # SENSITIVE READ: reading a secret FILE (that the ticket would otherwise deny) is not exfil — it
        # can be shown with sensitive values REDACTED. "deny" (default) = hard block; "ask" = offer the
        # choice (redact output / show raw / cancel) via a redactable ASK; "redact" = allow + always screen.
        sr = str(_legacy.get("sensitive_read", sensitive_read)).lower()
        self.sensitive_read = sr if sr in ("deny", "ask", "redact") else "deny"

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

    _TRAJ_CAP = 10_000  # keep the most-recent ~10k chars of the session transcript (bounds encode cost)

    def _traj_append(self, piece: str) -> None:
        """Accumulate the session transcript (turn by turn) in the durable store, capped to the recent
        tail so a long session still scores in bounded time. The goal is prepended at score time."""
        piece = (piece or "").strip()
        if not piece:
            return
        cur = self.store.get_meta("traj_turns", "") or ""
        cur = (cur + "\n" + piece) if cur else piece
        if len(cur) > self._TRAJ_CAP:
            cur = cur[-self._TRAJ_CAP:]
        self.store.set_meta("traj_turns", cur)

    def _traj_text(self) -> str:
        return f"GOAL: {self.goal}\n" + (self.store.get_meta("traj_turns", "") or "")

    def on_user_prompt(self, prompt: str) -> str:
        # the trusted goal anchors every relevance judgment; "continue" keeps the standing goal
        if _is_substantive_goal(prompt):
            self.goal = prompt.strip()
            self.store.set_meta("goal", self.goal)
            self.store.set_meta("traj_turns", "")   # a genuinely new task starts a fresh transcript
            self.store.set_meta("traj_steps", "0")  # …and a fresh step count for the trajectory gate
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

        # PLUGIN normalize — expose hidden intent (e.g. shell deobfuscation) before anything reads it
        if self.plugins:
            tool_input = self.plugins.normalize(tool_name, tool_input)

        # provenance labels — computed once, reused for the chromatic "who" and the judge facts
        labels = self._labels(tool_input)
        who = _who(labels)

        # HARD FLOOR: the capability ticket, checked deterministically before the judge — policy +
        # arithmetic, not an LLM reading text, so injection can't talk past it. Also the fast path:
        # an in-scope read is allowed here with no model call.
        gcheck = None
        if self.grant is not None:
            gcheck = self.grant.check(tool_name, tool_input, now=time.time(), used=self._grant_used())
            if gcheck.effect == "deny" and self.sensitive_read != "deny" and _is_read(tool_name, tool_input):
                # a READ of a restricted (secret) file is not exfil — offer to show it with sensitive
                # values REDACTED instead of hard-denying. "redact" → allow + always screen the output;
                # "ask" → a redactable ASK the caller renders as "redact output / show raw / cancel".
                redact = self.sensitive_read == "redact"
                eff = Effect.ALLOW if redact else Effect.ASK
                reason = ("reads a file with sensitive values — the output will be redacted" if redact
                          else "reads a file with sensitive values — redact the output, show it raw, or cancel")
                aid = self.audit.decision(checkpoint="sensitive-read", state=eff.value, tool=tool_name,
                                          summary=_summarize(tool_name, tool_input), reason=reason)
                return Decision(eff, eff.value, "sensitive-read", reason, redactable=True,
                                risk=chromatics.classify(eff.value, "grant-fastpath", True, False, False, who),
                                audit_id=aid)
            if gcheck.effect == "deny":
                # a floor breach means the session is being probed — ratchet suspicion (atomic).
                self.store.increment_meta("suspicion", 3)
                effect, reason = self._as_deny(gcheck.reason, "capability ticket (out-of-scope)")
                aid = self.audit.decision(checkpoint="out-of-scope", state=effect.value, tool=tool_name,
                                          summary=_summarize(tool_name, tool_input), reason=reason,
                                          suspicion=self._suspicion())
                return Decision(effect, effect.value, "out-of-scope", reason,
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

        # PLUGIN pre_check — deterministic hard rules that run BEFORE the judge (destructive commands,
        # dataflow exfil chains, PII egress). A plugin only tightens: DENY short-circuits; ASK is a floor.
        plugin_floor = None
        if self.plugins:
            from ddbt.plugins.base import PluginContext, finding_message, finding_tag
            pctx = PluginContext(session_id=self.session_id, goal=self.goal, provenance=who, store=self.store)
            pv = self.plugins.pre_check(tool_name, tool_input, pctx)
            if pv is not None and pv.effect == "deny":
                self.store.increment_meta("suspicion", 3)
                # "<detectors> · <Tactic>: We think this operation <finding>." — detector classification +
                # MITRE tactic (no codes), marking EVERY detector that flagged (pv.flagged).
                base = (finding_message(finding_tag(pv.plugin, pv.tactic, pv.flagged), pv.reason)
                        + (f" — try: {pv.suggestion}" if pv.suggestion else ""))
                effect, reason = self._as_deny(base, f"plugin:{pv.plugin}")
                aid = self.audit.decision(checkpoint=f"plugin:{pv.plugin}", state=effect.value, tool=tool_name,
                                          summary=_summarize(tool_name, tool_input), reason=reason,
                                          suspicion=self._suspicion())
                return Decision(effect, effect.value, f"plugin:{pv.plugin}", reason, relevant=False, stray=False,
                                risk=chromatics.classify("deny", "out-of-scope", False, False, False, who),
                                audit_id=aid)
            if pv is not None and pv.effect == "sanitize" and isinstance(pv.rewrite, dict):
                # redact-and-send: the payload is cleaned, the destination was already in scope → allow
                # the action with the redacted args (the caller runs Decision.rewritten_input).
                reason = ((pv.headline + " ") if pv.headline else "") + pv.reason
                aid = self.audit.decision(checkpoint=f"plugin:{pv.plugin}", state="allow", tool=tool_name,
                                          summary=_summarize(tool_name, pv.rewrite), reason=reason)
                return Decision(Effect.ALLOW, "allow", f"plugin:{pv.plugin}", reason,
                                risk=chromatics.classify("allow", "grant-fastpath", True, False, False, who),
                                audit_id=aid, rewritten_input=pv.rewrite)
            if pv is not None and pv.effect == "ask":
                plugin_floor = pv

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
        effect, checkpoint = self._combine(verdict, strictness, who, message=tool_name in _MESSAGE_TOOLS)
        # a plugin ASK-floor escalates an otherwise-ALLOW step to a human check
        if plugin_floor is not None and effect is Effect.ALLOW:
            effect, checkpoint = Effect.ASK, f"plugin:{plugin_floor.plugin}"
            # the plugin is the REASON for the ASK — show its detector alias(es) + MITRE tactic + concern,
            # NOT the judge's separate content verdict ("clean · risk=0.10") which would read contradictory.
            from ddbt.plugins.base import finding_message, finding_tag
            tag = finding_tag(plugin_floor.plugin, plugin_floor.tactic, plugin_floor.flagged)
            verdict.reason = finding_message(tag, plugin_floor.reason)
        reason = verdict.reason
        # GOAL-SHIFT RE-ANCHOR: when we follow the user to a new direction (goal_shift="allow", e.g. a
        # shell), adopt it as the working goal so the FOLLOW-UP steps read as on-goal instead of each
        # re-triggering a shift. Safe: this path is reached only for CLEAN provenance (injected content
        # was denied above), so an injection can never re-anchor the goal.
        if checkpoint == "goal-shift" and effect is Effect.ALLOW:
            new_goal = _summarize(tool_name, tool_input)[:200]
            if new_goal:
                self.goal = new_goal
                self.store.set_meta("goal", self.goal)
            reason = verdict.reason or "is a new direction you started (not from injected content)"
        elif checkpoint == "goal-shift":  # ASK on the shift — name it so the human sees a new direction
            reason = "is a new task you started (not from injected content)"
        # deny_mode="override" → a judge/combine DENY becomes an overridable, loudly-warned ASK_OVERRIDE
        if effect is Effect.DENY:
            effect, reason = self._as_deny(verdict.reason, checkpoint)

        # SESSION-TRAJECTORY gate: append this step to the running transcript and score the WHOLE
        # session so far. The per-step judge sees one action; this sees the pattern the steps form
        # together — a slow attack (read → encode → drip out) whose every step looks fine. It only
        # tightens (ALLOW/ASK → DENY), never on a message-to-user (speaking is never the exfil), and
        # only when the judge exposes a trajectory head. Held-out R-Judge: F1 0.64→0.75, spec 0.49→0.84.
        action_txt = (tool_input.get("action") if isinstance(tool_input, dict) and tool_input.get("action")
                      else _summarize(tool_name, tool_input))
        self._traj_append(f"AGENT:\n  ACTION: {action_txt}")
        steps = self.store.increment_meta("traj_steps", 1)
        # Fire ONLY on a genuine MULTI-STEP session. A single action is not a "trajectory" — that's the
        # per-step judge's job, and scoring one prose action against a session threshold just re-flags
        # benign prose (the head over-scores prose ~0.9). Requiring several accumulated steps confines
        # this to what it's for: a slow attack spread across turns. (Below the floor: no change, so the
        # single-action benchmarks are untouched; above it, R-Judge-style trajectories get the session view.)
        if (self.traj_gate and steps >= _TRAJ_MIN_STEPS and tool_name not in _MESSAGE_TOOLS
                and effect is Effect.ALLOW):
            traj_fn = getattr(self.step_judge, "trajectory_risk", None)
            traj_r = traj_fn(self._traj_text()) if traj_fn else None
            if traj_r is not None and traj_r >= self.traj_gate:
                effect, checkpoint = Effect.ASK, "session-trajectory"
                reason = "is part of a sequence of steps that together look unsafe"

        if not verdict.error:
            # this step's evidence tightens FUTURE steps; a downgraded block still counts as "blocked"
            self._bump_suspicion(verdict, blocked=effect in (Effect.DENY, Effect.ASK_OVERRIDE))

        # a call going ahead spends one unit of grant quota (atomic). ASK / ASK_OVERRIDE may proceed too
        # — debit at decision time so a spent ticket denies the next step.
        if gcheck is not None and gcheck.quota_key and effect in (Effect.ALLOW, Effect.ASK, Effect.ASK_OVERRIDE):
            self.store.increment_meta(f"grant_used:{gcheck.quota_key}", 1)

        chroma = "deny" if effect is Effect.ASK_OVERRIDE else effect.value   # alarming colour for a downgraded block
        aid = self.audit.decision(
            checkpoint=checkpoint,
            state=effect.value,
            tool=tool_name,
            summary=_summarize(tool_name, tool_input),
            reason=reason,
            error=verdict.error,
            strictness=strictness,
            suspicion=self._suspicion(),
            **verdict.signals(),  # the full diagnostic checklist (data-gathering)
        )
        return Decision(
            effect, effect.value, checkpoint, reason,
            relevant=verdict.serves_goal, harmful=verdict.harmful, stray=verdict.deviation,
            error=verdict.error,
            risk=chromatics.classify(chroma, checkpoint, verdict.serves_goal,
                                     verdict.harmful, verdict.deviation, who),
            audit_id=aid,
        )

    def _as_deny(self, reason: str, layer: str) -> tuple[Effect, str]:
        """Turn a would-be DENY into the configured outcome. deny_mode='block' (default) → a hard DENY;
        deny_mode='override' → ASK_OVERRIDE carrying a loud, layer-specific danger warning a human may
        force through. The warning names WHICH layer wanted to block and WHY, so the override is informed."""
        if self.deny_mode == "override":
            return Effect.ASK_OVERRIDE, (
                f"⚠ DANGER — ddbt would BLOCK this ({layer}). This session/query may be malicious; "
                f"proceed ONLY if you are certain it's you. Suspected: {reason}")
        return Effect.DENY, reason

    def _combine(self, verdict, strictness: int = 0, who: str = "you", message: bool = False) -> tuple[Effect, str]:
        """Checklist → decision. Axis 1 (deviation) hard-denies injection-linked steps; axis 2
        (harm) denies when ddbt is on; then adaptive strictness tightens a suspicious session."""
        if verdict.error:
            # infra failure (429, timeout, dead key) is not a security finding — ask a human,
            # don't hard-deny (that would brick a tool call in your editor). Benchmarks set "deny".
            return self.error_effect, "judge-error"
        if message:
            # A message to the operator has no external side-effect — the human reads it by
            # construction — so it is never a silent hard-DENY (blocking the agent from *speaking*
            # to its user is the wrong call; quoting/surfacing injected content is transparency, not
            # a consequential deviation). But a message the judge finds genuinely harmful still ASKs
            # a human — the feedback path stays intact — and a real leaked secret is caught upstream
            # by the deterministic PII/provenance plugin floor regardless.
            if self.ddbt and verdict.harmful:
                return Effect.ASK, "message-review"
            return Effect.ALLOW, "message"
        if verdict.deviation:
            # Off-goal + injection-linked (stranger/unknown provenance, suspected injection, or exfil)
            # is a hard DENY — a real attack. But off-goal with CLEAN provenance is the USER doing
            # something new: a GOAL SHIFT, not an attack. Denying that suspects everyday work (esp. in
            # a shell). So injection deviations hard-DENY; clean deviations follow the goal_shift lever.
            injection_linked = (verdict.injection_suspected or verdict.external_exfil
                                or who in ("stranger", "unknown"))
            # A goal shift that is ALSO harmful (exfil/destroy/high-impact off-goal) is not "just a new
            # task" — the harm axis still denies it regardless of provenance. Only a CLEAN, non-harmful
            # off-goal action is a benign goal shift the user may follow.
            if injection_linked or (self.ddbt and verdict.harmful):
                return Effect.DENY, "goal-fidelity"  # axis 1 — real injection / harmful deviation
            if self.goal_shift == "allow":
                return Effect.ALLOW, "goal-shift"    # follow the user (re-anchor happens in evaluate_action)
            if self.goal_shift == "ask" or self.gate_offgoal:
                return Effect.ASK, "goal-shift"      # confirm the new direction (a light human check)
            return Effect.DENY, "goal-fidelity"      # strict single-task mode
        if self.ddbt and verdict.harmful:
            return Effect.DENY, "ethics"  # axis 2 — only when ddbt enabled
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
        # PLUGIN observe — let dataflow/provenance taint mark a secret read for the cross-call check
        if self.plugins:
            from ddbt.plugins.base import PluginContext
            self.plugins.observe(tool_name, tool_input, payload,
                                 PluginContext(session_id=self.session_id, goal=self.goal, store=self.store))
        # TRAJECTORY LEDGER — record the confirmed step so cross-step detectors can score the history.
        # Always-on core infra (like the audit/quarantine/provenance index); best-effort.
        try:
            from ddbt.core.ledger import Ledger
            Ledger(self.store).record(tool_name, tool_input, payload)
        except Exception:  # noqa: BLE001 — telemetry must never break a tool call
            pass
        # feed the result into the session-trajectory transcript (the ENVIRONMENT turn) so the
        # trajectory gate on the NEXT step sees what came back — where an injection actually arrives.
        try:
            self._traj_append(f"ENVIRONMENT: {str(payload)[:2000]}")
        except Exception:  # noqa: BLE001 — never break a tool call over transcript bookkeeping
            pass
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
