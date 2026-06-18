"""The enforcement engine — agent-agnostic pipeline orchestrator (doc §1).

One engine, called by every adapter (Claude Code hooks, AgentDojo, MCP). It wires the
deterministic pipeline together and is the single place the security logic lives:

    on_session_start → seed/load envelope
    on_user_prompt   → ingest PRISTINE user grants (the only trusted widening)
    evaluate_action  → classify → Checkpoint 2 → irreversibility → staging lane → Decision
    record_result    → content inspector labels the output into provenance
    commit_batch     → Checkpoint 3 over the staged batch → release / hold

Hook-layer reality (documented honestly): a PreToolUse hook can only *allow / deny /
ask* on a built-in tool — it cannot redirect a live Write into an overlay. So where
the doc's overlay would "proceed into staging with no interruption", the hook layer
escalates to a human instead. The staging queue is fully real for action-tool sends
and for the commit-time review; redirecting built-in FS writes needs the OS substrate
(doc §9, v-next).
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass

from ddbt.core import bootstrap, checkpoint2, checkpoint3, envelope as envelope_mod, irreversibility
from ddbt.core.audit import AuditLogger
from ddbt.core.checkpoint2 import State
from ddbt.core.provenance import ProvenanceTracker
from ddbt.core.staging import Lane, StagingManager, route
from ddbt.core.trajectory import TrajectoryMonitor
from ddbt.policy.classifier import classify
from ddbt.policy.defaults import Policy, default_policy
from ddbt.store.session import SessionStore


class Effect(enum.Enum):
    """What the adapter enforces. Maps to Claude Code permissionDecision."""

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


@dataclass(slots=True)
class Decision:
    effect: Effect
    state: State
    checkpoint: str
    reason: str
    lane: str | None = None
    staged: bool = False
    audit_id: int = 0

    @property
    def overridable(self) -> bool:
        """A DENY from Checkpoint 2 is non-overridable (out-of-envelope + dangerous)."""
        return self.effect != Effect.DENY

    def to_dict(self) -> dict:
        return {
            "effect": self.effect.value,
            "state": self.state.name,
            "checkpoint": self.checkpoint,
            "reason": self.reason,
            "lane": self.lane,
            "staged": self.staged,
        }


@dataclass(slots=True)
class CommitResult:
    ok: bool
    released: int
    held: list[tuple[str, str]]  # (summary, reason)

    def summary(self) -> str:
        if self.ok:
            return f"commit accepted — released {self.released} staged op(s)"
        held = "; ".join(f"{s} ({r})" for s, r in self.held)
        return f"commit HELD — {len(self.held)} op(s) blocked: {held}"


_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)
_PATH_RE = re.compile(r"(?:^|\s)((?:~|/)[^\s'\"]+)")


_CONTINUATION = {"continue", "keep going", "go on", "next", "proceed", "yes", "do it", "go ahead", "resume"}


def _is_substantive_goal(prompt: str) -> bool:
    """A prompt carries a goal worth judging against only if it's more than a
    continuation cue and has some content (doc §3.4: goal-less prompts → no judging)."""
    p = prompt.strip().lower().rstrip(".!")
    if p in _CONTINUATION:
        return False
    return len(re.findall(r"[a-z0-9]{3,}", p)) >= 3


def _severity(effect: "Effect") -> int:
    return {Effect.ALLOW: 0, Effect.ASK: 1, Effect.DENY: 2}[effect]


def _signature(action) -> str:
    """Stable structural signature of an action (tool + op + sorted targets).

    Deliberately narrow: confirmation authorises THIS exact op on THESE exact targets,
    not a whole tool or a broad pattern.
    """
    targets = sorted(f"{t.kind}:{t.value}" for t in action.targets)
    return f"{action.tool_name}|{action.op}|{'|'.join(targets)}"


class Engine:
    def __init__(
        self,
        session_id: str,
        workspace_root: str,
        policy: Policy | None = None,
        base_dir=None,
        judge: checkpoint3.DiffJudge | None = None,
        classifier=classify,
        intent_judge=None,
    ):
        self.session_id = session_id
        self.workspace_root = workspace_root
        self.policy = policy or default_policy()
        # optional blind relevance judge (doc §3.4/§5.2). Consulted ONLY on the judgeable
        # middle tier, with structural facts + the trusted goal — never untrusted content.
        self.intent_judge = intent_judge
        # the classifier maps an agent's (tool_name, tool_input) → StructuralAction.
        # Pluggable so a non-Claude-Code agent (e.g. AgentDojo's domain tools) can supply
        # its own mapping while the deciding pipeline stays identical — the "any agent" point.
        self.classify = classifier
        self.store = SessionStore(session_id, base_dir=base_dir)
        self.tracker = ProvenanceTracker(self.store, self.policy)
        self.audit = AuditLogger(self.store)
        self.staging = StagingManager(self.store)
        self.trajectory = TrajectoryMonitor(self.store, self.policy)
        self.judge = judge
        self.envelope = envelope_mod.load_or_seed(self.store, workspace_root, self.policy)
        self.goal = self.store.get_meta("goal", "") or ""  # standing goal for the intent judge

    # ---- lifecycle ----

    def on_session_start(self, source: str, cwd: str, named_grants: list[str] | None = None) -> bootstrap.BootstrapResult:
        if source not in ("resume",):
            self.envelope = envelope_mod.seed_envelope(cwd or self.workspace_root, self.policy)
        for g in named_grants or []:
            self._grant(g)
        envelope_mod.save(self.store, self.envelope)
        result = bootstrap.verify(cwd or self.workspace_root)
        self.audit.event("bootstrap", status=result.status, detail=result.summary())
        return result

    def verify_config(self, cwd: str | None = None) -> bootstrap.BootstrapResult:
        """Re-run Boundary 0 (config + MCP integrity). Wired to the ConfigChange /
        FileChanged hooks so a mid-session config tamper (hook injection, base-URL
        redirect) is caught the moment it lands, not only at startup (doc §2)."""
        result = bootstrap.verify(cwd or self.workspace_root)
        self.audit.event("bootstrap", status=result.status, detail=result.summary())
        return result

    def on_user_prompt(self, prompt: str) -> str:
        """Ingest pristine user grants from the (trusted) prompt and return context to inject.

        The user prompt is origin=USER (pristine, trusted) — extracting named domains/paths
        from it is a legitimate, deliberate widening (doc §3.2), never an untrusted vector.
        """
        # capture the goal for the intent judge — but only from a SUBSTANTIVE prompt.
        # "continue"/"keep going" carry no goal, so we keep the standing one (doc §3.4).
        if _is_substantive_goal(prompt):
            self.goal = prompt.strip()
            self.store.set_meta("goal", self.goal)

        granted: list[str] = []
        for m in _DOMAIN_RE.finditer(prompt):
            self.envelope.grant_domain(m.group(1))
            granted.append(m.group(1))
        for m in _PATH_RE.finditer(prompt):
            self._grant(m.group(1))
            granted.append(m.group(1))
        if granted:
            self.audit.event("user_grant", granted=granted)
            envelope_mod.save(self.store, self.envelope)

        denials = [e for e in self.audit.trail() if e.get("kind") == "decision" and e.get("state") == "DENY"]
        if denials:
            last = denials[-1]
            return f"[ddbt] note: a prior action was blocked ({last.get('reason')}). Stay within the task's scope."
        return ""

    def _grant(self, raw: str) -> None:
        if "/" in raw or raw.startswith("~"):
            # doc §5.3: a path merely *named* in a prompt widens normal scope, but it can
            # NEVER open the hard-deny (sensitive) tier — granting a secret requires a
            # deliberate out-of-band confirmation, not a prose mention. Safe-direction.
            if self.policy.is_sensitive_path(raw):
                self.audit.event("grant_withheld", path=raw, reason="sensitive path needs explicit confirmation")
                return
            self.envelope.grant_write(str(self.policy.resolve(raw, self.workspace_root)))
        else:
            self.envelope.grant_domain(raw)

    # ---- per-action ----

    def _decide(self, action, cwd: str):
        """Full per-action decision, shared by evaluate_action and confirm_from_result.

        Order: deterministic pipeline → prior-confirmation downgrade → blind intent judge
        (only on the judgeable middle tier). Returns (effect, checkpoint, reason, c2, lane).
        """
        c2 = checkpoint2.evaluate(action, self.envelope, self.tracker, self.policy, cwd)
        verdict = irreversibility.check(action, self.envelope, self.policy)
        lane = route(action, self.envelope, self.policy, cwd)
        effect, checkpoint = self._map(c2.state, verdict, lane)
        reason = c2.reason
        if checkpoint == "irreversibility":
            reason = verdict.reason if verdict.triggered else "irreversible op requires confirmation"

        # 1) prior human confirmation (doc §3.2): identical gated action already approved
        if effect == Effect.ASK and self.store.is_confirmed(_signature(action)):
            return Effect.ALLOW, "confirmed", "previously confirmed by the user (gate approval)", c2, lane

        # 2) blind intent judge — ONLY on the judgeable middle tier, never the hard tier,
        #    and only when we have a goal to judge against (doc §3.4/§5.2).
        if self.intent_judge and c2.judgeable and self.goal and effect in (Effect.DENY, Effect.ASK):
            v = self._consult_intent(action, c2)
            if not v.relevant:
                return Effect.DENY, "intent:off-task", v.reason, c2, lane
            if c2.stakes == "high":  # on-task but risky → stakes decide we still ask a human
                effect, checkpoint, reason = Effect.ASK, "intent:gate", f"on-task but high-stakes: {v.reason}"
            else:  # on-task + low stakes
                effect, checkpoint, reason = Effect.ALLOW, "intent:on-task", v.reason

        # cumulative-trajectory check: can only RAISE friction (ALLOW→ASK), never lower it,
        # so a heuristic false-positive asks a human and never authorises (doc §1 lookahead).
        traj = self.trajectory.assess(action)
        if traj is not None:
            t_effect = Effect.DENY if traj[0] == State.DENY else Effect.ASK
            if _severity(t_effect) > _severity(effect):
                effect, checkpoint, reason = t_effect, "trajectory", traj[1]

        return effect, checkpoint, reason, c2, lane

    def _consult_intent(self, action, c2):
        from ddbt.judge.base import IntentFacts

        facts = IntentFacts(
            goal=self.goal,
            tool=action.tool_name,
            op=action.op,
            targets=[t.value for t in action.targets],
            stakes=c2.stakes,
        )
        v = self.intent_judge.judge(facts)
        self.audit.event("intent_judge", relevant=v.relevant, reason=v.reason, summary=action.summary)
        return v

    def evaluate_action(self, tool_name: str, tool_input: dict, cwd: str | None = None) -> Decision:
        action = self.classify(tool_name, tool_input or {}, self.policy)
        cwd = cwd or self.workspace_root
        effect, checkpoint, reason, c2, lane = self._decide(action, cwd)

        staged = False
        if lane == Lane.STAGED and effect == Effect.ALLOW:
            self.staging.stage(action, tool_input or {}, lane)
            staged = True

        audit_id = self.audit.decision(
            checkpoint=checkpoint,
            state=c2.state.name,
            tool=action.tool_name,
            summary=action.summary,
            reason=reason,
            lane=lane.value,
        )
        return Decision(effect, c2.state, checkpoint, reason, lane.value, staged, audit_id)

    @staticmethod
    def _map(state: State, verdict: irreversibility.IrreversibilityVerdict, lane: Lane) -> tuple[Effect, str]:
        if state == State.DENY:
            return Effect.DENY, "checkpoint2"  # out-of-envelope + dangerous, non-overridable
        if state == State.ESCALATE:
            effect, cp = Effect.ASK, "checkpoint2"
        elif state == State.AMBIGUOUS:
            # reversible (in-scope, git-tracked) → proceed; else can't stage at hook → ask
            effect, cp = (Effect.ALLOW, "checkpoint2") if lane == Lane.PASS_THROUGH else (Effect.ASK, "checkpoint2")
        else:
            effect, cp = Effect.ALLOW, "checkpoint2"

        # irreversibility gate only ever raises friction, never lowers it
        if lane == Lane.GATE_ONLY and effect == Effect.ALLOW:
            return Effect.ASK, "irreversibility"
        if verdict.triggered and not verdict.preauthorized and effect == Effect.ALLOW:
            return Effect.ASK, "irreversibility"
        return effect, cp

    def record_result(self, tool_name: str, tool_input: dict, tool_response: dict, cwd: str | None = None) -> None:
        action = self.classify(tool_name, tool_input or {}, self.policy)
        label = self.tracker.label_result(action, tool_response or {})
        self.trajectory.record(action)  # accumulate cumulative-trajectory counters
        if label.is_tainted:
            self.audit.event("labeled", tool=action.tool_name, summary=action.summary, label=label.describe())

    def confirm_from_result(self, tool_name: str, tool_input: dict, cwd: str | None = None) -> bool:
        """Called at PostToolUse: if a gated (ASK) action nonetheless RAN, a human approved
        it — a denied action never reaches PostToolUse. Record that confirmation so the
        identical action stops re-asking, and widen the envelope to cover its targets.

        This is the ONLY runtime growth path beyond pristine user grants, and it is
        confirmation-gated by construction: hard-denies never run → never widen; sensitive
        sources are DENY (not ASK) → never confirmable here either.
        """
        action = self.classify(tool_name, tool_input or {}, self.policy)
        cwd = cwd or self.workspace_root
        effect, _checkpoint, _reason, _c2, _lane = self._decide(action, cwd)
        if effect != Effect.ASK:
            return False  # was ALLOW (nothing to confirm) or DENY (must never widen)

        self.store.add_confirmed(_signature(action))
        widened = self._widen_for(action, cwd)
        envelope_mod.save(self.store, self.envelope)
        self.audit.event(
            "confirmed_grant", tool=action.tool_name, summary=action.summary, widened=widened
        )
        return True

    def _widen_for(self, action, cwd: str) -> list[str]:
        """Grant the action's targets into the envelope. Never grants a sensitive path
        (those are DENY, not ASK, so they can't reach here — but we double-guard)."""
        widened: list[str] = []
        for t in action.targets:
            if t.kind == "domain":
                self.envelope.grant_domain(t.value)
                widened.append(f"domain:{t.value}")
            elif t.kind == "path" and not self.policy.is_sensitive_path(t.value):
                resolved = str(self.policy.resolve(t.value, cwd))
                if action.op in ("write", "delete"):
                    self.envelope.grant_write(resolved)
                else:
                    self.envelope.grant_read(resolved)
                widened.append(f"path:{resolved}")
        return widened

    # ---- commit ----

    def commit_batch(self) -> CommitResult:
        pending = self.staging.pending()
        if not pending:
            return CommitResult(ok=True, released=0, held=[])
        rev = checkpoint3.review(pending, self.envelope, self.policy, self.judge)
        for it in rev.release:
            self.store.set_staged_status(it.id, "released")
            self.audit.event("released", id=it.id, item_kind=it.kind)
        for it, reason in rev.hold:
            self.store.set_staged_status(it.id, "dropped")
            self.audit.event("dropped", id=it.id, item_kind=it.kind, reason=reason)
        return CommitResult(
            ok=rev.ok,
            released=len(rev.release),
            held=[(it.action.get("summary", "?"), reason) for it, reason in rev.hold],
        )

    # ---- misc ----

    def audit_trail(self) -> str:
        return self.audit.render()

    def close(self) -> None:
        self.store.close()
