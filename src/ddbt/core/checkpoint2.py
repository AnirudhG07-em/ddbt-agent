"""Checkpoint 2 — structural conformance, the blind policy judge (doc §5).

Asks one content-blind question: does the *structural* action sit inside the scope
envelope? The judge reads only typed facts — tool class, op, target path/domain, and
the provenance *labels* of what's referenced — never the untrusted argument values.
Injected wording never reaches it (doc §5.4), so cleverness in phrasing buys nothing;
only structural drift is visible.

Four states (doc §5.2), with the override line drawn by **relevance, not stakes**:

  ALLOW      in-envelope, safe, clean — everyday work, zero friction
  AMBIGUOUS  on the boundary; if reversible → proceed into staging w/ a flag,
             else escalate (the only place a residual LLM call could live)
  ESCALATE   in-envelope but high-stakes — a human MAY approve (relevant)
  DENY       outside the envelope AND dangerous — NOBODY may override

The asymmetry: relevant-but-risky → human may approve; irrelevant-and-dangerous →
refused outright, justified by being out-of-bounds, never by suspicion of the user.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ddbt.core.envelope import Envelope
from ddbt.core.provenance import ProvenanceTracker
from ddbt.policy.classifier import StructuralAction, ToolClass
from ddbt.policy.defaults import Policy


class State(enum.IntEnum):
    """Ordered by severity so ``max`` picks the most restrictive across concerns."""

    ALLOW = 0
    AMBIGUOUS = 1
    ESCALATE = 2
    DENY = 3


@dataclass(slots=True)
class Concern:
    state: State
    reason: str
    # judgeable: a block/escalation whose RELEVANCE to the goal an intent judge may
    # refine (out-of-scope read, outbound to a novel domain). NON-judgeable concerns are
    # dangerous-regardless (sensitive source, toxic flow, out-of-envelope destruction) —
    # the hard tier the intent judge must never rescue.
    judgeable: bool = False
    stakes: str = "low"  # "low" (reads/fetch) | "high" (outbound/irreversible)


@dataclass(slots=True)
class Checkpoint2Result:
    state: State
    reasons: list[str] = field(default_factory=list)
    facts: dict = field(default_factory=dict)  # structural facts, for the audit log
    judgeable: bool = False
    stakes: str = "low"

    @property
    def reason(self) -> str:
        return "; ".join(self.reasons) or "in-envelope, clean"


def evaluate(
    action: StructuralAction,
    env: Envelope,
    tracker: ProvenanceTracker,
    policy: Policy,
    cwd: str | None = None,
) -> Checkpoint2Result:
    """Run the content-blind conformance check, returning the worst-case state."""
    # Pure tools never touch the system — chat/bookkeeping flows free (doc §3.2).
    if action.tool_class == ToolClass.PURE:
        return Checkpoint2Result(State.ALLOW, ["pure tool, no system effect"], {"tool_class": "pure"})

    concerns: list[Concern] = []
    facts: dict = {"tool": action.tool_name, "op": action.op, "class": action.tool_class.value}

    # --- universal sensitive-source guard (doc §3.1, §5.2) ---
    # ANY action that references a sensitive path — whether via the Read tool, a bash
    # `cat`/`cp`, a write, or a delete — is touching a secret. It is hard-denied unless
    # that exact resource was explicitly granted. This runs before the op-specific
    # checks so the tool used to reach the secret is irrelevant (closes the bash gap).
    sensitive_paths: set[str] = set()
    for raw in action.paths:
        if policy.is_sensitive_path(raw):
            sensitive_paths.add(raw)
            if not env.explicitly_grants(str(policy.resolve(raw, cwd))):
                # hard tier: a secret is dangerous regardless of any "relevance" — the
                # intent judge can NEVER rescue this (judgeable=False).
                concerns.append(Concern(State.DENY, f"sensitive source outside envelope: {raw}", judgeable=False))

    # --- reads (non-sensitive; sensitive handled by the guard above) ---
    # "exec" covers bash commands (cat/cp/head/...) whose path args read out-of-tree
    # files into the agent's context — the same boundary applies regardless of tool.
    if action.op in ("read", "fetch", "exec") and action.tool_class != ToolClass.UNTRUSTED_RETRIEVAL:
        for raw in action.paths:
            if raw not in sensitive_paths:
                concerns.append(_read_concern(raw, env, tracker, policy, cwd))

    # Untrusted retrieval (web/email/issue): the *ingest* is allowed (it lands tainted);
    # the danger is downstream when tainted data flows to a sink, caught on those actions.
    if action.tool_class == ToolClass.UNTRUSTED_RETRIEVAL:
        concerns.append(Concern(State.ALLOW, "untrusted retrieval (result will be tainted)"))

    # --- writes ---
    if action.op == "write":
        for raw in action.paths:
            if raw not in sensitive_paths:
                concerns.append(_write_concern(raw, env, policy, cwd, action))

    # --- deletes / destructive bash with path targets ---
    if action.op == "delete" or (action.dangerous_ops & {"delete", "truncate", "overwrite"}):
        for raw in action.paths:
            if raw not in sensitive_paths:
                concerns.append(_destructive_concern(raw, env, policy, cwd))
        if not action.paths:
            concerns.append(Concern(State.ESCALATE, "destructive op with no resolvable target"))

    # --- outbound / sinks ---
    if action.is_outbound:
        concerns.append(_outbound_concern(action, env, tracker))

    # --- bare exec / unknown action with no extractable target ---
    if not concerns:
        if action.tool_class == ToolClass.ACTION and action.tool_name not in ("Write", "Edit"):
            # e.g. `npm test`, `ls` — in-envelope tooling with no risky target
            concerns.append(Concern(State.ALLOW, "in-envelope tooling, no risky target"))
        else:
            concerns.append(Concern(State.ALLOW, "no structural concern"))

    worst = max(concerns, key=lambda c: c.state)
    reasons = [c.reason for c in concerns if c.state == worst.state]
    facts["concerns"] = [(c.state.name, c.reason) for c in concerns]
    # the decision is judgeable only if the WORST concern is — a single hard concern
    # (sensitive read) makes the whole action non-judgeable, even if others are softer.
    worst_concerns = [c for c in concerns if c.state == worst.state]
    judgeable = all(c.judgeable for c in worst_concerns) and worst.state != State.ALLOW
    stakes = "high" if any(c.stakes == "high" for c in worst_concerns) else "low"
    return Checkpoint2Result(worst.state, reasons, facts, judgeable=judgeable, stakes=stakes)


# ---- per-concern judges (each content-blind) ----


def _read_concern(
    raw: str, env: Envelope, tracker: ProvenanceTracker, policy: Policy, cwd: str | None
) -> Concern:
    resolved = str(policy.resolve(raw, cwd))
    label = tracker.resource_label(raw)
    # sensitive sources require an EXPLICIT exact grant — an ancestor-dir grant never
    # authorises a secret (doc §3.1 / §5.3). Non-sensitive reads use ordinary scope.
    granted = env.explicitly_grants(resolved) if label.sensitive else env.contains_read(resolved)
    if label.sensitive and not granted:
        # sensitive source → hard tier (never judgeable)
        return Concern(State.DENY, f"sensitive source outside envelope: {raw}", judgeable=False)
    if granted:
        return Concern(State.ALLOW, f"in-envelope read: {raw}")
    if policy.is_benign_read_path(raw):
        return Concern(State.ALLOW, f"benign system path: {raw}")
    # out-of-scope, non-sensitive read → RELEVANCE is the open question → judgeable, low stakes
    state = State.ESCALATE if policy.escalate_out_of_scope_reads else State.AMBIGUOUS
    return Concern(state, f"read outside envelope: {raw}", judgeable=True, stakes="low")


def _write_concern(
    raw: str, env: Envelope, policy: Policy, cwd: str | None, action: StructuralAction
) -> Concern:
    resolved = str(policy.resolve(raw, cwd))
    if policy.is_sensitive_path(raw) and not env.explicitly_grants(resolved):
        return Concern(State.DENY, f"write to sensitive path outside envelope: {raw}", judgeable=False)
    if env.contains_write(resolved):
        return Concern(State.ALLOW, f"in-envelope write: {raw}")
    # out-of-scope write → judgeable (could be on-task), high stakes (mutates outside root)
    return Concern(State.AMBIGUOUS, f"write outside envelope: {raw}", judgeable=True, stakes="high")


def _destructive_concern(raw: str, env: Envelope, policy: Policy, cwd: str | None) -> Concern:
    resolved = str(policy.resolve(raw, cwd))
    if env.contains_write(resolved):
        # in-envelope destructive op → relevant but irreversible → judgeable, high stakes
        return Concern(State.ESCALATE, f"destructive op on in-envelope path: {raw}", judgeable=True, stakes="high")
    # destructive op OUTSIDE the envelope (rm -rf ~) → dangerous regardless → HARD tier
    return Concern(State.DENY, f"destructive op outside envelope: {raw}", judgeable=False)


def _flow_label(action: StructuralAction, tracker: ProvenanceTracker):
    """The IFC label of the data this action would emit (doc §4): worst-label-wins join of
    every referenced resource's PROPAGATED label and the session watermark. The decider
    reasons over this label, never the bytes — so it catches *laundered* taint (untrusted
    web content written to a file, then sent out) that path/pattern matching alone misses."""
    from ddbt.core.labels import join_all

    labels = [tracker.resource_label(p) for p in action.paths]
    labels.append(tracker.watermark())
    return join_all(labels)


def _outbound_concern(action: StructuralAction, env: Envelope, tracker: ProvenanceTracker) -> Concern:
    flow = _flow_label(action, tracker)
    # confidential data leaving → HARD toxic-flow tier, never judged (even to a granted dest)
    if flow.sensitive:
        return Concern(State.DENY, "outbound carries confidential (sensitive) data — toxic flow", judgeable=False)
    domains = action.domains
    if not domains:
        return Concern(State.ESCALATE, "outbound with no resolvable destination", judgeable=False, stakes="high")
    out_domains = [d for d in domains if not env.allows_domain(d)]
    if out_domains:
        # outbound to a novel domain → RELEVANCE is the question → judgeable, high stakes
        return Concern(
            State.DENY, f"outbound to non-envelope domain(s): {', '.join(out_domains)}", judgeable=True, stakes="high"
        )
    # destination is granted — but if the data flow is UNTRUSTED-derived (laundered taint),
    # sending it out is still an integrity concern → escalate even to a granted domain
    if flow.is_untrusted:
        return Concern(
            State.ESCALATE, f"untrusted-derived data to granted domain(s): {', '.join(domains)}", judgeable=True, stakes="high"
        )
    return Concern(State.ALLOW, f"outbound to granted domain(s): {', '.join(domains)}")
