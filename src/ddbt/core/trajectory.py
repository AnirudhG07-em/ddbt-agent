"""Cumulative-trajectory checks (#1, doc §1 lookahead).

Every prior system — AgentSpec (acknowledged), CaMeL, FIDES, Conseca, LGA — judges each
action in isolation, so a multi-step attack where each step is individually benign slips
through. ddbt's session store already accumulates state across the (stateless) hook calls,
so we can reason over the whole *trajectory*, not just the current action.

Two shapes we watch (both heuristic → ESCALATE to a human, never silent hard-deny):
  * drip-exfil — an unusual number of outbound sends in one session.
  * exfil shape — a read-heavy session (broad recon) that then sends data externally.

These are friction-only signals: the engine lets them RAISE a decision (ALLOW→ASK) but
never lower one, so a cumulative false-positive can only ask a human, never authorise.
"""

from __future__ import annotations

from dataclasses import dataclass

from ddbt.core.checkpoint2 import State
from ddbt.policy.classifier import StructuralAction, ToolClass
from ddbt.policy.defaults import Policy
from ddbt.store.session import SessionStore

_OUTBOUND = "traj_outbound"
_INGESTS = "traj_untrusted_ingests"
_READS = "traj_reads"  # a set of distinct read paths


@dataclass(slots=True)
class TrajectoryMonitor:
    store: SessionStore
    policy: Policy

    def record(self, action: StructuralAction) -> None:
        """Update cumulative counters after an action has actually run (PostToolUse)."""
        if action.is_outbound:
            self.store.incr(_OUTBOUND)
        if action.tool_class == ToolClass.UNTRUSTED_RETRIEVAL:
            self.store.incr(_INGESTS)
        if action.op in ("read", "fetch"):
            for p in action.paths:
                self.store.add_member(_READS, p)

    def assess(self, action: StructuralAction) -> tuple[State, str] | None:
        """Cumulative risk for the PROPOSED action (counters reflect prior actions only)."""
        if not action.is_outbound:
            return None
        prior_outbound = self.store.get_counter(_OUTBOUND)
        if prior_outbound >= self.policy.max_outbound_per_session:
            return (
                State.ESCALATE,
                f"outbound budget exceeded ({prior_outbound} prior sends this session) — possible drip-exfil",
            )
        reads = self.store.set_size(_READS)
        if self.store.get_counter(_INGESTS) > 0 and reads >= self.policy.recon_read_threshold:
            return (
                State.ESCALATE,
                f"read-heavy session ({reads} files read) now sending externally — exfil shape",
            )
        return None
