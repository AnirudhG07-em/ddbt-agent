"""Staging — a tripwire on the dangerous subset, not a wall (doc §7.2).

Every side-effecting op falls into one of three lanes:

  PASS_THROUGH  in-scope writes/edits — happen directly (workspace is git-tracked,
                undo is free); zero overhead.
  STAGED        out-of-scope writes/deletes + all outbound network — intercepted and
                held in a real queue; released only at commit after Checkpoint 3.
  GATE_ONLY     un-stageable effects (DB DROP over a live connection, process kill,
                irreversible external API) — cannot be cheaply staged, so hard-confirm.

The queue is *real* at the semantic layer: a staged action is recorded and NOT
executed live; ``release_all`` / ``drop_all`` at commit decide its fate. True
packet-level egress control (raw sockets bypassing us) needs the OS substrate
(doc §9) and is out of scope for v0.1 — documented honestly.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from ddbt.core.envelope import Envelope
from ddbt.policy.classifier import StructuralAction
from ddbt.policy.defaults import Policy
from ddbt.store.session import SessionStore, StagedItem


class Lane(enum.Enum):
    PASS_THROUGH = "pass_through"
    STAGED = "staged"
    GATE_ONLY = "gate_only"


# bash binaries whose effects cannot be staged or cheaply undone
_UNSTAGEABLE_HINTS = ("kill", "killall", "pkill", "shutdown", "reboot", "systemctl")


def route(action: StructuralAction, env: Envelope, policy: Policy, cwd: str | None = None) -> Lane:
    """Decide which lane a (already Checkpoint-2-passed) action travels."""
    # DB drops / process control / system power are un-stageable → gate-only.
    if "drop" in action.dangerous_ops:
        return Lane.GATE_ONLY
    if action.tool_name == "Bash" and any(h in action.summary for h in _UNSTAGEABLE_HINTS):
        return Lane.GATE_ONLY

    # all outbound network is staged (held in the queue, released at commit)
    if action.is_outbound:
        return Lane.STAGED

    if action.op in ("write", "delete"):
        resolved = [str(policy.resolve(p, cwd)) for p in action.paths]
        in_scope = bool(resolved) and all(env.contains_write(r) for r in resolved)
        return Lane.PASS_THROUGH if in_scope else Lane.STAGED

    # reads / exec / pure → nothing to stage
    return Lane.PASS_THROUGH


@dataclass(slots=True)
class StagingManager:
    """Store-backed staging queue (survives the stateless hook subprocesses)."""

    store: SessionStore

    def stage(self, action: StructuralAction, tool_input: dict, lane: Lane) -> int:
        """Record an intercepted action; it does NOT execute live."""
        item = {
            "tool": action.tool_name,
            "op": action.op,
            "lane": lane.value,
            "targets": [(t.kind, t.value) for t in action.targets],
            "is_outbound": action.is_outbound,
            "summary": action.summary,
            "tool_input": tool_input,  # kept so the op can be applied at commit
        }
        sid = self.store.stage("network" if action.is_outbound else "fs", item)
        self.store.append_audit("staged", {"id": sid, "lane": lane.value, "summary": action.summary})
        return sid

    def pending(self) -> list[StagedItem]:
        return self.store.list_staged("pending")

    def release_all(self) -> list[StagedItem]:
        """Mark all pending items released (commit accepted)."""
        items = self.pending()
        for it in items:
            self.store.set_staged_status(it.id, "released")
            self.store.append_audit("released", {"id": it.id, "kind": it.kind})
        return items

    def drop_all(self, reason: str) -> list[StagedItem]:
        """Discard all pending items (commit rejected by Checkpoint 3)."""
        items = self.pending()
        for it in items:
            self.store.set_staged_status(it.id, "dropped")
            self.store.append_audit("dropped", {"id": it.id, "kind": it.kind, "reason": reason})
        return items
