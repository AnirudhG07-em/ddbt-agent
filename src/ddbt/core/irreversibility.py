"""Irreversibility gate (doc §6).

Any operation in the dangerous set ``{delete, truncate, drop, send, publish, push,
overwrite}`` requires confirmation **regardless of label** — unless it is
pre-authorised by an explicit user grant already in the envelope. This is a hard
gate in the scaffolding: the model cannot argue past it. It is orthogonal to
Checkpoint 2 (relevance/boundary); a relevant, in-envelope action can still be
irreversible and thus require a confirm.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ddbt.core.envelope import Envelope
from ddbt.policy.classifier import StructuralAction
from ddbt.policy.defaults import Policy


@dataclass(slots=True)
class IrreversibilityVerdict:
    triggered: bool
    ops: set[str] = field(default_factory=set)
    preauthorized: bool = False
    reason: str = ""


def check(action: StructuralAction, env: Envelope, policy: Policy) -> IrreversibilityVerdict:
    ops = set(action.dangerous_ops) & policy.dangerous_ops
    if action.is_outbound:
        ops.add("send")

    if not ops:
        return IrreversibilityVerdict(triggered=False)

    # Pre-authorisation: an outbound op whose every target domain was explicitly
    # granted into the envelope is allowed to flow (the user named it, doc §3.2).
    if ops <= {"send", "publish", "push"} and action.domains:
        if all(env.allows_domain(d) for d in action.domains):
            return IrreversibilityVerdict(
                triggered=True, ops=ops, preauthorized=True, reason="outbound to granted domain"
            )

    return IrreversibilityVerdict(
        triggered=True, ops=ops, preauthorized=False, reason=f"irreversible op(s): {', '.join(sorted(ops))}"
    )
