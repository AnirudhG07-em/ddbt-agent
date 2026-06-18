"""Checkpoint 3 — commit-time review of the materialised batch (doc §6).

At commit we judge the *real* staged effects (actual files to change, actual bytes
about to leave), not a predicted plan. v0.1 ships a **deterministic** reviewer (zero
LLM, matching the v0.1 scope): it holds any staged outbound whose destination is not
in the envelope or whose recorded payload references a sensitive path. The blind LLM
diff-judge (v0.3) plugs in via the optional ``judge`` argument without changing the
commit machinery — and, like Checkpoint 2, it only ever sees structural diff facts,
never untrusted prose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ddbt.core.envelope import Envelope
from ddbt.policy.defaults import Policy
from ddbt.store.session import StagedItem


class DiffJudge(Protocol):
    """The blind commit-time judge (v0.3). Input is structural diff facts."""

    def judge(self, item: StagedItem) -> tuple[bool, str]:  # (release_ok, reason)
        ...


@dataclass(slots=True)
class CommitReview:
    release: list[StagedItem] = field(default_factory=list)
    hold: list[tuple[StagedItem, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.hold


def review(
    items: list[StagedItem],
    env: Envelope,
    policy: Policy,
    judge: DiffJudge | None = None,
) -> CommitReview:
    out = CommitReview()
    for it in items:
        ok, reason = _deterministic_check(it, env, policy)
        if ok and judge is not None:
            ok, reason = judge.judge(it)
        if ok:
            out.release.append(it)
        else:
            out.hold.append((it, reason))
    return out


def _deterministic_check(item: StagedItem, env: Envelope, policy: Policy) -> tuple[bool, str]:
    action = item.action
    targets = action.get("targets", [])
    domains = [v for (k, v) in targets if k == "domain"]
    paths = [v for (k, v) in targets if k == "path"]

    if action.get("is_outbound"):
        bad = [d for d in domains if not env.allows_domain(d)]
        if bad:
            return False, f"outbound destination not in envelope: {', '.join(bad)}"
        # inspect the actual payload for sensitive-path references (the concrete diff)
        payload = str(action.get("tool_input", {}))
        for p in _sensitive_refs(payload, policy):
            return False, f"payload references sensitive path: {p}"
    for p in paths:
        if policy.is_sensitive_path(p):
            return False, f"staged op touches sensitive path: {p}"
    return True, "clean"


def _sensitive_refs(text: str, policy: Policy) -> list[str]:
    hits: list[str] = []
    for token in text.replace("'", " ").replace('"', " ").replace(",", " ").split():
        if ("/" in token or token.startswith("~")) and policy.is_sensitive_path(token):
            hits.append(token)
    return hits
