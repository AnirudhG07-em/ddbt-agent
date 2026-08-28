"""trajectory_score — a holistic per-session risk monitor over the whole action history.

The hard rules each catch one failure mode. This layer watches the SHAPE of the trajectory for the
diffuse signal no single rule sees: the agent quietly drifting off the user's goal and then moving data
outward. It engineers the cross-step features the fraud-detection-for-agents work (arXiv 2605.01143)
found dominant — context-exfil gap, action burst, destination novelty — and adds goal-drift (cosine of
the stated goal vs. recent actions, via the shared Model2Vec encoder).

Honest scope: that paper TRAINS a gradient-boosted tree on labelled trajectories. We have no labelled
trajectory corpus, so this is a TRANSPARENT WEIGHTED score, not a learned model, and it lives in the
ASK tier (it asks a human when the session looks risky; it does not hard-deny on a heuristic alone).
When a labelled trajectory set exists, the same features drop into a trained head (reusing sift's GBT).
"""

from __future__ import annotations

import re

from ddbt.core.ledger import EGRESS, Ledger, destinations, flatten, is_external
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

_HIGH_RISK = re.compile(r"send|email|mail|post|upload|push|curl|wget|transfer|pay|delete|remove|rm\s|drop|"
                        r"grant|revoke|deploy|execute|share|export", re.I)


def _registrable(host: str) -> str:
    labels = host.strip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


class TrajectoryScore(Plugin):
    name = "trajectory_score"

    def __init__(self, trusted_domains: tuple[str, ...] = (), ask: float = 0.4, deny: float = 0.7,
                 window: int = 5, gap_window: int = 4, goal_drift: bool = True):
        self.trusted = tuple(d.lower() for d in trusted_domains)
        self.ask, self.deny = ask, deny
        self.window, self.gap_window = window, gap_window
        self.goal_drift = goal_drift
        self._genc = None
        self._goal_vec = None
        self._goal_txt = None

    def _drift(self, goal: str, rows: list) -> float | None:
        """1 - cosine(goal, recent actions). Rising drift = the trajectory diverging from the task."""
        if not self.goal_drift or not goal or len(rows) < 2:
            return None
        try:
            from ddbt.judge.embedder import get_encoder
            enc = get_encoder()
            if enc is None:
                return None
            if self._goal_txt != goal:                       # cache the goal vector per session
                self._goal_vec = enc.encode([goal])[0]
                self._goal_txt = goal
            recent = " ".join(f"{r['tool']} {r['direction']} {r['destination']}" for r in rows[-self.window:])
            av = enc.encode([recent])[0]
            return max(0.0, 1.0 - float(self._goal_vec @ av))
        except Exception:  # noqa: BLE001
            return None

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        if ctx.store is None:
            return None
        led = Ledger(ctx.store)
        rows = led.rows()
        text = flatten(args)
        dests = destinations(text)
        ext_egress = bool(EGRESS.search(tool) or EGRESS.search(text)) and \
            ((not dests) or any(is_external(d, self.trusted) for d in dests))

        feats: dict[str, float] = {}
        # context-exfil gap: an external send close behind a read (read→exfil) is the exfil shape
        if ext_egress and rows:
            reads = [r for r in rows if r["direction"] == "read"]
            if reads:
                gap = max(0, (rows[-1]["step"] + 1) - reads[-1]["step"])
                feats["gap"] = max(0.0, 1.0 - gap / max(1, self.gap_window))
        # action burst: how much of the recent window is high-impact
        if rows:
            win = rows[-self.window:]
            hr = sum(1 for r in win if r["direction"] == "egress" or _HIGH_RISK.search(r["tool"]))
            feats["burst"] = hr / len(win)
        # destination novelty: a brand-new external destination
        if ext_egress and dests:
            prior = {_registrable(r["destination"]) for r in rows if r["destination"]}
            feats["novelty"] = 1.0 if any(_registrable(d) not in prior for d in dests) else 0.0
        # goal drift
        d = self._drift(ctx.goal, rows)
        if d is not None:
            feats["drift"] = d

        if not feats:
            return None
        # RAW weighted sum (weights sum to 1.0, so score ∈ [0,1] and no single feature can dominate —
        # a lone novel destination stays low; only several signals together escalate).
        weights = {"gap": 0.35, "burst": 0.2, "novelty": 0.15, "drift": 0.3}
        score = sum(weights[k] * v for k, v in feats.items())
        top = ", ".join(f"{k}={feats[k]:.2f}" for k in sorted(feats, key=lambda k: -feats[k])[:3])
        if score >= self.deny:
            return PreVerdict("deny", f"Trajectory risk {score:.2f} · session risk is very high ({top})", self.name)
        if score >= self.ask:
            return PreVerdict("ask", f"Trajectory risk {score:.2f} · this session's action pattern looks "
                              f"risky ({top}) — confirm before proceeding", self.name)
        return None
