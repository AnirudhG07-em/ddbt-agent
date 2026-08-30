"""Chromatics — a colour for every decision, so a human can read a session at a glance.

TELEMETRY, computed strictly DOWNSTREAM of a decision already made from trusted signals. It
never feeds back into a decision, so it adds no attack surface: an attacker cannot lower their
own colour, because the colour comes from the outcome, not their text.

Deliberately COARSE. We do not ask anyone — model or code — to guess a level on a fine scale;
fine levels are not calibratable. There are exactly four risk bands, decided by plain rules
over the verdict's booleans:

    none   ordinary on-goal action, from you              → green
    low    allowed, but with a soft signal / odd origin    → lime
    med    paused for a human (high-impact, on-goal)       → amber
    high   blocked — deviation, harm, or out of scope      → red

Session heat reuses the engine's own three states (NORMAL / ELEVATED / LOCKED), not a scale.
"""

from __future__ import annotations

from dataclasses import dataclass

LEVELS = ("none", "low", "med", "high")
_RGB = {
    "none": (60, 200, 90),
    "low": (150, 200, 60),
    "med": (225, 170, 40),
    "high": (230, 70, 60),
}


@dataclass(slots=True)
class Chroma:
    level: str        # one of LEVELS
    rgb: tuple        # (r, g, b)
    hex: str          # "#rrggbb"


def classify(effect: str, checkpoint: str, relevant: bool, harmful: bool,
             stray: bool, who: str, high_impact: bool = False) -> str:
    """The four-band rule. Discrete, code-decided — no scale to guess. A high-IMPACT ASK (sensitive
    data leaving, a destructive-but-confirmable op) is red, not amber — so `curl passport.png` reads as
    high while a benign new-host `curl apple.png` stays med."""
    if effect == "deny" or harmful or stray:
        return "high"
    if effect == "ask":
        return "high" if high_impact else "med"
    if who in ("stranger", "unknown") or not relevant:
        return "low"
    return "none"


def chroma(effect: str, checkpoint: str, relevant: bool, harmful: bool,
           stray: bool, who: str) -> Chroma:
    lvl = classify(effect, checkpoint, relevant, harmful, stray, who)
    r, g, b = _RGB[lvl]
    return Chroma(lvl, (r, g, b), f"#{r:02x}{g:02x}{b:02x}")


# ---- session heat: reuse the engine's states, don't invent a scale ----

_HEAT = {
    "NORMAL": (60, 200, 90),
    "ELEVATED": (225, 170, 40),
    "LOCKED": (230, 70, 60),
}


def heat_state(suspicion: int) -> tuple:
    """(name, rgb) for the session-heat meter — thresholds mirror engine._strictness()."""
    name = "NORMAL" if suspicion < 6 else ("ELEVATED" if suspicion < 12 else "LOCKED")
    return name, _HEAT[name]
