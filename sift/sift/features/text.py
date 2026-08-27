"""Canonicalisation of an agent action into the text `sift` actually judges.

Two jobs, both are *defence* choices, not cosmetics:

1. `render_action` turns a structured tool-call into a stable, tagged template string. Injecting
   structural tags (TOOL/SINK/SOURCE/PAYLOAD) into the text gives even a *static* embedder a weak
   provenance hint for free — the model can't compute taint, but it can see that a value is tagged
   `<external>` or `<tool_output>`. (Representation matters more than the encoder; cf. SetFit's
   finding that the head is cheap once the text is right — Tunstall et al., arXiv:2209.11055.)

2. `decode_and_normalise` unwraps base64 / hex / ROT13 and folds unicode confusables BEFORE
   embedding. This closes the single biggest evasion class for semantic detectors: the gap between
   what the detector reads and what the model executes (paraphrase/encoding/homoglyph attacks) —
   "Bypassing LLM Guardrails", arXiv:2504.11168, §Effective Attack Techniques.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
import unicodedata

_B64 = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}\s*){12,}")
# a tiny confusable table is enough for the common homoglyph tricks; full tables exist but add MB.
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "ѕ": "s", "і": "i", "һ": "h", "K": "k", "ａ": "a", "ｅ": "e",
})


def _try_b64(s: str) -> str | None:
    try:
        raw = base64.b64decode(s, validate=True)
        txt = raw.decode("utf-8")
        return txt if txt.isprintable() and len(txt) >= 4 else None
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _try_hex(s: str) -> str | None:
    try:
        raw = bytes.fromhex(re.sub(r"\s+", "", s))
        txt = raw.decode("utf-8")
        return txt if txt.isprintable() and len(txt) >= 4 else None
    except (ValueError, UnicodeDecodeError):
        return None


def decode_and_normalise(text: str) -> str:
    """Fold unicode, un-ROT13-ish, and inline-decode any base64/hex blobs, appending the plaintext
    so the embedder sees BOTH surfaces. Idempotent enough for training and inference."""
    if not text:
        return ""
    t = unicodedata.normalize("NFKC", text).translate(_CONFUSABLE)
    extras: list[str] = []
    for m in _B64.findall(t):
        dec = _try_b64(m)
        if dec:
            extras.append(dec)
    for m in _HEX.findall(t):
        dec = _try_hex(m)
        if dec:
            extras.append(dec)
    # ROT13 is self-inverse and common in these attacks; add the rotated view as a candidate.
    rot = codecs.encode(t, "rot_13")
    if rot != t:
        extras.append(rot)
    return t if not extras else t + " ⟨decoded⟩ " + " ".join(extras)


# ---- structural tagging of the destination / payload, purely lexical (no model) ----

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://([^/\s:'\"]+)")


def _flatten(obj) -> str:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(f"{k}={_flatten(v)}" for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten(v) for v in obj)
    return str(obj)


def render_action(tool: str, args: dict, goal: str = "", history: str = "",
                  sink_provenance: str = "unknown") -> str:
    """Canonical, tagged one-line rendering of a tool call in its context.

    `sink_provenance` is supplied by the harness/engine (user | tool-derived | unknown) — the text
    layer never *computes* it, it only surfaces it so the semantic model can weight it.
    """
    argtext = decode_and_normalise(_flatten(args))
    dests = _EMAIL.findall(argtext) + _URL.findall(argtext)
    dest_tag = f" SINK={','.join(dests)}" if dests else ""
    parts = [
        f"GOAL: {decode_and_normalise(goal)[:400]}" if goal else "GOAL: <none>",
        f"TOOL={tool} SOURCE={sink_provenance}{dest_tag}",
        f"ARGS: {argtext[:600]}",
    ]
    if history:
        parts.append(f"HISTORY: {decode_and_normalise(history)[:300]}")
    return "\n".join(parts)
