"""Structural features — the deterministic, non-semantic half of "bad".

The literature is unanimous that a semantic classifier alone is evadable (paraphrase/encoding/
adversarial perturbation — "Bypassing LLM Guardrails", arXiv:2504.11168) and that exfiltration is
caught by content + context + taint, not by similarity (DLP practice, e.g. Cyberhaven / Lakera).
So these features carry the load `sift`'s embedding cannot: which tool, is it an egress, does the
payload look sensitive, who chose the destination, how big is the blast radius.

These are cheap regex/lookup signals. They are *fused* with the semantic vector by the fusion method
(sift.methods.fusion) and are available to any method as extra columns. Provenance (`sink_provenance`)
is expected to arrive from the harness/engine — mirroring ddbt's own quarantine labelling — because
"could a stranger have chosen this value?" is a data-flow fact, not a text fact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict

import numpy as np

# tools/verbs that move data OUT of the agent's context = potential exfil sinks
# EGRESS = actually transmitting data OUT. Kept to send/transmit VERBS — not the bare noun "email"
# ("identify Alice's email", "search the invitation email" are reads, not egress) and not "fetch"
# (that's ingress). Real exfil still trips this via a send-verb OR an actual external destination
# (the `or dests` in extract()), so tightening the keywords cuts benign false-positives without
# losing attacks. "email"/"mail" only count as a verb when they carry a recipient ("email … to/@").
_EGRESS = re.compile(
    r"\b(send|post|put|upload|push|publish|share|export|curl|wget|webhook|sync|transfer|pay|wire|"
    r"sftp|scp|forward|exfiltrat\w*)\b|\b(e-?mail|mail)\b[^.]{0,60}\b(to|@)\b", re.I)
# high blast-radius / irreversible verbs
_DESTRUCTIVE = re.compile(
    r"\b(delete|drop|truncate|rm|remove|destroy|wipe|revoke|force|--force|reset\s+--hard|"
    r"overwrite|purge)\b", re.I)
# content that shouldn't leave: secrets + bulk PII
_SENSITIVE = re.compile(
    r"(BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]+|"
    r"password|passwd|secret|api[_-]?key|token|credential|\.env|id_rsa|customer|ssn|social security|"
    r"credit card|card number|cvv|bank account|patient|medical record|\b\d{3}-\d{2}-\d{4}\b|\b\d{16}\b)", re.I)
# social-engineering / evasion framing (a genuinely textual signal, kept lexical here)
_SECRECY = re.compile(
    r"\b(don'?t tell|do not tell|without (telling|informing)|keep (this |it )?(secret|quiet|"
    r"between us)|hide (this|it|from)|delete the log|disable (the )?log|no one (will|should) know|"
    r"pre-?approved|already approved)\b", re.I)

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://([^/\s:'\"]+)")

# BULK scope: "all / every / entire / each / whole / *" — the quantifier that separates a mass
# operation ("delete ALL rows", "export the WHOLE table") from a scoped one. Deterministic, and it's
# what a static embedding blurs — so it's exactly the kind of signal that belongs in the structural
# layer, not the model. Generalises across domains (db/files/email/cloud), no SQL parsing.
_BULK = re.compile(r"\b(all|every|each|entire|whole|everything|globally)\b|\*|1\s*=\s*1", re.I)
# scoping qualifiers that make an action targeted, not bulk — suppress the bulk flag when present
_SCOPED = re.compile(r"\b(the one|a single|single|specific|by (its )?id|where id|one record|one row|"
                     r"the row I|the one I|that I (named|asked|mentioned)|older than|expired)\b", re.I)

# order fixes the column layout used by every downstream method
FEATURE_NAMES = [
    "is_egress", "is_destructive", "payload_sensitive", "secrecy_framing",
    "has_external_dest", "sink_from_tool_output", "sink_unknown", "high_impact", "arg_scale",
    "bulk_scope",
]


@dataclass(slots=True)
class Structural:
    is_egress: float = 0.0
    is_destructive: float = 0.0
    payload_sensitive: float = 0.0
    secrecy_framing: float = 0.0
    has_external_dest: float = 0.0
    sink_from_tool_output: float = 0.0
    sink_unknown: float = 0.0
    high_impact: float = 0.0
    arg_scale: float = 0.0
    bulk_scope: float = 0.0

    def vector(self) -> np.ndarray:
        d = asdict(self)
        return np.asarray([d[k] for k in FEATURE_NAMES], dtype=np.float32)


def _arg_scale(text: str) -> float:
    """A crude blast-radius proxy: large recipient lists / row counts / amounts → →1.0."""
    nums = [int(n) for n in re.findall(r"\b(\d{2,7})\b", text)]
    recips = text.count("@")
    mag = max([recips] + [n for n in nums] + [0])
    return float(min(1.0, np.log1p(mag) / np.log1p(1000)))


def extract(tool: str, args_text: str, *, sink_provenance: str = "unknown",
            trusted_domains: tuple[str, ...] = ()) -> Structural:
    """Compute the structural feature row for one action. `args_text` should already be
    decode_and_normalise()'d. `trusted_domains` are destinations the *user* named (so a match there
    is not 'external'). `sink_provenance` ∈ {user, tool, unknown}."""
    blob = f"{tool} {args_text}"
    dests = _EMAIL.findall(args_text) + _URL.findall(args_text)
    external = any(not any(d.endswith(td) for td in trusted_domains) for d in dests) if dests else False
    is_egress = bool(_EGRESS.search(blob)) or bool(dests)
    bulk = bool(_BULK.search(args_text)) and not _SCOPED.search(args_text)
    return Structural(
        is_egress=float(is_egress),
        is_destructive=float(bool(_DESTRUCTIVE.search(blob))),
        payload_sensitive=float(bool(_SENSITIVE.search(args_text))),
        secrecy_framing=float(bool(_SECRECY.search(args_text))),
        has_external_dest=float(external),
        sink_from_tool_output=float(sink_provenance == "tool"),
        sink_unknown=float(sink_provenance == "unknown"),
        high_impact=float(is_egress or bool(_DESTRUCTIVE.search(blob))),
        arg_scale=_arg_scale(args_text),
        bulk_scope=float(bulk),
    )


def bulk_harm_rule(s: Structural) -> bool:
    """Deterministic 'malicious bulk data operation' — the general shape of a bad DB/data action, by
    INTENT not SQL: an operation over ALL/EVERY records that destroys, sends out, or touches sensitive
    data. Static embeddings blur 'delete all' vs 'delete the one I asked'; this rule doesn't. Fires
    only on the bulk quantifier (not scoped ops), so 'update the row I asked' stays clean."""
    return bool(s.bulk_scope and (s.is_destructive or s.is_egress or s.payload_sensitive))


def hard_exfil_rule(s: Structural) -> bool:
    """The deterministic exfil floor that no embedding is trusted to make: a sensitive payload
    leaving to an external sink the user did NOT choose (sink came from a tool output, or its
    provenance is unknown). Mirrors ddbt's provenance deny — if this fires, the decision is DENY
    regardless of the semantic score."""
    sink_not_user_chosen = bool(s.sink_from_tool_output or s.sink_unknown)
    return bool(s.payload_sensitive and s.has_external_dest and sink_not_user_chosen)
