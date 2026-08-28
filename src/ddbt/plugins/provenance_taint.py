"""Provenance taint — the trajectory-aware successor to dataflow_taint.

The read-secret -> ... -> send-out chain is two innocuous steps that together are exfiltration; a
per-call judge misses it. dataflow_taint caught the simple case but re-matched the secret as a
SUBSTRING of the outbound text — so `base64 .env` then `curl -d <blob>` walked straight past it,
because the encoded bytes don't contain the literal secret. That evasion is the whole game.

This plugin fixes it the way the literature converges on (CaMeL 2503.18813, FIDES 2505.23643, classic
DIFT): TAINT FOLLOWS THE DATA-FLOW EDGE, not the bytes. `out = f(tainted_in)` => `out` is tainted by
construction, whatever the encoding. Four layers catch a leaking secret:

  1. marker/token match  — the outbound payload literally contains a secret token or the secret file.
  2. edge propagation    — a transform (base64/gzip/split/openssl) whose INPUT was tainted taints its
                           OUTPUT tokens, so the encoded blob is tracked even though it looks random.
  3. decode-then-match   — the outbound payload is base64/hex/gzip-decoded (recursively) and re-scanned,
                           catching an inline-encoded secret with no prior transform step observed.
  4. entropy fallback    — once a secret was read, a high-entropy blob heading to an external sink is
                           the ciphertext/compressed-payload signature (weakest signal -> ASK, not DENY).

Confidentiality axis (may this leave?) is enforced here. The integrity axis (may untrusted data drive
a privileged action?) is already enforced by the engine's INJECTION-DERIVED hard-deny; this plugin
records the untrusted label into the taint state so the later trajectory layers can use it too.
"""

from __future__ import annotations

import json
import re

from ddbt.core.ledger import (EGRESS as _EGRESS, MAX_SCAN_CHARS, READ, SECRET_FILE as _SECRET_FILE,
                              SECRET_PATH as _SECRET_PATH, SECRET_VALUE as _SECRET_VALUE,
                              TRANSFORM as _TRANSFORM, TaintLabel, decode_variants, destinations, flatten,
                              is_external, max_token_entropy, shannon_entropy)
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

_KEY = "provenance_taint"

# sources that inject attacker-influenceable content (integrity axis)
_UNTRUSTED_SRC = re.compile(r"webfetch|websearch|fetch|browse|crawl|http", re.I)


def _secret_tokens(blob: str) -> set[str]:
    """Distinctive substrings of secret material — explicit secret-value shapes plus long,
    high-entropy tokens — that identify this secret if it later appears (even after decoding)."""
    toks: set[str] = set()
    for m in _SECRET_VALUE.finditer(blob):
        for piece in re.findall(r"[A-Za-z0-9+/=_.\-]{8,}", m.group(0)):
            toks.add(piece.lower())
    for t in re.findall(r"[A-Za-z0-9+/=_\-]{12,}", blob):
        if shannon_entropy(t) >= 3.2:
            toks.add(t.lower())
    return {t for t in toks if len(t) >= 8}


class ProvenanceTaint(Plugin):
    name = "provenance_taint"
    headline = "A secret read earlier this session may be leaving your machine."

    def __init__(self, trusted_domains: tuple[str, ...] = ()):
        self.trusted = tuple(d.lower() for d in trusted_domains)

    # ---- persisted taint state (survives the stateless per-call hook) ----
    def _load(self, ctx: PluginContext) -> tuple[TaintLabel, list[str]]:
        if ctx.store is None:
            return TaintLabel(), []
        raw = ctx.store.get_meta(_KEY)
        try:
            d = json.loads(raw) if raw else {}
        except (ValueError, TypeError):
            d = {}
        return TaintLabel.from_dict(d.get("label", {})), list(d.get("markers", []))

    def _save(self, ctx: PluginContext, label: TaintLabel, markers: list[str]) -> None:
        if ctx.store is not None:
            payload = json.dumps({"label": label.to_dict(), "markers": markers[-16:]})
            ctx.store.set_meta(_KEY, payload[:8000])

    # ---- observe: accumulate taint from reads and transforms ----
    def observe(self, tool: str, args: dict, result, ctx: PluginContext) -> None:
        args_text, res_text = flatten(args)[:MAX_SCAN_CHARS], flatten(result)[:MAX_SCAN_CHARS]
        blob = f"{args_text} {res_text}"
        label, markers = self._load(ctx)
        changed = False

        read_secret = (_SECRET_PATH.search(blob) and READ.search(tool)) or _SECRET_VALUE.search(res_text)
        if read_secret:
            label.secret = True
            label.sources.add(f"secret read via {tool}")
            label.tokens |= _secret_tokens(res_text)
            for m in _SECRET_FILE.findall(blob):
                if m.lower() not in markers:
                    markers.append(m.lower())
            changed = True

        if _UNTRUSTED_SRC.search(tool):
            label.untrusted = True
            label.sources.add(f"untrusted content via {tool}")
            changed = True

        # EDGE PROPAGATION: a transform whose input references existing taint taints its output.
        # `base64 .env` -> the encoded blob's tokens become tainted, so a later curl of that blob is
        # caught even though the blob shares no bytes with the secret. This is the anti-encoding core.
        if _TRANSFORM.search(f"{tool} {args_text}") and self._refs_taint(args_text, label, markers):
            new = {t for t in _blobs(res_text)}
            if new - label.tokens:
                label.tokens |= new
                label.sources.add("propagated through an encoding/transform step")
                changed = True

        if changed:
            self._save(ctx, label, markers)

    def _refs_taint(self, text: str, label: TaintLabel, markers: list[str]) -> bool:
        low = text.lower()
        if _SECRET_PATH.search(low):
            return True
        return any(m in low for m in markers) or any(t in low for t in label.tokens if len(t) >= 8)

    # ---- pre_check: enforce the confidentiality axis at the sink ----
    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        text = flatten(args)[:MAX_SCAN_CHARS]   # bound the scan up front (a huge payload must not stall us)
        dests = destinations(text)
        if not (_EGRESS.search(tool) or _EGRESS.search(text) or dests):
            return None
        label, markers = self._load(ctx)
        if not (label.secret or label.untrusted):
            return None

        hit = self._carries(text, label, markers)
        if not hit:
            return None
        kind, detail = hit
        external = (not dests) or any(is_external(d, self.trusted) for d in dests)
        where = dests[0] if dests else "an unverified destination"

        if label.secret and kind != "entropy" and external:
            why = (f"Exfiltration (T1567 · TA0010) · a secret read earlier this session is leaving to "
                   f"{where} ({detail}) — the read->send exfil chain, tracked across encoding")
            return PreVerdict("deny", why, self.name)
        # weaker signals or internal destinations -> put a human in the loop
        why = (f"Exfiltration (T1567 · TA0010) · data derived from a secret read earlier this session "
               f"is being sent {'out to ' + where if external else 'onward'} ({detail}) — confirm it's intended")
        return PreVerdict("ask", why, self.name)

    def _carries(self, text: str, label: TaintLabel, markers: list[str]) -> tuple[str, str] | None:
        """Does the outbound payload carry tainted data? Checked against every DECODING of the
        payload — and of each long token WITHIN it — so an encoded secret embedded in a command
        (e.g. `curl -d '<base64>' host`) is matched in the clear. Returns (kind, detail) or None."""
        text = text[:MAX_SCAN_CHARS]  # bound the scan — a huge outbound payload must not stall the decision
        candidates = [text] + re.findall(r"[A-Za-z0-9+/=_\-]{16,}", text)[:128]
        variants = []
        for c in candidates:
            variants.extend(decode_variants(c))
        variants = [v.lower() for v in variants]
        for tok in label.tokens:
            if len(tok) >= 8 and any(tok in v for v in variants):
                return "token", f"carries secret token …{tok[-8:]}"
        for mk in markers:
            if mk and any(mk in v for v in variants):
                return "marker", f"carries the secret file {mk}"
        for v in variants[1:]:  # a decoded (not the raw) payload revealing a secret path
            if _SECRET_PATH.search(v):
                return "decoded", "a decoded payload reveals secret material"
        if label.secret:
            e, blob = max_token_entropy(text, 24)
            if e >= 4.3:
                return "entropy", f"high-entropy blob leaving after a secret read (H={e:.1f})"
        return None


def _blobs(text: str) -> set[str]:
    """Long tokens of a transform's output — the encoded blob(s) to keep tainting forward."""
    return {t.lower() for t in re.findall(r"[A-Za-z0-9+/=_\-]{16,}", text)
            if shannon_entropy(t) >= 3.5}
