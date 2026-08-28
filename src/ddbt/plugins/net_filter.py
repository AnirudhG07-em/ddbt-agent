"""net_filter — deterministic network egress control at the tool boundary.

Where an agent may send data is the crux of exfil defense: an injection succeeds when it gets the
agent to POST user data to a destination the ATTACKER chose. The research consensus (CaMeL 2503.18813,
FIDES 2505.23643, InjecAgent 2403.02691) is that the single highest-value, LLM-free rule is a
provenance gate on the destination — and it maps directly onto the missed InjecAgent data-stealing
class, whose attacker address always lives in untrusted tool output and never in the user's request.

Controls, deny-overrides (most-severe wins), ordered by measured prevention value:
  A. destination provenance — an egress whose recipient/URL/phone is INJECTION-DERIVED (seen only in
     untrusted tool content, not named by the user, not a first-party field) → DENY. FIDES→0, CaMeL→0.
  B. SSRF / cloud-metadata / raw-IP — 169.254.169.254, metadata.google.internal, fd00:ec2::254, all
     RFC-6890 special ranges, raw-IP literals → DENY. Credential-theft-via-SSRF, ~0 false positives.
  C. exfil-service denylist — paste/tunnel/webhook/OOB/shortener hosts → DENY. Config-extensible.
  D. eTLD+1-aware matching so evil.github.io / github.com.attacker.net can't slip the lists.
  E. newly-seen-this-session external destination → ASK. Cheap, no feed, high signal.

Everything here is deterministic and LLM-free; the semantic sensitivity/goal-relatedness layer
(Model2Vec) rides on top of this as raise-to-ASK-only enrichment (added separately).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ddbt.core import provenance
from ddbt.core.ledger import (EGRESS as _EGRESS, MAX_SCAN_CHARS, Ledger, destinations, flatten,
                              MULTI_SUFFIX, is_external, registrable as _registrable, split_ident as _split_ident)
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

# High-impact / irreversible / actuation verbs — the Direct-Harm class (money, access, destruction,
# data mutation, credentials) that has no external sink for the destination gate to catch; gated on
# integrity instead. Matched against the CAMEL/SNAKE-SPLIT tool name (BankManagerPayBill → "Pay Bill")
# so word boundaries work. Read-only verbs (view/get/list/…) are deliberately absent → reads run free.
_HIGH_IMPACT = re.compile(
    r"\b(transfer|withdraw|deposit|pay|payment|charge|purchase|buy|order|checkout|place|trade|invest|"
    r"refund|wire|remit|send|"
    r"delete|remove|erase|wipe|drop|destroy|purge|truncate|"
    r"grant|revoke|unlock|disable|enable|deactivate|activate|suspend|terminate|provision|"
    r"shutdown|reboot|reset|deploy|execute|run|install|uninstall|"
    r"create|update|modify|edit|manage|move|rename|replace|overwrite|set|add|dispatch|submit|issue|"
    r"password|passcode|pin|credential|"
    r"book|reserve|cancel|schedule|approve|authorize|publish|share|post|upload)\b", re.I)

# Cloud-metadata endpoints (credential theft via SSRF) and the special-use ranges we never egress to.
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "169.254.169.254", "fd00:ec2::254",
                             "metadata.goog", "instance-data"})

# Exfil / paste / tunnel / webhook / OOB / shortener services — a callout here is near-certain exfil.
# Seeded from soy-rafa/claude-mcp-sentinel + projectdiscovery/interactsh + PeterDaveHello/url-shorteners.
# Matched on eTLD+1 (apex or any subdomain); extend via ddbt.json {"net_filter": {"exfil_services": [...]}}.
_EXFIL_SERVICES = frozenset({
    # paste / file-drop
    "pastebin.com", "paste.ee", "ghostbin.com", "hastebin.com", "dpaste.com", "ix.io", "0x0.st",
    "transfer.sh", "file.io", "gofile.io", "anonfiles.com", "catbox.moe", "termbin.com", "bashupload.com",
    # request-catchers / webhooks / OOB
    "webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "beeceptor.com", "smee.io",
    "requestrepo.com", "requestcatcher.com", "hookbin.com", "canarytokens.com", "dnslog.cn",
    "burpcollaborator.net", "oastify.com", "oast.pro", "oast.live", "oast.site", "oast.online",
    "oast.fun", "oast.me", "interact.sh", "pipedream.com",
    # tunnels
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "loca.lt",
    "localtunnel.me", "localhost.run", "telebit.io", "pagekite.me",
    # URL shorteners (hide the true destination behind one redirect)
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly", "buff.ly", "cutt.ly", "rb.gy",
    "t.ly", "shorturl.at", "rebrand.ly", "adf.ly",
})

_SINK_KINDS = ("email", "url", "phone", "handle")


def _host_of(kind: str, ident: str) -> str | None:
    """The host/domain an identifier would reach: url→netloc, email→domain. None for non-network."""
    ident = ident.strip().lower()
    if kind == "url":
        try:
            return (urlparse(ident).hostname or "").strip("[]") or None
        except ValueError:
            return None
    if kind == "email" and "@" in ident:
        return ident.rsplit("@", 1)[-1] or None
    return None


def _suffix_match(host: str, denyset: frozenset) -> bool:
    """host is, or is a subdomain of, a denylisted domain."""
    host = host.strip(".").lower()
    return any(host == d or host.endswith("." + d) for d in denyset)


def _ssrf_hit(host: str) -> str | None:
    """A metadata endpoint, a raw-IP literal, or a name resolving to a special-use range (checked on
    the literal only — no runtime DNS). Returns a reason or None."""
    if not host:
        return None
    if host in _METADATA_HOSTS:
        return "cloud metadata endpoint (credential theft)"
    literal = host.strip("[]")
    try:
        ip = ipaddress.ip_address(literal)
    except ValueError:
        return None  # a name; we do not resolve at runtime (stays offline/deterministic)
    if ip in ipaddress.ip_network("169.254.169.254/32") or ip in ipaddress.ip_network("fd00:ec2::254/128"):
        return "cloud metadata IP (credential theft)"
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return f"raw IP in a special-use range ({literal})"
    return f"raw-IP destination ({literal}) — agents should use a named host"


class NetFilter(Plugin):
    name = "net_filter"
    headline = "Data is heading to a risky or attacker-controlled destination."

    def __init__(self, trusted_domains: tuple[str, ...] = (), exfil_services=(), allow_hosts=(),
                 multi_suffixes=(), provenance_gate: bool = True, block_ssrf: bool = True,
                 block_exfil_services: bool = True, gate_unknown_destinations: bool = False,
                 gate_newly_seen: bool = True, action_integrity: bool = True):
        self.trusted = tuple(d.lower() for d in trusted_domains) + tuple(h.lower() for h in allow_hosts)
        self.exfil = _EXFIL_SERVICES | {s.lower() for s in exfil_services}
        self.multi = MULTI_SUFFIX | {s.lower() for s in multi_suffixes}
        self.provenance_gate = provenance_gate
        self.block_ssrf = block_ssrf
        self.block_exfil_services = block_exfil_services
        self.gate_unknown = gate_unknown_destinations
        self.gate_newly_seen = gate_newly_seen
        self.action_integrity = action_integrity

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        text = flatten(args)[:MAX_SCAN_CHARS]
        # A2. action-integrity (Direct-Harm class): a high-impact/irreversible action whose parameters
        # are lifted from untrusted content — not from the user's request — must not proceed unconfirmed.
        # This is the FIDES integrity axis and the only lever for in-system harm (no external sink).
        integrity = None
        if self.action_integrity and _HIGH_IMPACT.search(_split_ident(tool)) and self._injection_driven(text, ctx):
            integrity = PreVerdict("ask",
                "Untrusted-driven action (TA0002) · this high-impact action's parameters came from "
                "untrusted tool content, not from your request — confirm before it runs", self.name)
        if not (_EGRESS.search(tool) or _EGRESS.search(text) or destinations(text)):
            return integrity
        sinks = [(k, t) for k, t in provenance.extract(text) if k in _SINK_KINDS]
        if not sinks:
            return integrity   # no destination to gate, but the action-integrity verdict still stands
        goal = (ctx.goal or "").lower()
        worst: PreVerdict | None = None
        seen_regs = self._session_destinations(ctx)

        for kind, ident in sinks:
            host = _host_of(kind, ident)
            # B. SSRF / metadata / raw-IP — hard deny, independent of provenance
            if self.block_ssrf and host:
                s = _ssrf_hit(host)
                if s:
                    worst = self._max(worst, PreVerdict("deny",
                        f"SSRF/metadata (T1552 · TA0006) · egress to {s}", self.name))
                    continue
            reg = _registrable(host, self.multi) if host else None
            # C. exfil-service denylist
            if self.block_exfil_services and host and (_suffix_match(host, self.exfil)):
                worst = self._max(worst, PreVerdict("deny",
                    f"Exfiltration (T1567 · TA0010) · {reg or host} is a known exfil/paste/tunnel/webhook "
                    f"service — a near-certain exfil sink", self.name))
                continue
            # A. destination provenance gate — the InjecAgent data-stealing lever
            v = self._provenance_verdict(ident, host, reg, goal, ctx, seen_regs)
            worst = self._max(worst, v)
        return self._max(worst, integrity)

    def _injection_driven(self, args_text: str, ctx: PluginContext) -> bool:
        """Are this action's parameters lifted from untrusted content the session ingested? Compares
        the argument tokens against quarantined (untrusted) tool output — high overlap ⇒ the injected
        instruction, not the user, chose these parameters."""
        if ctx.store is None:
            return False
        q = " ".join(ctx.store.recent_quarantine(6)).lower()
        if not q:
            return False
        toks = {t for t in re.findall(r"[a-z0-9@._/-]{4,}", args_text.lower())}
        if len(toks) < 3:
            return False
        return sum(1 for t in toks if t in q) / len(toks) >= 0.6

    def _provenance_verdict(self, ident, host, reg, goal, ctx, seen_regs) -> PreVerdict | None:
        dl = ident.strip().lower()
        if dl in goal or (host and host in goal):
            return None  # USER-NAMED — the user chose this destination; trusted
        origins = set()
        if ctx.store is not None:
            origins = {s.get("origin") for s in ctx.store.lookup_provenance(dl)}
        if provenance.FIELD in origins:
            return None  # GROUNDED — a first-party structured field (e.g. "reply to the sender")
        external = (not host) or is_external(host, self.trusted)
        if self.provenance_gate and provenance.CONTENT in origins and external:
            # INJECTION-DERIVED: this destination was chosen by whoever wrote untrusted tool content,
            # not by the user. This is the exfil sink of the data-stealing attack class.
            return PreVerdict("deny",
                f"Exfiltration (T1567 · TA0010) · the destination {ident[:48]!r} was chosen by untrusted "
                f"tool content, not by you — the injected-recipient exfil pattern", self.name)
        if not external:
            return None
        # UNKNOWN origin (never in the goal, never in a tool result) on an external destination.
        if self.gate_unknown:
            return PreVerdict("ask",
                f"egress to {ident[:48]!r}, a destination that appears neither in your request nor in any "
                f"tool result — confirm it's intended", self.name)
        if self.gate_newly_seen and reg and reg not in seen_regs:
            return PreVerdict("ask",
                f"first send to {reg} this session — confirm this new external destination", self.name)
        return None

    def _session_destinations(self, ctx: PluginContext) -> set[str]:
        if ctx.store is None:
            return set()
        regs = set()
        for r in Ledger(ctx.store).egress_rows():
            d = r.get("destination")
            if d:
                regs.add(_registrable(d, self.multi))
        return regs

    @staticmethod
    def _max(a: PreVerdict | None, b: PreVerdict | None) -> PreVerdict | None:
        order = {"ask": 1, "deny": 2}
        if a is None:
            return b
        if b is None:
            return a
        return b if order.get(b.effect, 0) > order.get(a.effect, 0) else a
