"""The trajectory substrate — shared state + views that every cross-step detector reads.

Single-action judging (mitre_guard, destructive_guard, the sift step-judge) cannot see an attack
that is spread across the history: read a secret at step 3, base64 it at step 7, dribble it out over
"benign" fetches at steps 10-14. Each step is innocuous alone; the pattern is the danger. The fix,
convergent across the agent-security papers (CaMeL 2503.18813, FIDES 2505.23643), the APT
provenance-IDS lineage (Holmes, UNICORN), and classic DLP, is to score the SESSION ACTION GRAPH.

This module is that substrate — the cheap tabular form of the graph plus the primitives the detectors
share. The engine records one row per confirmed-executed step (Ledger.record, from record_result);
plugins read views over it (Ledger.rows / egress_rows / bytes_to / intervals / read_rows). Kept
deterministic and dependency-free so the whole trajectory stack stays LLM-free and tiny.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import math
import re
import zlib
from collections import Counter
from dataclasses import dataclass, field

# The single scan bound for the whole guard. Every per-step regex is O(n) (or worse if it backtracks),
# so a multi-MB argument/result — which an adversary can send precisely to stall the guard — must never
# reach one un-truncated. Detectors slice their input to this before scanning. One knob, tuned so a
# real command/destination/secret is always well within it while a DoS payload is bounded.
MAX_SCAN_CHARS = 200_000

# ---- classification of a step by what it does to data flow ----

# a step that sends data OUT of the trust boundary (the sink side of an exfil chain)
EGRESS = re.compile(r"send|email|mail|post|put|upload|push|publish|share|export|curl|wget|webhook|sync|"
                    r"transfer|sftp|scp|pay|wire|slack|discord|telegram|dns|message|notify|sms", re.I)
# a step that brings data IN (the source side — where a secret or untrusted content enters)
READ = re.compile(r"read|cat|get|fetch|open|load|grep|glob|ls|list|select|query|scan|head|tail", re.I)

# ---- shared signal patterns (one definition, imported by the plugins) ----
# secret material by PATH, by VALUE, and the file-name form to carry as an exfil marker.
SECRET_PATH = re.compile(r"\.env\b|id_rsa|/\.ssh/|/\.aws/|credential|\bsecret\b|\.pem\b|private[_-]?key|"
                         r"/etc/shadow|\.npmrc|\.netrc|\btoken\b|api[_-]?key", re.I)
SECRET_VALUE = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{16,}|"
                          r"xox[baprs]-[A-Za-z0-9-]+|gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}|"
                          r"(?:password|passwd|api[_-]?key|secret)\s*[=:]\s*\S+", re.I)
SECRET_FILE = re.compile(r"[\w./-]*(?:\.env|id_rsa|id_ed25519|credentials|\.pem|\.npmrc|\.netrc|shadow)[\w./-]*", re.I)
# encode/compress/reformat steps whose output inherits its input's taint (the anti-obfuscation set).
TRANSFORM = re.compile(r"base64|b64encode|gzip|gunzip|\bzip\b|\bxz\b|\btar\b|openssl|\bxxd\b|hexdump|"
                       r"\bsplit\b|\btr\b|\brev\b|\biconv\b|\bjq\b|urlencode|\buuencode\b|\bzlib\b", re.I)

# quantifiers are BOUNDED (DNS labels are <=63 chars, <=127 labels) so these stay linear — an
# unbounded `+` before a required suffix backtracks O(n^2) on a long homogeneous payload (a DoS input).
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.){1,20}[A-Za-z]{2,24})")
_URL = re.compile(r"https?://([^/\s:'\"]{1,255})")
# a bare host:port or host in a curl/db arg (e.g. evil.io:4444, redis://h, mysql://h)
_HOSTISH = re.compile(r"(?:[a-z]{1,15}://)?((?:[a-z0-9-]{1,63}\.){1,20}[a-z]{2,24})(?::\d+)?", re.I)

# File extensions that a BARE `name.ext` would otherwise be misread as a host (name.txt → host name.txt),
# turning a local file read into phantom "egress". None of these is a real TLD; genuinely ambiguous
# ones (.io/.co/.sh/.me/.app/.dev) are left as hosts, and any real host with a scheme is caught by _URL.
_FILE_EXTS = frozenset(
    "txt log md csv tsv json yaml yml toml ini cfg conf lock xml html htm js mjs cjs jsx tsx ts css scss "
    "less py pyc rb go rs java kt c cc cpp cxx hpp cs php pl lua sql bash zsh ps1 bat cmd png jpg jpeg gif "
    "bmp svg ico webp pdf doc docx xls xlsx ppt pptx zip gz tgz tar bz2 xz rar bin exe dll dylib so class "
    "jar war env pem crt cert pub dat db sqlite bak tmp swp map min mod sum gradle properties dockerfile "
    "gitignore npmrc wasm tf tfvars ipynb parquet avro proto".split())


def flatten(obj) -> str:
    """The string leaves of a tool-input/result structure, space-joined."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(flatten(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(flatten(v) for v in obj)
    return str(obj)


def shannon_entropy(s: str) -> float:
    """Bits/char. Reference bands: English prose ~3.5-4.5; base64 of random/compressed/encrypted
    ~6.0; raw random bytes ~8. High entropy on an outbound payload = likely encoded/encrypted."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def max_token_entropy(text: str, min_len: int = 20) -> tuple[float, str]:
    """The highest-entropy long token in `text` and the token itself — the base64/hex/ciphertext
    blob a naive substring check would miss. Returns (0.0, '') if no long token."""
    best, blob = 0.0, ""
    for t in re.findall(r"[A-Za-z0-9+/=_\-]{%d,}" % min_len, text):
        e = shannon_entropy(t)
        if e > best:
            best, blob = e, t
    return best, blob


def destinations(text: str) -> list[str]:
    """External destinations named in a payload — email domains, URL hosts, bare hosts — lowercased,
    de-duplicated. Where an effect would land; the key for per-destination accounting."""
    text = text[:MAX_SCAN_CHARS]  # bound the scan (regexes below are linear on bounded-label hosts)
    seen, out = set(), []
    hosts = _EMAIL.findall(text) + _URL.findall(text)
    for h in _HOSTISH.findall(text):        # bare hosts: drop `file.ext` false hosts (name.txt, app.log)
        if h.rsplit(".", 1)[-1].lower() not in _FILE_EXTS:
            hosts.append(h)
    for d in hosts:
        d = d.lower().strip(".")
        if d and d not in seen and "." in d:
            seen.add(d)
            out.append(d)
    return out


def is_external(dest: str, trusted: tuple[str, ...]) -> bool:
    """A destination is external unless it is (or is under) a trusted domain."""
    dest = dest.lower()
    return not any(dest == t or dest.endswith("." + t) or dest.endswith(t) for t in trusted)


# Minimal multi-label public suffixes so eTLD+1 is correct on the common shared platforms (a full PSL
# snapshot is the next upgrade). Without these, evil.github.io collapses to github.io and would inherit
# an allowlist entry it shouldn't. Extend via config {"net_filter": {"multi_suffixes": [...]}}.
MULTI_SUFFIX = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "com.br", "co.in", "co.za", "com.cn",
    "github.io", "gitlab.io", "herokuapp.com", "blogspot.com", "web.app", "firebaseapp.com",
    "pages.dev", "workers.dev", "s3.amazonaws.com", "azurewebsites.net", "cloudfront.net", "netlify.app",
})


def registrable(host: str, multi: frozenset = MULTI_SUFFIX) -> str:
    """eTLD+1 aware of multi-label suffixes (co.uk, github.io) — enough that shared-platform tenants
    (evil.github.io) are distinct and list-matching isn't trivially bypassed. Not a full PSL."""
    labels = host.strip(".").split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-3:]) in multi:
        return ".".join(labels[-4:]) if len(labels) >= 4 else host
    if ".".join(labels[-2:]) in multi:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def split_ident(name: str) -> str:
    """BankManagerPayBill / bank_manager_pay_bill → 'Bank Manager Pay Bill' so \\b verb matches fire."""
    return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", re.sub(r"[_\-]+", " ", name))


def decode_variants(s: str, depth: int = 2):
    """`s` plus its base64 / hex / gzip / zlib decodings (recursively, best-effort) — so a secret
    hidden by an encoding step is matched in the clear. This is the deterministic answer to
    'base64 the secret before exfil': we decode the outbound payload and re-scan, no LLM needed."""
    seen, out, frontier = set(), [], [(s, 0)]
    while frontier:
        cur, d = frontier.pop()
        if not cur or cur in seen or len(out) > 24:
            continue
        seen.add(cur)
        out.append(cur)
        if d >= depth or len(cur) > 200_000:
            continue
        for dec in _one_hop_decodes(cur):
            if dec and dec not in seen:
                frontier.append((dec, d + 1))
    return out


def _one_hop_decodes(s: str) -> list[str]:
    outs: list[str] = []
    compact = s.strip().strip("'\"")
    # base64 (pad tolerantly)
    if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", compact):
        try:
            raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
            outs.append(raw.decode("utf-8", "ignore"))
            outs += _decompress(raw)
        except (binascii.Error, ValueError):
            pass
    # hex
    hx = re.sub(r"[^0-9a-fA-F]", "", compact)
    if len(hx) >= 16 and len(hx) % 2 == 0:
        try:
            raw = bytes.fromhex(hx)
            outs.append(raw.decode("utf-8", "ignore"))
            outs += _decompress(raw)
        except ValueError:
            pass
    return outs


def _decompress(raw: bytes) -> list[str]:
    outs: list[str] = []
    for fn in (lambda b: gzip.decompress(b), lambda b: zlib.decompress(b)):
        try:
            outs.append(fn(raw).decode("utf-8", "ignore"))
        except (OSError, zlib.error, EOFError):
            pass
    return outs


# ---- two-axis provenance label (CaMeL {sources,readers} + FIDES {confidentiality,integrity}) ----

@dataclass
class TaintLabel:
    """A value's provenance, propagated by UNION along data-flow edges. Confidentiality answers
    'may this leave?'; integrity answers 'may this drive a privileged action?'. Two axes because a
    secret (high-confidentiality) and attacker-influenced text (low-integrity) need different rules."""
    secret: bool = False          # confidentiality: derived from secret material
    untrusted: bool = False       # integrity: derived from attacker-influenceable content
    sources: set = field(default_factory=set)   # human-readable origins, for the reason string
    tokens: set = field(default_factory=set)     # distinctive secret substrings, for content match

    def union(self, other: "TaintLabel") -> "TaintLabel":
        return TaintLabel(self.secret or other.secret, self.untrusted or other.untrusted,
                          self.sources | other.sources, self.tokens | other.tokens)

    def to_dict(self) -> dict:
        return {"secret": self.secret, "untrusted": self.untrusted,
                "sources": sorted(self.sources)[:12], "tokens": sorted(self.tokens)[:40]}

    @classmethod
    def from_dict(cls, d: dict) -> "TaintLabel":
        d = d or {}
        return cls(bool(d.get("secret")), bool(d.get("untrusted")),
                   set(d.get("sources", [])), set(d.get("tokens", [])))


def direction_of(tool: str, args_text: str) -> str:
    """Classify a step. Egress wins over read (a curl that reads a file to POST it is egress)."""
    if EGRESS.search(tool) or EGRESS.search(args_text):
        return "egress"
    if READ.search(tool):
        return "read"
    return "other"


# ---- the ledger view (thin wrapper over SessionStore) ----

class Ledger:
    """Read/append view over the store's `ledger` table. Detectors construct one from ctx.store."""

    def __init__(self, store):
        self.store = store

    def record(self, tool: str, args, result, *, extra: dict | None = None) -> int:
        """Append the just-executed step. Called by the engine from record_result — so the ledger
        reflects steps that actually RAN, and the next step is judged against real history."""
        if self.store is None:
            return 0
        args_text = flatten(args)
        direction = direction_of(tool, args_text)
        payload = args_text if direction == "egress" else flatten(result)
        n_bytes = len(payload)                        # true size (before capping the scan)
        # bound the scan: entropy/destination regexes are O(n); a multi-MB file read must not stall a
        # decision. MAX_SCAN_CHARS is ample to see a destination or a high-entropy blob.
        scan, dscan = payload[:MAX_SCAN_CHARS], args_text[:MAX_SCAN_CHARS]
        dests = destinations(dscan)
        ent, _ = max_token_entropy(scan)
        step = self.store.increment_meta("ledger_step", 1)
        return self.store.append_ledger({
            "step": step, "tool": tool, "direction": direction,
            "destination": dests[0] if dests else "",
            "n_bytes": n_bytes, "entropy": round(ent, 3),
            "extra": {**(extra or {}), **({"destinations": dests} if len(dests) > 1 else {})},
        })

    def rows(self) -> list[dict]:
        return self.store.read_ledger() if self.store is not None else []

    def egress_rows(self) -> list[dict]:
        return [r for r in self.rows() if r["direction"] == "egress"]

    def read_rows(self) -> list[dict]:
        return [r for r in self.rows() if r["direction"] == "read"]

    def bytes_to(self, dest: str) -> int:
        dest = dest.lower()
        return sum(r["n_bytes"] for r in self.egress_rows() if r["destination"] == dest)

    def calls_to(self, dest: str) -> int:
        dest = dest.lower()
        return sum(1 for r in self.egress_rows() if r["destination"] == dest)

    def intervals(self, dest: str) -> list[float]:
        """Inter-call gaps (seconds) to one destination — the series a beacon detector scores."""
        ts = [r["ts"] for r in self.egress_rows() if r["destination"] == dest.lower()]
        return [b - a for a, b in zip(ts, ts[1:])]

    def destination_counts(self) -> Counter:
        return Counter(r["destination"] for r in self.egress_rows() if r["destination"])
