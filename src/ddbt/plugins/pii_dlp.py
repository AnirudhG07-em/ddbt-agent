"""PII / DLP plugin — typed sensitive-data detection on egress, backed by Presidio when available.

Presidio (github.com/microsoft/presidio, now data-privacy-stack) gives *validated, typed* PII
detection — Luhn-checked cards, SSNs, emails, IPs, crypto — far stronger than a single regex. This
plugin runs Presidio's Analyzer in PATTERN-ONLY mode (no spaCy NER, so it's light and fast) on the
payload of an egress step and ASKs a human when it would send meaningful PII to an external sink.

Presidio is optional: if `presidio-analyzer` isn't installed, the plugin degrades to a built-in regex
detector so it still works (just coarser). Detection here is deterministic; it complements sift's
semantic risk and the dataflow-taint chain, and sets up a future SANITIZE (redact-then-send) outcome
via Presidio's Anonymizer.
"""

from __future__ import annotations

import re

from ddbt.core.ledger import EGRESS as _EGRESS, flatten as _flatten
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://([^/\s:'\"]+)")

# fallback regex detectors (used when Presidio isn't installed)
_FALLBACK = {
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "EMAIL": _EMAIL,
    "IP": re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    "API_KEY": re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b"),
}


def _luhn_ok(num: str) -> bool:
    ds = [int(c) for c in re.sub(r"\D", "", num)]
    if len(ds) < 13:
        return False
    s, alt = 0, False
    for d in reversed(ds):
        d = d * 2 - 9 if alt and d * 2 > 9 else (d * 2 if alt else d)
        s += d
        alt = not alt
    return s % 10 == 0


# Presidio's AnalyzerEngine is a stateless, read-only detector, but constructing one spins up a spaCy
# NLP pipeline (~3s cold). It's identical across every plugin instance, so build it ONCE and share it —
# otherwise a benchmark that makes a fresh plugin per case pays that ~1.3s over and over (the dominant
# cost in replays: ~20+ min on InjecAgent alone, not the ~1ms inference). Sentinel distinguishes
# "not built yet" from "built, but presidio unavailable → None".
_ANALYZER_SENTINEL = object()
_ANALYZER = _ANALYZER_SENTINEL


def _installed_spacy_model():
    """Return an already-INSTALLED spaCy English model name, or None. We NEVER download one — a bare
    AnalyzerEngine() defaults to en_core_web_lg (~560MB) and will try to fetch it at runtime (fatal
    inside the em-bash OS sandbox, which denies the write). So Presidio's NER is used only if a model
    is already present; otherwise we fall back to the regex detectors below."""
    import importlib.util
    for name in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm"):
        if importlib.util.find_spec(name) is not None:
            return name
    return None


def _shared_analyzer():
    global _ANALYZER
    if _ANALYZER is _ANALYZER_SENTINEL:
        _ANALYZER = None
        model = _installed_spacy_model()
        if model is not None:                       # only build Presidio NER if a model already exists
            try:
                from presidio_analyzer import AnalyzerEngine
                from presidio_analyzer.nlp_engine import NlpEngineProvider
                provider = NlpEngineProvider(nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model}],
                })
                _ANALYZER = AnalyzerEngine(nlp_engine=provider.create_nlp_engine())
            except Exception:
                _ANALYZER = None                    # any failure → regex fallback, never a download
    return _ANALYZER


def redaction_backend() -> str:
    """Which redaction is active: "presidio" (typed PII incl. names via NER) or "regex" (emails, cards,
    SSNs, API keys — always available, no deps, no model). Used to tell the UI what it can offer."""
    return "presidio" if _shared_analyzer() is not None else "regex"


class PiiDlp(Plugin):
    name = "pii_dlp"
    headline = "Personal info (names, emails, SSNs, cards) may be leaking out."

    def __init__(self, min_entities: int = 1, trusted_domains: tuple[str, ...] = (), mode: str = "sanitize"):
        # mode: "ask" (confirm with a human) | "sanitize" (redact PII, then send) | "deny" (block)
        self.min_entities = int(min_entities)
        self.trusted = tuple(d.lower() for d in trusted_domains)
        self.mode = mode if mode in ("ask", "sanitize", "deny") else "ask"
        self._analyzer = self._try_presidio()
        self._anonymizer = self._try_anonymizer()

    def _try_presidio(self):
        return _shared_analyzer()

    def _detect(self, text: str) -> list[str]:
        hits: list[str] = []
        # Presidio (validated, typed) if available…
        if self._analyzer is not None:
            try:
                hits += [r.entity_type for r in self._analyzer.analyze(text=text, language="en") if r.score >= 0.5]
            except Exception:
                pass
        # …AND the regex fallback — Presidio pattern-only (no NER) misses some, e.g. a bare SSN. Union
        # so a detector's blind spot is covered by the other.
        for name, pat in _FALLBACK.items():
            for m in pat.findall(text):
                val = m if isinstance(m, str) else " ".join(m)
                if name == "CREDIT_CARD" and not _luhn_ok(val):
                    continue
                hits.append(name)
        seen, out = set(), []
        for h in hits:
            if h not in seen:
                seen.add(h); out.append(h)
        return out

    def _try_anonymizer(self):
        try:
            from presidio_anonymizer import AnonymizerEngine
            return AnonymizerEngine()
        except Exception:
            return None

    def _redact_text(self, text: str) -> str:
        """Replace detected PII with typed placeholders — Presidio Anonymizer if available, THEN the
        regex fallback on top (so a bare SSN Presidio's pattern-only mode misses is still redacted)."""
        out = text
        if self._analyzer is not None and self._anonymizer is not None:
            try:
                results = self._analyzer.analyze(text=out, language="en")
                out = self._anonymizer.anonymize(text=out, analyzer_results=results).text
            except Exception:
                pass
        for name, pat in _FALLBACK.items():        # union: catch what Presidio missed
            out = pat.sub(f"<{name}_REDACTED>", out)
        return out

    # destination fields carry the (already grant-checked) recipient — never redact them, or the
    # send breaks; only redact the CONTENT the message carries.
    _DEST_KEYS = {"to", "recipient", "recipients", "cc", "bcc", "url", "host", "dest",
                  "destination", "address", "email", "account", "vendor"}

    def _redact_args(self, args) -> dict:
        if isinstance(args, dict):
            return {k: (self._redact_text(v) if isinstance(v, str) and k.lower() not in self._DEST_KEYS else v)
                    for k, v in args.items()}
        return {"value": self._redact_text(str(args))}

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        text = _flatten(args)
        dests = _EMAIL.findall(text) + _URL.findall(text)
        is_egress = bool(_EGRESS.search(tool) or dests)
        if not is_egress:
            return None
        external = any(not any(d.endswith(t) for t in self.trusted) for d in dests) if dests else True
        if not external:
            return None
        entities = self._detect(text)
        if len(entities) < self.min_entities:
            return None
        kinds = ", ".join(sorted(set(entities))[:4])
        if self.mode == "sanitize":
            return PreVerdict("sanitize", f"redacted PII ({kinds}) before sending to an external destination",
                              self.name, rewrite=self._redact_args(args))
        if self.mode == "deny":
            return PreVerdict("deny", f"egress carries sensitive data ({kinds}) to an external destination", self.name)
        return PreVerdict("ask", f"egress carries sensitive data ({kinds}) to an external destination",
                          self.name, suggestion="redact the PII before sending, or send to an approved address")
