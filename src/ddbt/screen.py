"""Screen arbitrary TEXT for sensitive content and get a model-safe, redacted copy.

`Guard.check()` decides whether a tool CALL may run (what the agent SENDS). `screen()` is the other
direction — inspect tool OUTPUT (or any text) BEFORE it reaches the LLM (what the model SEES). That's
the piece a shell-with-an-LLM (Warp-style) needs: run `cat .env`, then `screen` the output so the raw
secret never enters the model's context — redact it, or ask a human first.

Deterministic and LLM-free: secret patterns (API keys, private keys, tokens) + PII (Presidio if
installed, else regex). Returns what was found, a redacted copy, and an `effect` ('ask' if sensitive)
so the caller can gate before showing anything to the model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ddbt.core.ledger import SECRET_VALUE

# Any assignment whose NAME looks secret (…KEY / …SECRET / …TOKEN / PASSWORD / CREDENTIAL / …AUTH) →
# redact its VALUE. Broader than the shared SECRET_VALUE shapes, which is right for OUTPUT screening
# (masking is non-destructive), and catches the common `AWS_SECRET_ACCESS_KEY=…`, `DB_PASSWORD=…` forms.
_ENV_SECRET = re.compile(
    r"([A-Za-z0-9_.\-]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|API[_-]?KEY|AUTH)"
    r"[A-Za-z0-9_.\-]*\s*[=:]\s*)([^\s\"']+)", re.I)


@dataclass
class Screen:
    sensitive: bool                              # did we find secrets / PII?
    redacted: str                                # the text with sensitive spans masked — safe for the LLM
    findings: list[str] = field(default_factory=list)   # kinds found, e.g. ["SECRET", "EMAIL", "US_SSN"]
    reason: str = ""

    @property
    def effect(self) -> str:
        """'ask' when sensitive (gate before the model sees it), else 'allow'. The ASK layer you wanted."""
        return "ask" if self.sensitive else "allow"


_PII = None


def _pii():
    global _PII
    if _PII is None:
        from ddbt.plugins.pii_dlp import PiiDlp
        _PII = PiiDlp()
    return _PII


def screen_text(text: str) -> Screen:
    """Detect + redact secrets and PII in `text`. Never raises; degrades to secrets-only if PII deps
    are missing. Reusable without a Guard: `from ddbt import screen_text`."""
    text = str(text)
    findings: list[str] = []
    redacted = text
    if _ENV_SECRET.search(redacted):             # NAME_SECRET=value / DB_PASSWORD=value assignments
        findings.append("SECRET")
        redacted = _ENV_SECRET.sub(lambda m: m.group(1) + "<SECRET_REDACTED>", redacted)
    if SECRET_VALUE.search(redacted):            # standalone API keys / private keys / tokens (AKIA, sk-…)
        findings.append("SECRET")
        redacted = SECRET_VALUE.sub("<SECRET_REDACTED>", redacted)
    try:
        p = _pii()
        pii = p._detect(text)
        if pii:
            findings += sorted(set(pii))
            redacted = p._redact_text(redacted)
    except Exception:  # noqa: BLE001 — PII detection is best-effort; secrets still get masked
        pass
    sensitive = bool(findings)
    kinds = ", ".join(sorted(set(findings))[:5])
    return Screen(sensitive, redacted, sorted(set(findings)),
                  f"contains sensitive data ({kinds})" if sensitive else "no sensitive data detected")
