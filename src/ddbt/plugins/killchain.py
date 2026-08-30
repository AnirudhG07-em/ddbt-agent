"""killchain — correlate single-step signals into a multi-stage attack, the Holmes (S&P'19) pattern.

The other plugins judge one step. But an attack is a PROGRESSION: read a secret (Credential Access),
base64 it (Defense Evasion), POST it out (Exfiltration). Each step alone may only warrant ALLOW/ASK;
the SEQUENCE is the attack. Holmes' contribution over per-call signatures is to correlate them along
the ATT&CK kill chain and fire on the correlated scenario, not the individual event.

This plugin is deliberately SCOPED to one thing: slow-poisoning data EXFILTRATION, and it is checked
ONLY at a NETWORK SEND. That is the design: `observe()` quietly records, on EVERY step, whether that
step touched sensitive data (credential-access / collection) — but the whole-session look-back that
decides "is this a chain?" runs ONLY when the CURRENT command is an external network send (curl/scp/
POST/…). A send is the one moment data can actually leave, so it's the only moment worth correlating
the history. On any non-network command this plugin does nothing at all — no history scan — and the
per-step plugins (destructive, mitre, pii, provenance, …) handle those exactly as usual.

The firing rule, from the data-exfiltration methodology (mindpointgroup.com/blog/conducting-and-
detecting-data-exfiltration): at a network send to an EXTERNAL destination, look back — if sensitive
data was ACCESSED earlier this session, the send completes an exfiltration chain → DENY. If nothing
sensitive was accessed, or the destination is trusted, it's an ordinary request → silent. So `cat .env`
then `curl evil.com` is stopped; `ls; cat notes; curl github.com` is not.
"""

from __future__ import annotations

import json
import re

from ddbt.core.ledger import EGRESS, destinations, flatten, is_external
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

_KEY = "killchain_stages"

# A step "touches sensitive data" when it reads a secret/credential or stages data for collection.
_SENS = re.compile(r"\.env\b|\.env\.|id_rsa|/\.ssh/|/\.aws/|/\.gnupg/|credential|\bsecret\b|\.pem\b|\.key\b|"
                   r"private[_-]?key|/etc/shadow|password|\btoken\b|api[_-]?key|mimikatz|lazagne|"
                   r"\bdump\b|select\s+\*|\btar\s+-c|\bzip\s+-r|screencapture|keylog|mailbox", re.I)


def _basename(tok: str) -> str:
    return tok.rsplit("/", 1)[-1].strip("'\"")


def _file_refs(text: str) -> set[str]:
    """Files this command READS/SENDS (by basename): curl `@file` bodies, `-T`/`-o` targets, and scp/rsync
    source paths. Basenames make the match robust to differing paths for the same file."""
    refs: set[str] = set()
    for m in re.finditer(r"@([^\s'\";|>&]+)", text):                       # curl -d @f, -F x=@f, --data-binary @f
        refs.add(_basename(m.group(1)))
    for m in re.finditer(r"(?:-T|--upload-file|-o|--output)\s+@?([^\s'\";|>&]+)", text):
        refs.add(_basename(m.group(1)))
    if re.search(r"\b(scp|rsync|sftp)\b", text):                            # source file(s), skip host:path dests/flags
        for tok in re.split(r"[\s'\"|;]+", text)[1:]:
            if ":" in tok or tok.startswith("-"):
                continue
            if "/" in tok or re.search(r"\.[A-Za-z0-9]{1,6}$", _basename(tok)):
                refs.add(_basename(tok))
    return {r for r in refs if r and r not in (".", "..")}


def _all_files(text: str) -> set[str]:
    """Every file-ish token in a command (by basename) — used by observe to taint the sensitive files a
    step READS (e.g. `cat .env` → `.env`), which the send-oriented `_file_refs` doesn't capture."""
    files: set[str] = set()
    for tok in re.split(r"[\s'\"|;>&=]+", text):
        tok = tok.lstrip("@")
        if not tok or tok.startswith("-"):
            continue
        base = _basename(tok)
        if ("/" in tok or re.search(r"\.[A-Za-z0-9]{1,6}$", base)) and base not in (".", ".."):
            files.add(base)
    return files


def _outputs(text: str) -> set[str]:
    """Artifacts this command WRITES (by basename): shell redirects and `-o`/`tee` targets. These inherit
    taint when the command touched sensitive data (e.g. `base64 .env > /tmp/b` taints `b`)."""
    outs: set[str] = set()
    for m in re.finditer(r">>?\s*([^\s'\";|&]+)", text):
        outs.add(_basename(m.group(1)))
    for m in re.finditer(r"(?:-o|--output|\btee)\s+([^\s'\";|>&]+)", text):
        outs.add(_basename(m.group(1)))
    return {o for o in outs if o and o not in (".", "..")}


class KillChain(Plugin):
    name = "killchain"
    headline = "These steps together look like a multi-stage attack."

    def __init__(self, trusted_domains: tuple[str, ...] = ()):
        self.trusted = tuple(d.lower() for d in trusted_domains)

    def _external_egress(self, tool: str, text: str) -> bool:
        if not (EGRESS.search(tool) or EGRESS.search(text)):
            return False
        dests = destinations(text)
        return (not dests) or any(is_external(d, self.trusted) for d in dests)

    def _load(self, ctx: PluginContext) -> list[str]:
        if ctx.store is None:
            return []
        try:
            return list(json.loads(ctx.store.get_meta(_KEY) or "[]"))
        except (ValueError, TypeError):
            return []

    def observe(self, tool: str, args: dict, result, ctx: PluginContext) -> None:
        if ctx.store is None:
            return
        text = f"{flatten(args)} {flatten(result)}"
        taint = set(self._load(ctx))
        # A step is tainted if it touches sensitive data directly, OR reads an already-tainted artifact.
        if _SENS.search(text) or (_all_files(text) & taint):
            if _SENS.search(text):
                taint |= _all_files(text)     # the sensitive files it reads are now tainted (cat .env → .env)
            taint |= _outputs(text)           # …and anything derived from this step (base64 .env > /tmp/b)
            ctx.store.set_meta(_KEY, json.dumps(sorted(taint)[-128:]))

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        text = flatten(args)
        # SCOPE GATE: the slow-exfil check runs ONLY at an external network send — the one moment data can
        # actually leave. Not a network send (or a send to a trusted host) → do nothing.
        if not self._external_egress(tool, text):
            return None
        # It IS an external send. Fire ONLY if THIS send carries data that was accessed/staged earlier —
        # i.e. it references a TAINTED artifact. Uploading an unrelated benign file (apple.jpg) after
        # having read a secret earlier is NOT exfiltration, so it is left alone. `_load` holds taint from
        # EARLIER steps only (observe runs after this pre_check).
        leaked = _file_refs(text) & set(self._load(ctx))
        if not leaked:
            return None
        names = ", ".join(sorted(leaked))
        return PreVerdict("deny", f"completes a data-exfiltration sequence — {names} was read or staged from "
                          f"sensitive data earlier this session, and this command sends it to an external "
                          f"destination", self.name, tactic="exfiltration")
