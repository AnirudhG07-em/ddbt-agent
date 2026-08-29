"""killchain — correlate single-step signals into a multi-stage attack, the Holmes (S&P'19) pattern.

The other plugins judge one step. But an attack is a PROGRESSION: read a secret (Credential Access),
base64 it (Defense Evasion), POST it out (Exfiltration). Each step alone may only warrant ALLOW/ASK;
the SEQUENCE is the attack. Holmes' contribution over per-call signatures is to correlate them along
the ATT&CK kill chain and fire on the correlated scenario, not the individual event.

This plugin keeps a per-session, ordered list of the ATT&CK TACTICS reached (coarse detectors — the
precise technique signatures are mitre_guard's job). Its ONE firing rule, taken straight from the
data-exfiltration methodology (mindpointgroup.com/blog/conducting-and-detecting-data-exfiltration):
a chain is only real once sensitive data was actually ACCESSED (credential-access / collection) — mere
recon or cleanup is NOT a chain. Given real data access, a step that then SENDS to an external
destination is exfiltration → DENY; a fuller multi-stage progression into another terminal tactic
(destroy / C2 / persistence) → DENY. Everything else stays silent. This is deliberately conservative:
without a prior data-access stage AND a terminal action, the plugin never fires, so an ordinary run of
varied commands (ls, cat notes, git status, a couple of curls to trusted hosts) is never a "kill chain".
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
# A chain needs proof that sensitive data was actually TOUCHED (accessed or staged), not just recon.
_DATA_ACCESS = {"credential_access", "collection"}   # read a secret / staged data to send
_WEAK = {"discovery", "defense_evasion"}             # recon or cleanup — supporting only, never enough alone
_TERMINAL = {"exfiltration", "impact", "command_and_control", "persistence"}


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
        cur = _stages(tool, text, self._external_egress(tool, text))
        term = cur & _TERMINAL
        if not term:
            return None                     # not a terminal action → no chain to complete yet
        # `_load` holds only stages from EARLIER steps (observe runs after this pre_check), so it is
        # exactly the prior history — don't subtract the current step, or a terminal that also happens
        # to name a secret (e.g. `curl -d @.env …`) would erase the real earlier access that precedes it.
        history = self._load(ctx)
        data_prior = [s for s in history if s in _DATA_ACCESS]
        weak_prior = [s for s in history if s in _WEAK]
        # THE gate: no earlier step actually accessed sensitive data → this is not a chain. This is
        # what stops a run of varied commands (recon, cleanup, a destructive step) from reading as an
        # attack. Exfiltration in particular requires that data was accessed AND is now being sent out.
        if not data_prior:
            return None
        chain = " → ".join(data_prior + weak_prior + sorted(term))
        if "exfiltration" in term:
            return PreVerdict("deny", f"completes a data-exfiltration sequence · {chain} — sensitive data "
                              f"was accessed earlier and this step sends it to an external destination",
                              self.name, tactic="exfiltration")
        # A non-exfil terminal (destroy / C2 / persistence) is a chain only with a fuller progression.
        if len(data_prior) + len(weak_prior) >= 2:
            return PreVerdict("deny", f"is part of a multi-stage attack · {chain} — steps that are "
                              f"innocuous alone but together complete an attack", self.name)
        return None
