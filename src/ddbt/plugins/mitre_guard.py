"""MITRE-mapped detection signatures — a deep, deterministic library of known-bad action patterns.

The industry way to broaden coverage without hurting precision is signature detection mapped to MITRE
ATT&CK (cf. Sigma rules, MITRE ATLAS). Each signature is a SPECIFIC pattern for one technique, so it
rarely fires on benign actions (precision) while adding a whole tactic of coverage (recall). It runs
after shell-deobfuscation, so obfuscated commands are matched in the clear. Each hit denies with a
MITRE-labelled reason: "<Tactic> (<technique>)".

Verdict: "deny" for unambiguously malicious techniques; "ask" for high-impact-but-context-dependent
ones (a human confirms). Extend by adding a row — that's the whole point.
"""

from __future__ import annotations

import re

from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

_KEYS = ("command", "cmd", "script", "code", "sql", "query", "action", "value", "body", "instruction")

# (regex, tactic, technique, verdict, short-why)
_SIGS: list[tuple[re.Pattern, str, str, str, str]] = [
    # --- Defense Evasion (TA0005) ---
    (re.compile(r"\b(ufw\s+disable|iptables\s+-F|systemctl\s+(stop|disable)\s+\w*(firewall|firewalld)|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off)\b", re.I),
     "Defense Evasion", "T1562 Impair Defenses (firewall)", "deny", "disables the firewall"),
    (re.compile(r"\b(setenforce\s+0|disable\s+selinux|systemctl\s+(stop|disable)\s+\w*(defender|clamav|falcon|crowdstrike)|Set-MpPreference\s+-DisableRealtimeMonitoring)\b", re.I),
     "Defense Evasion", "T1562 Impair Defenses (AV/EDR)", "deny", "disables antivirus/EDR"),
    (re.compile(r"\b(history\s+-c|unset\s+HISTFILE|rm\s+.*/var/log|truncate\s+-s\s*0\s+.*log|journalctl\s+--vacuum|wevtutil\s+cl)\b", re.I),
     "Defense Evasion", "T1070 Indicator Removal (clear logs)", "deny", "clears logs to cover tracks"),
    (re.compile(r"\b(vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no|delete\s+all\s+snapshots|rm\s+.*(backup|snapshot))\b", re.I),
     "Defense Evasion", "T1490 Inhibit System Recovery", "deny", "deletes backups/snapshots"),
    # --- Privilege Escalation (TA0004) ---
    (re.compile(r"\b(chmod\s+[ug]\+s|chmod\s+[0-7]*4[0-7]{3}|echo\s+.*ALL.*NOPASSWD.*sudoers|>>\s*/etc/sudoers|usermod\s+-aG\s+(sudo|admin|wheel|docker))\b", re.I),
     "Privilege Escalation", "T1548 Abuse Elevation", "deny", "grants itself elevated privileges"),
    # --- Persistence (TA0003) ---
    (re.compile(r"authorized_keys|\bcrontab\s+-|/etc/cron|systemctl\s+enable|New-Service|schtasks\s+/create|LaunchDaemons", re.I),
     "Persistence", "T1543/T1053 Service/Scheduled Task", "ask", "installs a persistence mechanism"),
    # --- Command and Control (TA0011) ---
    (re.compile(r"(bash\s+-i\s*>&?\s*/dev/tcp|nc\s+.*-e\s|ncat\s+.*-e\s|python.*pty\.spawn|/dev/tcp/\d|\bngrok\b)", re.I),
     "Command and Control", "T1059 Reverse Shell", "deny", "opens a reverse shell / tunnel"),
    # --- Impact (TA0040) ---
    (re.compile(r"\b(xmrig|minerd|stratum\+tcp|cgminer|ethminer|coinhive)\b", re.I),
     "Impact", "T1496 Resource Hijacking (miner)", "deny", "runs a cryptocurrency miner"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;|\bshred\s+-|\bcipher\s+/w|mkfs\.|dd\s+.*of=/dev/", re.I),
     "Impact", "T1485/T1561 Destruction/Wipe", "deny", "wipes data or a disk"),
    # --- Collection / surveillance (TA0009) ---
    (re.compile(r"\b(screencapture|import\s+-window|/dev/video|/dev/audio|ffmpeg.*(-f\s+(avfoundation|v4l2|alsa))|keylog|pynput|xdotool\s+key)\b", re.I),
     "Collection", "T1113/T1123/T1056 Screen/Audio/Input Capture", "deny", "covertly captures screen/mic/keystrokes"),
    # --- Credential Access (TA0006) ---
    (re.compile(r"\b(mimikatz|lazagne|/etc/shadow|gcloud\s+auth\s+print|aws\s+configure\s+get\s+aws_secret|cat\s+.*(\.ssh/id_|\.aws/credentials|\.env))\b", re.I),
     "Credential Access", "T1552 Unsecured Credentials", "deny", "reads stored credentials/secrets"),
    # --- Exfiltration (TA0010) ---
    (re.compile(r"\b(curl|wget)\b[^|;&]*(-d\s*@|--data-binary\s*@|-T\s)[^|;&]*https?://|transfer\.sh|pastebin\.com|\|\s*(nc|ncat)\s", re.I),
     "Exfiltration", "T1567 Exfil Over Web Service", "deny", "sends file contents to an external service"),
    # --- Initial Access / Supply Chain (TA0001) ---
    (re.compile(r"\b(npm\s+publish|pip.*upload|twine\s+upload|curl\s+.*\|\s*(sudo\s+)?(ba)?sh)\b", re.I),
     "Initial Access", "T1195 Supply Chain / remote-exec", "ask", "publishes a package or pipes remote code to a shell"),
]


def _text(args) -> str:
    if isinstance(args, dict):
        return " ".join(str(args[k]) for k in _KEYS if isinstance(args.get(k), str)) or \
               " ".join(str(v) for v in args.values() if isinstance(v, str))
    return str(args)


class MitreGuard(Plugin):
    name = "mitre_guard"

    def _match(self, args) -> tuple | None:
        blob = _text(args)
        for pat, tactic, tech, verdict, why in _SIGS:
            if pat.search(blob):
                return tactic, tech, verdict, why
        return None

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        hit = self._match(args)
        if not hit:
            return None
        tactic, tech, verdict, why = hit
        return PreVerdict(verdict, f"{tactic} ({tech}) · {why}", self.name)
