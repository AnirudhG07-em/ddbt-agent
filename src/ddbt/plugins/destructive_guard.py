"""Destructive-command guard — a deterministic hard-deny for catastrophic, irreversible commands,
with a safer-alternative suggestion (SafeFix pattern from AgentTrust / Destructive Command Guard).

These are bad in every workspace and shouldn't wait on the judge: `rm -rf /`, `DROP DATABASE`,
`git push --force` to a protected ref, `mkfs`, `dd of=/dev/…`, `chmod 777 -R /`, curl-pipe-to-shell.
The plugin DENYs and hands back a safer form so the agent can self-correct rather than just being
refused. Patterns are conservative (aimed at clearly-catastrophic forms) to keep false positives low;
workspace-specific "don't do X" belongs in ddbt.json `behaviors`, not here.
"""

from __future__ import annotations

import re

from ddbt.core.ledger import MAX_SCAN_CHARS
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

# (pattern, human reason, safer suggestion or None)
_RULES: list[tuple[re.Pattern, str, str | None]] = [
    (re.compile(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(/|~|\$HOME|\*)(\s|$)", re.I),
     "recursive force-delete of a root/home/glob path", "scope the delete to a specific project path"),
    (re.compile(r"\b(mkfs|fdisk|dd)\b.*\bof=/dev/", re.I),
     "writes directly to a block device (data destruction)", None),
    (re.compile(r"\bDROP\s+(DATABASE|SCHEMA)\b", re.I),
     "drops an entire database/schema", "back up first, or drop a specific table with a WHERE-scoped migration"),
    (re.compile(r"\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\b[^;]{0,2000}\b(WHERE\s+1\s*=\s*1|$)", re.I),
     "deletes all rows from a table", "add a specific WHERE clause and take a backup"),
    (re.compile(r"\bgit\s+push\b.*(--force|-f)\b", re.I),
     "force-push rewrites shared history", "push without --force, or use --force-with-lease on a personal branch"),
    (re.compile(r"\bchmod\s+-R?\s*777\b", re.I),
     "world-writable permissions", "use 755 for dirs / 644 for files"),
    (re.compile(r"\bcurl\b[^|]{0,2000}\|\s*(sudo\s+)?(ba)?sh\b|\bwget\b[^|]{0,2000}\|\s*(ba)?sh\b", re.I),
     "pipes a remote script straight into a shell", "download first, inspect, then run: curl -o s.sh URL && cat s.sh && bash s.sh"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;", ),
     "fork bomb", None),
]

_TEXT_KEYS = ("command", "cmd", "script", "code", "sql", "query", "value")


def _text(args: dict) -> str:
    if not isinstance(args, dict):
        return str(args)[:MAX_SCAN_CHARS]
    return " ".join(str(args[k]) for k in _TEXT_KEYS if isinstance(args.get(k), str))[:MAX_SCAN_CHARS]


class DestructiveGuard(Plugin):
    name = "destructive_guard"
    headline = "This command could irreversibly destroy data."

    def _match(self, args: dict):
        blob = _text(args)
        for pat, reason, fix in _RULES:
            if pat.search(blob):
                return reason, fix
        return None

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        hit = self._match(args)
        if hit:
            reason, fix = hit
            return PreVerdict("deny", f"destructive command: {reason}", self.name, suggestion=fix)
        return None

    def suggest(self, tool: str, args: dict) -> str | None:
        hit = self._match(args)
        return hit[1] if hit else None
