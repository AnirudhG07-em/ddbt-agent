"""Capability ticket — the agent's OWN scoped credentials, enforced by CODE, not the judge.

The agent acts on your behalf but does NOT get your account. A user-authored grant bounds which
tools it may call, which destinations it may reach, which paths are off-limits, how many
high-impact actions, and for how long. Every check is deterministic policy + arithmetic — a
stranger who talked the agent into anything still can't exceed the ticket (SAGA, arXiv:2504.21034).

Three outcomes, all before the judge runs:
  DENY  — out of scope (tool/destination/path/quota/expiry). The hard floor. No model call.
  ALLOW — provably safe and in scope (a read, no egress). The fast path. No model call.
  DEFER — in scope but consequential → hand to the step-judge.

The policy is expressed per RESOURCE, each with an ``allow`` and a ``deny`` list, so blocking is
symmetric with granting — you can deny a mail domain, a host, or a tool as easily as allowing one.
Two schemas load transparently (see :meth:`Grant.from_dict`):
  * nested (preferred, what ddbt.json writes):  {"tools": {"allow": [...], "deny": [...]},
    "files": {"deny": [...]}, "email": {"allow": [...], "deny": [...]}, "web": {...}, "quotas": {}}
  * flat legacy (old .ddbt/grant.json):  {"tools": [...], "deny_paths": [...],
    "allow_email_domains": [...], "allow_hosts": [...], "quotas": {}}
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://([^/\s:'\"]+)")

# Tools whose only effect is to pull data back into the agent's own (quarantined) context.
# A read cannot leak on its own, so it is safe to fast-path without the judge.
_READ_ONLY = {"Read", "Grep", "Glob", "LS", "NotebookRead"}
_READ_ONLY_MCP = re.compile(r"^mcp__[^_]+__.*(list|get|search|read|fetch|describe|show|find)", re.I)


@dataclass(slots=True)
class GrantCheck:
    effect: str  # "allow" | "deny" | "defer"
    reason: str
    quota_key: str | None = None  # if set, a quota'd tool — engine debits it when the call runs


def _section(d: dict, key: str, legacy_allow: str | None = None, legacy_deny: str | None = None):
    """Pull (allow, deny) for one resource, accepting either schema.

    Nested:  d[key] is a dict → its "allow"/"deny" lists.
    Legacy:  d[key] is a bare list → treat as the allow-list; deny comes from `legacy_deny`.
    Absent:  fall back to the flat legacy top-level keys.
    """
    v = d.get(key)
    if isinstance(v, dict):
        return list(v.get("allow", [])), list(v.get("deny", []))
    allow = list(v) if isinstance(v, list) else list(d.get(legacy_allow, []) if legacy_allow else [])
    deny = list(d.get(legacy_deny, []) if legacy_deny else [])
    return allow, deny


def _lower(xs) -> list[str]:
    return [str(x).lower() for x in (xs or [])]


@dataclass(slots=True)
class Grant:
    """A user-authored scope for one agent session. An empty allow-list means 'no allow-limit of
    that kind'; a deny-list always subtracts. The one always-on rule is file `deny` (secrets stay
    off-limits). Deny wins over allow wherever both could match."""

    tools: list[str] = field(default_factory=list)           # allowed tool globs; [] = any tool
    deny_tools: list[str] = field(default_factory=list)       # tool globs never permitted
    deny_paths: list[str] = field(default_factory=list)       # paths never touched (e.g. "~/.ssh/*")
    allow_email_domains: list[str] = field(default_factory=list)  # sends only to these; [] = any
    deny_email_domains: list[str] = field(default_factory=list)   # never mail these domains
    allow_hosts: list[str] = field(default_factory=list)     # URLs only to these hosts; [] = any
    deny_hosts: list[str] = field(default_factory=list)      # never reach these hosts
    quotas: dict = field(default_factory=dict)               # tool-glob -> max high-impact calls
    ttl_seconds: int = 0                                     # 0 = no expiry
    issued_at: float = 0.0
    fast_path_reads: bool = True                             # allow safe reads with no judge call
    label: str = "session grant"

    @classmethod
    def from_dict(cls, d: dict, now: float = 0.0) -> "Grant":
        tools_allow, tools_deny = _section(d, "tools", legacy_allow="tools", legacy_deny="deny_tools")
        email_allow, email_deny = _section(d, "email", legacy_allow="allow_email_domains",
                                           legacy_deny="deny_email_domains")
        host_allow, host_deny = _section(d, "web", legacy_allow="allow_hosts", legacy_deny="deny_hosts")
        files = d.get("files")
        # paths are case-sensitive globs → keep original case (don't route through _section/_lower)
        deny_paths = list(files.get("deny", [])) if isinstance(files, dict) else list(d.get("deny_paths", []))
        g = cls(
            tools=tools_allow,          # original case kept for display; matched case-insensitively
            deny_tools=tools_deny,
            deny_paths=deny_paths,
            allow_email_domains=_lower(email_allow),  # domains/hosts are case-insensitive
            deny_email_domains=_lower(email_deny),
            allow_hosts=_lower(host_allow),
            deny_hosts=_lower(host_deny),
            quotas=dict(d.get("quotas", {})),
            ttl_seconds=int(d.get("ttl_seconds", 0)),
            fast_path_reads=bool(d.get("fast_path_reads", True)),
            label=str(d.get("label", "session grant")),
        )
        g.issued_at = float(d.get("issued_at") or now)
        return g

    # ---- the check (deterministic) ----

    def check(self, tool: str, args: dict, now: float, used: dict | None = None) -> GrantCheck:
        used = used or {}
        strings = _strings(args)
        tool_l = tool.lower()

        # 1. expiry — a stale ticket grants nothing
        if self.ttl_seconds and self.issued_at and now - self.issued_at > self.ttl_seconds:
            return GrantCheck("deny", f"grant expired ({int(now - self.issued_at)}s > {self.ttl_seconds}s TTL)")

        # 2. tool scope — deny-list wins, then the allow-list must admit it (case-insensitive)
        if any(fnmatch.fnmatch(tool_l, pat.lower()) for pat in self.deny_tools):
            return GrantCheck("deny", f"tool '{tool}' is denied by this agent's grant")
        if self.tools and not any(fnmatch.fnmatch(tool_l, pat.lower()) for pat in self.tools):
            return GrantCheck("deny", f"tool '{tool}' is not in this agent's grant")

        # 3. secret / forbidden paths — always on, the one non-negotiable
        hit = _first_path_hit(strings, self.deny_paths)
        if hit:
            return GrantCheck("deny", f"grant forbids touching {hit}")

        # 4. destinations — deny-list wins, then the allow-list must admit it (only when present)
        for dom in _email_domains(strings):
            if dom in self.deny_email_domains:
                return GrantCheck("deny", f"email to '{dom}' is denied by the grant")
            if self.allow_email_domains and dom not in self.allow_email_domains:
                return GrantCheck("deny", f"email to '{dom}' is outside the grant "
                                          f"(allowed: {', '.join(self.allow_email_domains)})")
        for host in _url_hosts(strings):
            if host in self.deny_hosts:
                return GrantCheck("deny", f"host '{host}' is denied by the grant")
            if self.allow_hosts and host not in self.allow_hosts:
                return GrantCheck("deny", f"request to host '{host}' is outside the grant "
                                          f"(allowed: {', '.join(self.allow_hosts)})")

        # 5. quota — a spent budget denies before the judge is consulted
        qkey = next((pat for pat in self.quotas if fnmatch.fnmatch(tool, pat)), None)
        if qkey is not None:
            cap = int(self.quotas[qkey])
            spent = int(used.get(qkey, 0))
            if spent >= cap:
                return GrantCheck("deny", f"grant quota for '{qkey}' is spent ({spent}/{cap})", qkey)

        # 6. fast path — a safe read, in scope, no egress → allow with no model call
        if self.fast_path_reads and _is_read_only(tool) and not _email_domains(strings) and not _url_hosts(strings):
            return GrantCheck("allow", "read-only, in scope, no egress → fast-path (no judge call)", qkey)

        # 7. in scope but consequential → let the judge decide
        return GrantCheck("defer", "in scope; consequential → judged", qkey)

    def describe(self) -> str:
        bits = []
        if self.tools:
            bits.append(f"tools={','.join(self.tools)}")
        if self.deny_tools:
            bits.append(f"!tools={','.join(self.deny_tools)}")
        if self.allow_email_domains:
            bits.append(f"email→{','.join(self.allow_email_domains)}")
        if self.deny_email_domains:
            bits.append(f"!email={','.join(self.deny_email_domains)}")
        if self.allow_hosts:
            bits.append(f"hosts→{','.join(self.allow_hosts)}")
        if self.deny_hosts:
            bits.append(f"!hosts={','.join(self.deny_hosts)}")
        if self.quotas:
            bits.append("quota=" + ",".join(f"{k}:{v}" for k, v in self.quotas.items()))
        if self.deny_paths:
            bits.append(f"never={','.join(self.deny_paths)}")
        if self.ttl_seconds:
            bits.append(f"ttl={self.ttl_seconds}s")
        return " · ".join(bits) or "unrestricted"


# ---- helpers (module-level, pure) ----


def _strings(obj) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_strings(v))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_strings(v))
    return out


def _is_read_only(tool: str) -> bool:
    return tool in _READ_ONLY or bool(_READ_ONLY_MCP.match(tool))


def _email_domains(strings: list[str]) -> list[str]:
    out = []
    for s in strings:
        out.extend(m.lower() for m in _EMAIL.findall(s))
    return out


def _url_hosts(strings: list[str]) -> list[str]:
    out = []
    for s in strings:
        out.extend(m.lower() for m in _URL.findall(s))
    return out


def _first_path_hit(strings: list[str], deny_paths: list[str]) -> str | None:
    """The offending path token if any arg trips a deny rule, else None. Matches two ways — to
    catch a bare path arg and a path buried in a shell command: fnmatch on split tokens, plus a
    substring test on the rule's core ('~/.ssh/*' → '.ssh', '**/id_rsa*' → 'id_rsa')."""
    for raw in strings:
        low = raw.lower()
        tokens = re.split(r"[\s@='\"]+", raw)
        for pat in deny_paths:
            core = pat.replace("*", "").replace("~", "").strip("/").lower()
            if core and core in low:
                return pat
            if any(fnmatch.fnmatch(t, pat) or fnmatch.fnmatch(t, "*" + pat.lstrip("*")) for t in tokens if t):
                return pat
    return None
