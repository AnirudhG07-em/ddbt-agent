"""AgentDojo tool classification (the adapter's structural mapping).

AgentDojo's suites use domain tools (``send_money``, ``post_webpage``, ``read_email``,
``share_file`` …), not Claude Code's Read/Write/Bash. This module maps each to a
content-blind :class:`StructuralAction` so the *same* engine pipeline decides. The
core security move is unchanged: an outbound/sink tool whose destination identifier
(recipient email, URL, IBAN, channel) was not named in the user task is out-of-envelope.

`extract_identifiers` is used in BOTH places that must agree: seeding the envelope from
the (trusted) user task, and reading destination identifiers out of a tool call's args.
"""

from __future__ import annotations

import json
import re

from ddbt.policy.classifier import StructuralAction, Target, ToolClass
from ddbt.policy.defaults import Policy

# verbs that make a tool an outbound sink (data leaves to a destination)
_SINK_HINTS = (
    "send", "post", "share", "publish", "transfer", "pay", "invite", "forward",
    "message", "email", "dm", "tweet", "upload", "schedule_transaction", "add_user",
    "reserve", "book", "make_reservation", "create_calendar_event", "comment",
)
# verbs whose result is externally-influenceable content (carries injections)
_UNTRUSTED_READ_HINTS = (
    "webpage", "web", "email", "inbox", "channel", "message", "review", "comment",
    "issue", "ticket", "feed", "search_web",
)
_READ_HINTS = ("read", "get", "search", "list", "show", "check", "find", "view")

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL_RE = re.compile(r"https?://([^/\s'\"]+)", re.IGNORECASE)
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{8,30}\b")
_HANDLE_RE = re.compile(r"(?<![\w])@([\w.-]{2,})")


def extract_identifiers(text: str) -> list[str]:
    """Pull destination identifiers (emails, URL hosts, IBANs, @handles) from text."""
    out: list[str] = []
    for m in _EMAIL_RE.finditer(text):
        out.append(m.group(0).lower())
    for m in _URL_RE.finditer(text):
        out.append(m.group(1).split(":")[0].lower())
    for m in _IBAN_RE.finditer(text):
        out.append(m.group(0))
    for m in _HANDLE_RE.finditer(text):
        out.append("@" + m.group(1).lower())
    # de-dupe preserving order
    seen: set[str] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


def _is_sink(name: str) -> bool:
    return any(h in name for h in _SINK_HINTS)


def _is_untrusted_read(name: str) -> bool:
    return any(h in name for h in _UNTRUSTED_READ_HINTS)


def classify_agentdojo(tool_name: str, tool_input: dict, policy: Policy) -> StructuralAction:
    name = tool_name.lower()
    args_text = json.dumps(tool_input or {}, default=str)

    if _is_sink(name):
        targets = [Target("domain", ident) for ident in extract_identifiers(args_text)]
        return StructuralAction(
            tool_name=tool_name,
            tool_class=ToolClass.ACTION,
            op="send",
            targets=targets,
            is_outbound=True,
            dangerous_ops={"send"},
            summary=f"{tool_name}->{','.join(t.value for t in targets) or '?'}",
        )

    if any(h in name for h in _READ_HINTS):
        cls = ToolClass.UNTRUSTED_RETRIEVAL if _is_untrusted_read(name) else ToolClass.TRUSTED_RETRIEVAL
        return StructuralAction(tool_name, cls, op="fetch", summary=f"{tool_name}:read")

    if "delete" in name or "remove" in name or "cancel" in name:
        return StructuralAction(
            tool_name, ToolClass.ACTION, op="delete", dangerous_ops={"delete"}, summary=f"{tool_name}:delete"
        )

    # unknown verb → conservative action (engine tends to escalate, safe-direction)
    return StructuralAction(tool_name, ToolClass.ACTION, op="exec", summary=f"{tool_name}:action")
