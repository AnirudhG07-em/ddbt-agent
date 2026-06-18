"""Tool classification + structural extraction (doc §4, §5).

This module turns a raw ``(tool_name, tool_input)`` into a :class:`StructuralAction`
— *typed facts about the action*: its class, the operation kind, the paths/domains
it targets, whether it leaves the system, and which dangerous ops it performs.

What we deliberately do **not** do: let the untrusted *values* (a fetched web page's
prose, a file's contents) influence anything. We parse a path or a URL out of the
arguments because a path/domain is *structural metadata* (doc §5: "target path/domain"
is explicitly an allowed input to the judge). We never parse meaning out of content.
The Bash command string is the agent's own directive (structure), not third-party
data, so extracting "this runs ``rm`` against ``~``" is structural, not content-reading.
"""

from __future__ import annotations

import enum
import re
import shlex
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ddbt.policy.defaults import Policy


class ToolClass(enum.Enum):
    """Doc §4 tool taxonomy, plus PURE for no-system-effect tools."""

    TRUSTED_RETRIEVAL = "trusted_retrieval"  # first-party reads: in-scope file, owned git
    UNTRUSTED_RETRIEVAL = "untrusted_retrieval"  # externally influenceable: web, email, issue
    ACTION = "action"  # externally observable effects: write, send, exec, push
    PURE = "pure"  # no system effect (e.g. TodoWrite) — never reaches checkpoint 2


@dataclass(frozen=True, slots=True)
class Target:
    """A structural target of an action. ``kind`` ∈ {"path", "domain"}."""

    kind: str
    value: str


@dataclass(slots=True)
class StructuralAction:
    """Content-blind, typed description of a proposed action (the judge's left-hand side)."""

    tool_name: str
    tool_class: ToolClass
    op: str  # "read" | "write" | "delete" | "send" | "exec" | "fetch" | "noop"
    targets: list[Target] = field(default_factory=list)
    is_outbound: bool = False  # data leaves the system (network / send)
    dangerous_ops: set[str] = field(default_factory=set)  # subset of Policy.dangerous_ops
    summary: str = ""  # short structural summary for the audit log (no untrusted content)

    @property
    def paths(self) -> list[str]:
        return [t.value for t in self.targets if t.kind == "path"]

    @property
    def domains(self) -> list[str]:
        return [t.value for t in self.targets if t.kind == "domain"]


# ---- domain / url extraction -------------------------------------------------

_URL_RE = re.compile(r"\b(?:https?://|ftp://)([^/\s'\"]+)", re.IGNORECASE)
# bare host in args like `scp x host:/p`, `nc host port`. The negative lookbehind keeps us
# from matching a hostname embedded inside a file path (…/notes.txt) or token.
_HOST_RE = re.compile(r"(?<![\w./@-])((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)
# last-label values that mean "this is a filename, not a host"
_FILE_EXTS = frozenset(
    "txt py json md csv log sh yaml yml ini cfg js ts tsx html xml pem key env lock toml "
    "go rs java c cpp h rb php sql pdf png jpg gif zip tar gz".split()
)


def _domains_in(text: str) -> list[str]:
    found: list[str] = []
    for m in _URL_RE.finditer(text):
        found.append(m.group(1).split(":")[0].lower())
    for m in _HOST_RE.finditer(text):
        host = m.group(1).lower()
        if host.rsplit(".", 1)[-1] in _FILE_EXTS:
            continue  # e.g. notes.txt / config.yaml — a filename, not a domain
        if host not in found:
            found.append(host)
    return found


# ---- bash command analysis ---------------------------------------------------

# commands that send data out of the machine
_NET_BINARIES = {"curl", "wget", "nc", "ncat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp"}
_NET_SUBCMDS = {("git", "push"), ("git", "remote")}
# commands that destroy / mutate irreversibly
_DESTRUCTIVE = {
    "rm": "delete",
    "rmdir": "delete",
    "shred": "delete",
    "unlink": "delete",
    "truncate": "truncate",
    "mkfs": "delete",
    "dd": "overwrite",
}


_NON_PATH_CHARS = set("><|*?$`")


def _looks_like_path(tok: str) -> bool:
    """A token is a path target if it has a path separator / ~ and no shell metachars."""
    if tok.startswith("-") or not tok:
        return False
    if "://" in tok:
        return False  # a URL, not a filesystem path (handled as a domain target)
    if any(c in _NON_PATH_CHARS for c in tok):
        return False  # redirect (2>/dev/null), glob (*.py), pipe, var — not a literal path
    return tok.startswith(("/", "~", "../", "./")) or "/" in tok


# curl/wget flags that indicate data is being UPLOADED (a sink), not just fetched
_UPLOAD_FLAGS = ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
                 "-F", "--form", "-T", "--upload-file", "--post-data", "--post-file")
_GET_FETCHERS = {"curl", "wget"}


def _is_data_upload(toks: list[str], command: str) -> bool:
    """True if a curl/wget command sends a body (POST/PUT/upload) rather than a plain GET.

    A read-only GET is retrieval (like WebFetch); only an upload is an outbound sink.
    Command substitution or an @file argument also count — they can smuggle data out.
    """
    if "$(" in command or "`" in command:
        return True
    for i, t in enumerate(toks[1:], 1):
        if t.startswith("@"):
            return True
        if any(t == f or t.startswith(f + "=") for f in _UPLOAD_FLAGS):
            return True
        if t in ("-d", "-F", "-T"):  # short flags take a following value
            return True
        if t == "-X" or t.startswith("--request"):
            nxt = toks[i + 1].upper() if i + 1 < len(toks) else ""
            if nxt in ("POST", "PUT", "DELETE", "PATCH"):
                return True
    return False


def _safe_split(command: str) -> list[list[str]]:
    """Split a shell command into pipeline/##-separated simple commands, best-effort.

    Tokenising can fail on exotic syntax; we degrade to a single opaque token list
    rather than guessing — the caller treats an unparseable destructive command
    conservatively.
    """
    # break on common separators while keeping it simple and deterministic
    segments = re.split(r"&&|\|\||[;|&\n]", command)
    out: list[list[str]] = []
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        try:
            out.append(shlex.split(seg))
        except ValueError:
            out.append(seg.split())
    return out


def _classify_bash(command: str, policy: "Policy") -> StructuralAction:
    segments = _safe_split(command)
    targets: list[Target] = []
    dangerous: set[str] = set()
    is_outbound = False
    fetched = False  # a read-only GET happened (retrieval, not a sink)
    op = "exec"

    for toks in segments:
        if not toks:
            continue
        binary = toks[0].rsplit("/", 1)[-1]
        sub = toks[1] if len(toks) > 1 else ""

        if binary in _NET_BINARIES or (binary, sub) in _NET_SUBCMDS:
            doms = _domains_in(" ".join(toks))
            # a plain GET via curl/wget is retrieval, like WebFetch — NOT an outbound sink
            if binary in _GET_FETCHERS and not _is_data_upload(toks, command):
                fetched = True
                for d in doms:
                    targets.append(Target("domain", d))
            else:
                is_outbound = True
                op = "send"
                for d in doms:
                    targets.append(Target("domain", d))

        if binary in _DESTRUCTIVE:
            kind = _DESTRUCTIVE[binary]
            dangerous.add(kind)
            if op == "exec":
                op = "delete" if kind == "delete" else op
            # for a destructive command, every non-flag arg is a target (even bare
            # filenames without a slash) so the boundary check has something to resolve
            for tok in toks[1:]:
                if not tok.startswith("-"):
                    targets.append(Target("path", tok))  # bare filenames count for rm
        # SQL-ish destructive verbs embedded anywhere in the command
        upper = " ".join(toks).upper()
        for verb in ("DROP TABLE", "DROP DATABASE", "TRUNCATE", "DELETE FROM"):
            if verb in upper:
                dangerous.add("drop")

        # path-looking arguments (absolute, ~, or relative-with-slash) are structural targets.
        # strip curl's @file prefix so the path resolves/labels correctly (-d @/tmp/x)
        for tok in toks[1:]:
            cand = tok[1:] if tok.startswith("@") else tok
            if _looks_like_path(cand):
                targets.append(Target("path", cand))

    # a command whose only network activity was a GET fetch (no send, no destruction) is
    # untrusted retrieval — same class as WebFetch, so it flows freely and taints its result
    pure_fetch = fetched and not is_outbound and not dangerous and op == "exec"
    tool_class = ToolClass.UNTRUSTED_RETRIEVAL if pure_fetch else ToolClass.ACTION
    if pure_fetch:
        op = "fetch"

    summary = f"bash:{op}"
    if dangerous:
        summary += f"[{','.join(sorted(dangerous))}]"
    # de-duplicate targets (a token can match both the destructive and generic branches)
    deduped: list[Target] = []
    seen: set[tuple[str, str]] = set()
    for t in targets:
        key = (t.kind, t.value)
        if key not in seen:
            seen.add(key)
            deduped.append(t)
    return StructuralAction(
        tool_name="Bash",
        tool_class=tool_class,
        op=op,
        targets=deduped,
        is_outbound=is_outbound,
        dangerous_ops=dangerous,
        summary=summary,
    )


# ---- top-level classification ------------------------------------------------


def classify(tool_name: str, tool_input: dict, policy: "Policy") -> StructuralAction:
    """Produce the content-blind StructuralAction for a tool call."""
    name = tool_name

    # MCP tools: mcp__<server>__<tool>. Class is decided by the server's trust.
    if name.startswith("mcp__"):
        parts = name.split("__")
        server = parts[1] if len(parts) > 1 else ""
        cls = (
            ToolClass.TRUSTED_RETRIEVAL
            if server in policy.trusted_mcp_servers
            else ToolClass.UNTRUSTED_RETRIEVAL
        )
        # an MCP tool that names an outbound-ish verb is treated as an action
        if any(k in name.lower() for k in ("send", "post", "publish", "push", "write", "delete")):
            cls = ToolClass.ACTION
        return StructuralAction(name, cls, op="fetch", summary=f"mcp:{server}")

    if name in policy.untrusted_tools:
        url = tool_input.get("url") or tool_input.get("query") or ""
        targets = [Target("domain", d) for d in _domains_in(str(url))]
        return StructuralAction(
            name, ToolClass.UNTRUSTED_RETRIEVAL, op="fetch", targets=targets, summary=f"{name}:fetch"
        )

    if name in policy.pure_tools:
        return StructuralAction(name, ToolClass.PURE, op="noop", summary=f"{name}:noop")

    if name in ("Read", "Glob", "Grep", "LS", "NotebookRead"):
        path = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("pattern") or ""
        targets = [Target("path", str(path))] if path else []
        return StructuralAction(
            name, ToolClass.TRUSTED_RETRIEVAL, op="read", targets=targets, summary=f"{name}:read"
        )

    if name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = tool_input.get("file_path") or tool_input.get("path") or ""
        # No "overwrite" danger tag here: a file edit inside the workspace is the
        # bread-and-butter action and is git-reversible (doc §7.2 pass-through lane).
        # The boundary check (write outside scope) and bash `dd`/`truncate` carry the
        # destructive weight instead — keeping everyday edits frictionless.
        return StructuralAction(
            name,
            ToolClass.ACTION,
            op="write",
            targets=[Target("path", str(path))] if path else [],
            summary=f"{name}:write",
        )

    if name == "Bash":
        return _classify_bash(str(tool_input.get("command", "")), policy)

    # Unknown tool: treat as an action with no extractable target (safe-direction → caller
    # will tend to escalate/stage rather than silently allow).
    return StructuralAction(name, ToolClass.ACTION, op="exec", summary=f"{name}:unknown")
