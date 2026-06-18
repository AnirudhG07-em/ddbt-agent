"""Policy: the tunable knobs of the sandbox (doc §5, §6, §7.2).

Everything here is *structural* — path patterns, operation names, tool-name sets.
No knob ever depends on reading untrusted content. A deployment customises a
:class:`Policy`; :func:`default_policy` is the showcase baseline.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

# Operations that are irreversible / externally observable. The irreversibility
# gate (doc §6) hard-confirms these regardless of label, unless pre-authorised.
DEFAULT_DANGEROUS_OPS: frozenset[str] = frozenset(
    {"delete", "truncate", "drop", "send", "publish", "push", "overwrite"}
)

# Confidentiality: paths whose contents are secrets. Matched structurally (glob),
# never by reading the file. Anything matching is labelled ``sensitive`` and is an
# always-out envelope exclusion unless explicitly granted (doc §3.1).
DEFAULT_SENSITIVE_GLOBS: tuple[str, ...] = (
    "**/.ssh",  # the directory itself, not just files within
    "**/.ssh/*",
    "**/.ssh/**",
    "**/.aws",
    "**/.gcp",
    "**/.kube",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/*.pem",
    "**/*.key",
    "**/.env",
    "**/.env.*",
    "**/.aws/**",
    "**/.gcp/**",
    "**/.config/gcloud/**",
    "**/.kube/config",
    "**/.netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.git-credentials",
    "**/credentials*",
    "**/secrets*",
    "**/*token*",
    "**/*.p12",
    "**/*.pfx",
)

# Claude Code built-in tools that ingest externally-influenceable content.
DEFAULT_UNTRUSTED_TOOLS: frozenset[str] = frozenset({"WebFetch", "WebSearch"})

# Tools with no system side effect — never gated (doc §3.2: chat flows free).
DEFAULT_PURE_TOOLS: frozenset[str] = frozenset({"TodoWrite", "Task"})


@dataclass(slots=True)
class Policy:
    """A complete, structural policy. Cheap to copy and tweak per session."""

    dangerous_ops: frozenset[str] = DEFAULT_DANGEROUS_OPS
    sensitive_globs: tuple[str, ...] = DEFAULT_SENSITIVE_GLOBS
    untrusted_tools: frozenset[str] = DEFAULT_UNTRUSTED_TOOLS
    pure_tools: frozenset[str] = DEFAULT_PURE_TOOLS
    trusted_mcp_servers: frozenset[str] = frozenset()
    # domains allowed to receive outbound data by default (empty = none until granted)
    default_allowed_domains: frozenset[str] = frozenset()
    # tighten reads: a non-sensitive file read OUTSIDE the envelope (incl. via bash
    # `cat`/`cp`) escalates to a human instead of silently passing. Errs toward the
    # boundary (doc §3.3); flip off if escalations get noisy (the §8 tuning tension).
    escalate_out_of_scope_reads: bool = True
    # cumulative-trajectory thresholds (doc §1 lookahead — the gap every system shares):
    # too many outbound sends in a session = possible drip-exfil; a read-heavy session that
    # then sends externally = the classic exfil shape. Heuristic, tune against traces.
    max_outbound_per_session: int = 6
    recon_read_threshold: int = 25
    # device/system paths that are harmless to touch and never trigger a boundary check
    benign_read_paths: frozenset[str] = frozenset(
        {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/zero", "/dev/urandom", "/dev/tty"}
    )

    def is_benign_read_path(self, path: str) -> bool:
        return os.path.normpath(os.path.expanduser(str(path))) in self.benign_read_paths

    def is_sensitive_path(self, path: str) -> bool:
        """Structural confidentiality check: does this path match a secret pattern?"""
        try:
            norm = os.path.expanduser(path)
            norm = os.path.normpath(norm)
        except (ValueError, TypeError):
            norm = str(path)
        candidates = {path, norm, os.path.basename(norm)}
        for pat in self.sensitive_globs:
            for cand in candidates:
                if fnmatch.fnmatch(cand, pat) or fnmatch.fnmatch(cand, pat.replace("**/", "")):
                    return True
        return False

    def resolve(self, path: str, cwd: str | None = None) -> Path:
        """Resolve a possibly-relative / ~ path to an absolute Path (no I/O, no symlink follow)."""
        p = Path(os.path.expanduser(str(path)))
        if not p.is_absolute() and cwd:
            p = Path(cwd) / p
        # normpath without touching the filesystem (the file may not exist / be off-limits)
        return Path(os.path.normpath(str(p)))


def default_policy() -> Policy:
    """The showcase baseline policy."""
    return Policy()
