"""Per-project configuration — ``ddbt.json``: ONE declarative file per project.

Everything that scopes an agent lives here, and each part is meant to be added to freely:
  * judge         — which provider/model decides, and which axes are on
  * ``policy``    — the capability ticket: what's allowed AND what's denied, per resource
                    (tools / files / email / web / quotas). Every resource has an ``allow`` and a
                    ``deny`` list, so blocking a mail domain or host is as easy as granting one.
                    Add a new resource key and grant.py just reads it — nothing else to wire.
  * ``auth``      — the agent's own scoped credentials, referenced by env-var NAME or file path,
                    never inlined. SCAFFOLDING for now (see doc/credentials.md); nothing mints yet.

Discovered like ``.env`` — ``ddbt.json`` in the cwd or any parent, then ``~/.ddbt/ddbt.json`` as a
global default. Env vars always win, so DDBT_PROVIDER / DDBT_JUDGE_MODEL stay overrides.

Precedence for any setting:  env var  >  ddbt.json  >  built-in default.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

FILENAME = "ddbt.json"

# The defaults the loader falls back to when a setting is absent. `policy` defaults to None so that
# a project with an external .ddbt/grant.json (legacy) still resolves; `install` writes an inline
# policy into ddbt.json (TEMPLATE below) so the common case is genuinely one file.
DEFAULTS = {
    "judge": "sift",           # decider: "sift" (default, non-LLM) or "llm" (flagged fallback)
    "provider": None,          # None → auto-detect from keys (see judge/provider.py)
    "model": None,             # None → the provider's default model
    "ddbt": True,              # axis 2 (harm/ethics)
    "gate_offgoal": True,      # benign off-goal step → ask a human, not a hard deny
    "error_effect": "ask",     # judge infra failure → "ask" (human) or "deny" (fail-closed)
    "policy": None,            # inline capability ticket (the deterministic allow/deny floor)
    "behaviors": {},           # workspace semantic rules for the sift judge (NL or taxonomy) — no retrain
    "plugins": [],             # optional pluggable defenses (see ddbt.plugins) — names or {name: opts}
    "auth": {},                # the agent's own scoped credentials (scaffolding; doc/credentials.md)
}


# What `install` writes. The `policy` block is the whole ticket, inline, with allow AND deny lists
# per resource — extend it by adding to a list or adding a new resource key. Secrets in `auth` are
# referenced by ENV-VAR NAME or file path — never inlined — so a committed ddbt.json leaks nothing.
TEMPLATE = {
    "judge": "sift",
    "provider": None,
    "model": None,
    "ddbt": True,
    "gate_offgoal": True,
    "error_effect": "ask",

    # Workspace SEMANTIC rules for the sift judge — natural language OR taxonomy dicts. Unlike the
    # deterministic `policy` above, these are judged by similarity (no retrain: they're embedded and
    # compared live). "deny" raises risk on matching actions; "allow" lowers it (known-good).
    "behaviors": {
        "deny": [
            "push to git, create a commit, or open a pull request without me explicitly asking",
            "close, reopen, or mass-transition Jira tickets I did not specifically name",
            "read from, modify, or drop tables in the production database",
            "export or copy database rows or customer data to any destination outside the workspace",
            {"domain": "git", "category": "unauthorized_change",
             "text": "force-push or rewrite shared git history that nobody approved"},
        ],
        "allow": [
            "read and summarize files in the workspace",
            "run the test suite and report the results",
            "query the database read-only for counts or schema when asked",
        ],
    },

    # pluggable defenses, on by default (all deterministic + light). Remove any you don't want, or
    # add "pii_dlp" (Presidio-backed egress PII check). See src/ddbt/plugins/.
    "plugins": ["shell_deobfuscation", "dataflow_taint", "destructive_guard"],

    "policy": {
        "label": "ddbt assistant",
        "ttl_seconds": 0,           # 0 = no expiry
        "fast_path_reads": True,    # safe reads skip the judge
        # each resource: what the agent MAY do (allow) and what it may NEVER do (deny).
        # [] allow = "no allow-limit of this kind"; deny always subtracts and wins ties.
        "tools": {
            "allow": ["Read", "Grep", "Glob", "LS", "Bash", "Write", "Edit",
                      "NotebookRead", "TodoWrite", "mcp__github__*"],
            "deny": [],
        },
        "files": {  # always-on secret floor; add project paths to taste
            "deny": ["~/.ssh/*", "**/id_rsa*", "**/.env", "~/.aws/*", "**/credentials*", "**/*.pem"],
        },
        "email": {"allow": [], "deny": []},   # domains the agent may / may never send to
        "web": {"allow": [], "deny": []},     # hosts the agent may / may never reach
        "quotas": {},                          # tool-name -> max high-impact calls, e.g. {"send_email": 3}
    },

    "auth": {
        "_status": "SCAFFOLDING — not consumed by ddbt yet. See doc/credentials.md.",
        "github": {"app_id": "", "installation_id": "", "private_key_path": ".ddbt/github-app.pem", "repositories": []},
        "gmail": {"client_id_env": "DDBT_GMAIL_CLIENT_ID", "client_secret_env": "DDBT_GMAIL_CLIENT_SECRET",
                  "refresh_token_env": "DDBT_GMAIL_REFRESH_TOKEN", "scopes": ["https://www.googleapis.com/auth/gmail.send"]},
        "jira": {"base_url": "", "bot_email": "", "api_token_env": "DDBT_JIRA_API_TOKEN", "project_key": ""},
    },
}


def write_default(project: str | Path, force: bool = False) -> tuple[Path, bool]:
    """Write TEMPLATE to <project>/ddbt.json. Returns (path, written); written=False if it
    already existed and force is off (never clobber a user's config silently)."""
    path = Path(project) / FILENAME
    if path.exists() and not force:
        return path, False
    path.write_text(json.dumps(TEMPLATE, indent=2, ensure_ascii=False) + "\n")
    _load_raw.cache_clear()
    return path, True


def _find_file(cwd: str | Path | None) -> Path | None:
    """ddbt.json in cwd or any parent, then ~/.ddbt/ddbt.json. First hit wins."""
    start = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    for d in (start, *start.parents):
        f = d / FILENAME
        if f.is_file():
            return f
    glob = Path.home() / ".ddbt" / FILENAME
    return glob if glob.is_file() else None


@lru_cache(maxsize=32)
def _load_raw(resolved: str | None) -> tuple:
    """Read and parse the file at `resolved` (a str path or None). Cached, hashable key.
    Returns (data_items, source_path) — a malformed file falls back to defaults, never raises."""
    if not resolved:
        return tuple(DEFAULTS.items()), ""
    try:
        data = json.loads(Path(resolved).read_text())
        if not isinstance(data, dict):
            data = {}
    except (OSError, json.JSONDecodeError):
        data = {}
    merged = {**DEFAULTS, **data}
    return tuple(merged.items()), resolved


def load(cwd: str | Path | None = None) -> dict:
    """The effective config dict for a project (file merged over defaults; env NOT applied here)."""
    f = _find_file(cwd)
    items, _ = _load_raw(str(f) if f else None)
    return dict(items)


def source(cwd: str | Path | None = None) -> str:
    """Path of the ddbt.json actually in effect, or "" if none (pure defaults)."""
    f = _find_file(cwd)
    return str(f) if f else ""


# ---- resolved settings, with env override ----

def provider(cwd: str | Path | None = None) -> str | None:
    """Configured provider name, or None to let key auto-detection choose. Env DDBT_PROVIDER wins."""
    env = (os.environ.get("DDBT_PROVIDER") or "").strip().lower()
    if env:
        return env
    val = load(cwd).get("provider")
    return str(val).strip().lower() if val else None


def model(cwd: str | Path | None = None) -> str | None:
    """Configured judge model id, or None for the provider default. Env wins (DDBT_JUDGE_MODEL,
    or DDBT_MODEL as an alias)."""
    env = os.environ.get("DDBT_JUDGE_MODEL") or os.environ.get("DDBT_MODEL")
    if env:
        return env.strip()
    val = load(cwd).get("model")
    return str(val).strip() if val else None


def engine_kwargs(cwd: str | Path | None = None) -> dict:
    """The ddbt / gate_offgoal / error_effect settings the hook passes into Engine()."""
    c = load(cwd)
    return {
        "ddbt": bool(c.get("ddbt", c.get("ddbd", True))),  # "ddbd" = legacy alias
        "gate_offgoal": bool(c.get("gate_offgoal", True)),
        "error_effect": str(c.get("error_effect", "ask")),
    }


def plugins(cwd: str | Path | None = None):
    """Enabled plugin spec from ddbt.json: a list of names or a {name: options} map. See
    ddbt.plugins.from_config. Empty → no plugins (pure core behaviour)."""
    p = load(cwd).get("plugins")
    return p if isinstance(p, (list, dict)) else []


def behaviors(cwd: str | Path | None = None) -> dict:
    """Workspace semantic rules for the sift judge: {"deny": [...], "allow": [...]}, where each item
    is a natural-language string or a taxonomy dict {domain, category, text}. Consumed by sift, not
    the deterministic grant. Empty {} → sift uses only its built-in catalog."""
    b = load(cwd).get("behaviors")
    return b if isinstance(b, dict) else {}


def grant_spec(cwd: str | Path | None = None):
    """The capability ticket: the inline ``policy`` object in ddbt.json, loaded via
    Grant.from_dict. Returns None when no policy is configured (no ticket)."""
    p = load(cwd).get("policy")
    return p if isinstance(p, dict) else None


def auth(cwd: str | Path | None = None) -> dict:
    """The agent's own scoped-credential block (``auth``; ``oauth`` accepted as a legacy alias).
    SCAFFOLDING — returned for tooling/inspection; nothing mints from it yet (doc/credentials.md)."""
    c = load(cwd)
    a = c.get("auth")
    if not a:  # absent or empty → accept the legacy "oauth" key
        a = c.get("oauth")
    return a if isinstance(a, dict) else {}
