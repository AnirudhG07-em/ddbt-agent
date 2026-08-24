"""Per-project configuration — ``ddbt.json``.

One declarative file per project: which provider/model backs the judge, which axes are on,
where the grant lives, and (forward-looking) the agent's own scoped credentials. Discovered
like ``.env`` — ``ddbt.json`` in the cwd or any parent, then ``~/.ddbt/ddbt.json`` as a global
default. Env vars always win over the file, so DDBT_PROVIDER / DDBT_JUDGE_MODEL stay overrides.

Precedence for any setting:  env var  >  ddbt.json  >  built-in default.

The ``oauth`` block is SCAFFOLDING: the ticket (floor) runs today, but per-provider credential
minting is not built yet, so nothing here consumes it. See doc/credentials.md.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

FILENAME = "ddbt.json"

# The defaults `ddbt init` writes and the loader falls back to when no file is present.
DEFAULTS = {
    "provider": None,          # None → auto-detect from keys (see judge/provider.py)
    "model": None,             # None → the provider's default model
    "ddbd": True,              # axis 2 (harm/ethics)
    "gate_offgoal": True,      # benign off-goal step → ask a human, not a hard deny
    "error_effect": "ask",     # judge infra failure → "ask" (human) or "deny" (fail-closed)
    "grant": ".ddbt/grant.json",  # path (relative to the project) or an inline grant object
    "oauth": {},               # forward-looking; not consumed yet (doc/credentials.md)
}


# What `ddbt init` writes. Secrets are referenced by ENV-VAR NAME or file path — never inlined —
# so a committed ddbt.json leaks nothing. The oauth block is scaffolding; see doc/credentials.md.
TEMPLATE = {
    "provider": None,
    "model": None,
    "ddbd": True,
    "gate_offgoal": True,
    "error_effect": "ask",
    "grant": ".ddbt/grant.json",
    "oauth": {
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
    """The ddbd / gate_offgoal / error_effect settings the hook passes into Engine()."""
    c = load(cwd)
    return {
        "ddbd": bool(c.get("ddbd", True)),
        "gate_offgoal": bool(c.get("gate_offgoal", True)),
        "error_effect": str(c.get("error_effect", "ask")),
    }


def grant_spec(cwd: str | Path | None = None):
    """The grant as configured: an inline dict, or a path string (relative to the project),
    or None. The hook resolves a path relative to the project root."""
    return load(cwd).get("grant")
