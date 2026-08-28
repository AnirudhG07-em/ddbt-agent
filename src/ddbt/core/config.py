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

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

from ddbt.plugins import DEFAULT_PLUGINS as _DEFAULT_PLUGINS

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
    "deny_mode": "block",      # "block" = hard DENY; "override" = DENY→ASK_OVERRIDE (a human may force it)
    "policy": None,            # inline capability ticket (the deterministic allow/deny floor)
    "behaviors": {},           # workspace semantic rules for the sift judge (NL or taxonomy) — no retrain
    "rulesets": [],            # names of REUSABLE rule-packs in ~/.ddbt/rules/<name>/ to fold in (additive)
    "llm": {"provider": None, "model": None, "max_requests": 4},  # AUTHORING LLM (ddbt create-rules) — never runtime
    "trajectory_rules": [],    # P5 declarative cross-step DSL (see ddbt.plugins.policy_rules)
    "plugins": list(_DEFAULT_PLUGINS),  # ALL defenses on by default — even with no ddbt.json present
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
    # "block" = a DENY is a hard, un-forceable block (default). "override" = a DENY becomes ASK_OVERRIDE:
    # you CAN force it through, but with a loud warning naming the layer that flagged it and why.
    "deny_mode": "block",

    # Reusable rule-packs (in ~/.ddbt/rules/, shared across projects) this project opts into. Author one
    # for any tool with:  ddbt create-rules "notion-cli"  — it drafts good/bad rules, you verify, it folds
    # in live (no retrain). Any project references the same pack by name.
    "rulesets": [],

    # The AUTHORING LLM for `ddbt create-rules` — NEVER used by the runtime guard (which is LLM-free).
    # null provider = auto-detect from GEMINI_API_KEY / ANTHROPIC_API_KEY; max_requests caps a draft.
    "llm": {"provider": None, "model": None, "max_requests": 4},

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

    # ALL defenses on by default, named so anyone can read what each does (short names also work).
    # Remove any you don't want. 'review_sensitive_sends' reuses the sift Model2Vec encoder; the rest
    # are deterministic + light. See src/ddbt/plugins/ (and plugins.ALIASES for the name mapping).
    "plugins": list(_DEFAULT_PLUGINS),

    # P5 — declarative cross-step rules, evaluated by policy_rules against the whole session. Add your
    # own freely; see src/ddbt/plugins/policy_rules.py for the full condition vocabulary.
    "trajectory_rules": [
        {"when": [{"tainted": True}, {"dest_external": True}], "then": "deny",
         "reason": "a secret was read earlier this session and this step sends data to an external destination"},
        {"when": [{"count": {"tool": "delete|destroy|remove|drop", "min": 5}}], "then": "ask",
         "reason": "an unusual number of destructive actions this session"},
    ],

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

    # the agent's own scoped credentials, referenced by ENV-VAR NAME or file path (never inlined).
    # Empty by default; scaffolding only — see doc/credentials.md for the shape when you need it.
    "auth": {},
}


# ---- where config lives: an OUT-OF-BAND per-project layer the guarded agent can't reach ----
#
# A project's policy is discovered from up to three files, merged low→high precedence:
#   1. ~/.ddbt/ddbt.json                          global defaults for this machine
#   2. ./ddbt.json (cwd or a parent)              IN-PROJECT — committable, team-shared (but an agent
#                                                 working in the repo could edit it)
#   3. ~/.ddbt/projects/<hash(project)>/ddbt.json OUT-OF-BAND — authoritative, tamper-proof (the agent
#                                                 in the repo cannot see or edit it). `install` writes here.
# The out-of-band layer WINS on conflicts. Deny lists are the exception: they are UNIONED across every
# layer, so no layer can weaken the floor — in-project may only ADD denies, never remove them.

# deny-list paths that are additive across layers (a floor, never weakened by a lower-precedence layer).
_DENY_PATHS = (("policy", "tools", "deny"), ("policy", "files", "deny"),
               ("policy", "web", "deny"), ("policy", "email", "deny"), ("behaviors", "deny"))


def _home() -> Path:
    return Path(os.environ.get("DDBT_HOME") or (Path.home() / ".ddbt"))


def project_root(cwd: str | Path | None = None) -> Path:
    """The project's identity: the nearest ancestor holding a .git, else cwd itself. Stable per repo."""
    start = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    for d in (start, *start.parents):
        if (d / ".git").exists():
            return d
    return start


def project_key(cwd: str | Path | None = None) -> str:
    """A near-deterministic per-project key = blake2b of the resolved project-root path."""
    return hashlib.blake2b(str(project_root(cwd)).encode(), digest_size=8).hexdigest()


def project_dir(cwd: str | Path | None = None) -> Path:
    """The out-of-band per-project directory under ~/.ddbt — config, per-project centroids, etc."""
    return _home() / "projects" / project_key(cwd)


def _in_project_file(cwd: str | Path | None) -> Path | None:
    start = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    for d in (start, *start.parents):
        f = d / FILENAME
        if f.is_file():
            return f
    return None


def _read(path: Path | None) -> dict:
    if not path:
        return {}
    try:
        d = json.loads(Path(path).read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _dig(d: dict, path: tuple):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def _bury(d: dict, path: tuple, val) -> None:
    for p in path[:-1]:
        d = d.setdefault(p, {})
    d[path[-1]] = val


def write_default(project: str | Path, force: bool = False, in_project: bool = False) -> tuple[Path, bool]:
    """Write TEMPLATE to the per-project config. Default target is the OUT-OF-BAND dir
    (~/.ddbt/projects/<hash>/ddbt.json) so a compromised agent can't edit its own policy; pass
    in_project=True to write a committable ./ddbt.json instead. Never clobbers unless force."""
    path = (Path(project) / FILENAME) if in_project else _oob_file(project)
    if path.exists() and not force:
        return path, False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(TEMPLATE, indent=2, ensure_ascii=False) + "\n")
    _load_raw.cache_clear()
    return path, True


def _oob_file(cwd: str | Path | None) -> Path:
    return project_dir(cwd) / FILENAME


@lru_cache(maxsize=64)
def _load_raw(cwd_key: str | None) -> str:
    """Merged config JSON for a resolved cwd, cached. Layers low→high: defaults, global, in-project,
    out-of-band (authoritative); deny lists unioned across all (an un-weakenable floor)."""
    cwd = cwd_key or None
    layers = [dict(DEFAULTS), _read(_home() / FILENAME), _read(_in_project_file(cwd)), _read(_oob_file(cwd))]
    merged: dict = {}
    for layer in layers:
        merged = _deep_merge(merged, layer)
    for path in _DENY_PATHS:                       # additive deny floor: union across every layer
        seen, union = set(), []
        for layer in layers:
            for x in (_dig(layer, path) or []):
                k = json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x)
                if k not in seen:
                    seen.add(k)
                    union.append(x)
        if union or _dig(merged, path) is not None:
            _bury(merged, path, union)
    _fold_rulesets(merged)                          # resolve "rulesets" refs → additive behaviors/exemplars
    return json.dumps(merged)


def _fold_rulesets(merged: dict) -> None:
    """Fold each referenced reusable rule-pack (~/.ddbt/rules/<name>/) into the effective config —
    its behaviors ADD to the project's deny/allow, its exemplars ADD to net_semantic. Shared authoring:
    a pack is written once (ddbt create-rules) and any project opts in by name. Missing packs are skipped."""
    names = merged.get("rulesets")
    if not isinstance(names, list) or not names:
        return
    from ddbt.core import rules  # lazy — rules imports config._home
    beh = merged.setdefault("behaviors", {}) if isinstance(merged.get("behaviors"), dict) else {}
    merged["behaviors"] = beh
    for pack in filter(None, (rules.load_pack(n) for n in names)):
        pb = pack.get("behaviors", {}) if isinstance(pack.get("behaviors"), dict) else {}
        for kind in ("deny", "allow"):
            items = pb.get(kind)
            if isinstance(items, list) and items:
                existing = beh.get(kind) if isinstance(beh.get(kind), list) else []
                beh[kind] = existing + [x for x in items if x not in existing]


def load(cwd: str | Path | None = None) -> dict:
    """The effective config for a project — the three layers merged (env NOT applied here)."""
    key = str(Path(cwd).resolve()) if cwd else str(Path.cwd().resolve())
    return json.loads(_load_raw(key))


def sources(cwd: str | Path | None = None) -> list[str]:
    """Every config file contributing to the effective policy, low→high precedence (existing only)."""
    out = []
    for f in (_home() / FILENAME, _in_project_file(cwd), _oob_file(cwd)):
        if f and Path(f).is_file():
            out.append(str(f))
    return out


def source(cwd: str | Path | None = None) -> str:
    """The highest-precedence config file in effect (out-of-band > in-project > global), or ""."""
    s = sources(cwd)
    return s[-1] if s else ""


def _set_rulesets(refs: list, cwd: str | Path | None) -> Path:
    path = _oob_file(cwd)
    cfg = _read(path) or dict(TEMPLATE)
    cfg["rulesets"] = refs
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
    _load_raw.cache_clear()
    return path


def add_ruleset(name: str, cwd: str | Path | None = None) -> Path:
    """Reference a reusable rule-pack from this project's OUT-OF-BAND ddbt.json (create from template if
    absent). Idempotent. Returns the config path. Used by `ddbt create-rules` / `ddbt enable-rules`."""
    cur = _read(_oob_file(cwd)).get("rulesets")
    refs = list(cur) if isinstance(cur, list) else []
    return _set_rulesets(refs + [name] if name not in refs else refs, cwd)


def remove_ruleset(name: str, cwd: str | Path | None = None) -> Path:
    """Un-reference a rule-pack from this project (`ddbt disable-rules`). The pack itself is untouched."""
    cur = _read(_oob_file(cwd)).get("rulesets")
    refs = [r for r in cur if r != name] if isinstance(cur, list) else []
    return _set_rulesets(refs, cwd)


def llm(cwd: str | Path | None = None) -> dict:
    """AUTHORING-LLM settings for `ddbt create-rules` (NEVER used by the runtime guard): which provider
    and model draft rule content, and the per-command request cap. Env DDBT_LLM_PROVIDER /
    DDBT_LLM_MODEL / DDBT_LLM_MAX_REQUESTS override ddbt.json; None provider = auto-detect from keys."""
    d = load(cwd).get("llm")
    d = d if isinstance(d, dict) else {}
    prov = os.environ.get("DDBT_LLM_PROVIDER") or d.get("provider")
    model = os.environ.get("DDBT_LLM_MODEL") or d.get("model")
    try:
        cap = int(os.environ.get("DDBT_LLM_MAX_REQUESTS") or d.get("max_requests", 4) or 4)
    except (TypeError, ValueError):
        cap = 4
    return {"provider": str(prov).lower() if prov else None, "model": model or None, "max_requests": max(1, cap)}


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
        "deny_mode": (os.environ.get("DDBT_DENY_MODE") or str(c.get("deny_mode", "block"))).lower(),
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


def trajectory_rules(cwd: str | Path | None = None) -> list:
    """The P5 declarative trajectory DSL: ddbt.json ``trajectory_rules`` — a list of
    {"when": [...], "then": "deny"|"ask", "reason": "..."} evaluated by the policy_rules plugin
    against the session's cross-step state. Empty when absent. See ddbt.plugins.policy_rules."""
    r = load(cwd).get("trajectory_rules")
    return r if isinstance(r, list) else []


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
