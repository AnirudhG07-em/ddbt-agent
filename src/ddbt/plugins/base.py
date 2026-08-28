"""Plugin framework — pluggable, per-workspace defenses that layer on the core engine.

Each plugin is an optional, deterministic (or lazily-semantic) module that hooks the tool-call
pipeline at well-defined points. They compose the state-of-the-art techniques surveyed from
AgentTrust (arXiv:2605.04785), Invariant Guardrails, and Presidio into ddbt's layered stack, and are
turned on per project via ddbt.json `"plugins"`. Nothing here changes behaviour unless a plugin is
enabled — an empty manager is a pass-through.

Hooks (all optional; override only what you need):
  * normalize(tool, args) -> args   : rewrite args to EXPOSE hidden intent before anything reads them
                                      (e.g. shell deobfuscation). Pure text, never executes.
  * pre_check(tool, args, ctx)      : a deterministic hard rule that runs BEFORE the judge and can
                                      DENY or ASK (a plugin only ever TIGHTENS, never forces allow).
  * observe(tool, args, result, ctx): watch a tool's OUTPUT to accumulate cross-call state (taint).
  * suggest(tool, args) -> str      : a safer-alternative hint shown with a block (SafeFix pattern).

A plugin only tightens the decision; the engine still runs its floor, judge, and heat.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PluginContext:
    """What a plugin needs from the session. `store` gives cross-call persistence (get/set_meta),
    keyed by session on disk — so a plugin like dataflow-taint survives the stateless per-call hook."""
    session_id: str = "default"
    goal: str = ""
    provenance: str = "unknown"   # who chose this: "you" | "stranger" | "unknown"
    store: object | None = None   # SessionStore-like: get_meta(k)/set_meta(k,v); None → stateless


@dataclass
class PreVerdict:
    effect: str                   # "deny" | "ask" | "sanitize"  — a plugin tightens or redacts
    reason: str
    plugin: str
    suggestion: str | None = None
    rewrite: dict | None = None   # for "sanitize": the redacted args to run instead of the original


class Plugin:
    """Base class — subclass and override the hooks you use. All default to no-ops."""

    name = "plugin"

    def normalize(self, tool: str, args: dict) -> dict:
        return args

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        return None

    def observe(self, tool: str, args: dict, result, ctx: PluginContext) -> None:
        pass

    def suggest(self, tool: str, args: dict) -> str | None:
        return None


# deny wins over ask wins over sanitize (a hard block beats a redact-and-send).
_SEVERITY = {"allow": 0, "sanitize": 1, "ask": 2, "deny": 3}


class PluginManager:
    """Runs the enabled plugins' hooks in order and aggregates. Fail-open per plugin: one plugin
    raising never breaks a decision (it's skipped) — the core floor/judge still runs."""

    def __init__(self, plugins: list[Plugin] | None = None):
        self.plugins = list(plugins or [])

    def __bool__(self) -> bool:
        return bool(self.plugins)

    def normalize(self, tool: str, args: dict) -> dict:
        for p in self.plugins:
            try:
                args = p.normalize(tool, args) or args
            except Exception:  # noqa: BLE001
                continue
        return args

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        """Most-severe pre-verdict across plugins (deny beats ask), or None."""
        worst = None
        for p in self.plugins:
            try:
                v = p.pre_check(tool, args, ctx)
            except Exception:  # noqa: BLE001
                v = None
            if v and (worst is None or _SEVERITY.get(v.effect, 0) > _SEVERITY.get(worst.effect, 0)):
                worst = v
        return worst

    def observe(self, tool: str, args: dict, result, ctx: PluginContext) -> None:
        for p in self.plugins:
            try:
                p.observe(tool, args, result, ctx)
            except Exception:  # noqa: BLE001
                continue

    def suggest(self, tool: str, args: dict) -> str | None:
        for p in self.plugins:
            try:
                s = p.suggest(tool, args)
            except Exception:  # noqa: BLE001
                s = None
            if s:
                return s
        return None
