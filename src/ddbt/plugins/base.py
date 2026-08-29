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


# Per-plugin PROFILE: (intuitive alias shown to the user, default MITRE tactic key its findings map to).
# The alias is the classification the user recognises; the tactic resolves to a "<Tactic> (<T-id>)"
# label. A finding may override the tactic per-verdict (PreVerdict.tactic) — e.g. net_filter's SSRF hit.
PLUGIN_PROFILE: dict[str, tuple[str, str]] = {
    "shell_deobfuscation": ("reveal_hidden_commands", ""),
    "provenance_taint":    ("stop_secret_exfiltration", "exfiltration"),
    "exfil_budget":        ("stop_slow_data_leaks", "exfiltration"),
    "net_filter":          ("control_network_egress", ""),   # per-finding tactic (a new-site ASK is not exfil)
    "net_semantic":        ("review_sensitive_sends", "exfiltration"),
    "killchain":           ("detect_multi_step_attacks", "exfiltration"),
    "trajectory_score":    ("watch_session_risk", ""),
    "policy_rules":        ("custom_rules", ""),
    "destructive_guard":   ("block_destructive_commands", "catastrophic_destruction"),
    "mitre_guard":         ("block_known_attacks", ""),   # per-signature tactic (set on the verdict)
    "pii_dlp":             ("redact_personal_data", "exfiltration"),
}


def plugin_alias(canon: str) -> str:
    return PLUGIN_PROFILE.get(canon, (canon, ""))[0]


def plugin_tactic(canon: str) -> str:
    return PLUGIN_PROFILE.get(canon, (canon, ""))[1]


def mitre_label(tactic_key: str) -> str:
    """The MITRE tactic NAME for a key (no technique codes shown to the user), or '' if unmapped —
    e.g. 'Exfiltration'. Names come from sift.data.mitre.MAP (the MITRE profile)."""
    if not tactic_key:
        return ""
    try:
        from sift.data import mitre
        m = mitre.lookup(tactic_key)
        return "" if m.tactic_id == "-" else m.tactic
    except Exception:
        return ""


def finding_tag(canon: str, tactic: str, flagged=None) -> str:
    """The finding header: '<alias>[ + <alias>…] · <Tactic>'. `flagged` = (alias, tactic) for EVERY
    plugin that fired this step, so the user sees all detectors that agreed. No technique codes."""
    aliases = [a for a, _ in (flagged or [])] or [plugin_alias(canon)]
    seen, uniq = set(), []
    for a in aliases:
        if a not in seen:
            seen.add(a); uniq.append(a)
    lead = " + ".join(uniq)
    lbl = mitre_label(tactic or plugin_tactic(canon))
    return f"{lead} · {lbl}" if lbl else lead


# the two COMMON phrases that wrap every finding, so all messages read the same way.
_PREAMBLE = "ddbt: We have detected the following inconsistencies in your operation:"
_LEDE = "We think this operation"


def finding_message(tag: str, finding: str) -> str:
    """Compose one finding into the common template: '<detectors · Tactic>: We think this operation
    <finding>.' — or, with no detector tag (a judge-only finding), just 'We think this operation …'."""
    finding = finding.rstrip(" .")
    body = f"{_LEDE} {finding}."
    return f"{tag}: {body}" if tag else body


def wrap_message(reason: str) -> str:
    """Prefix the common preamble. The 🛡 marker and risk band are added by the hook renderer."""
    return f"{_PREAMBLE} {reason}"


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
    headline: str = ""            # plain, user-facing "what this means for you" (from the plugin)
    tactic: str = ""              # MITRE tactic key for THIS finding (overrides the plugin default)
    flagged: list | None = None   # [(alias, tactic)] for EVERY plugin that fired — set by the manager


class Plugin:
    """Base class — subclass and override the hooks you use. All default to no-ops."""

    name = "plugin"
    # a plain-language, user-facing summary of what THIS plugin firing means (not the technical reason).
    # Shown alongside the detailed reason so a non-expert understands the risk. Override per plugin.
    headline = ""

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
        """Most-severe pre-verdict across plugins (deny beats ask), or None. The returned verdict also
        carries `flagged` = every plugin that fired this step (alias + tactic), so the message can mark
        all detectors that agreed, not just the most-severe one."""
        worst = None
        fired: list = []
        for p in self.plugins:
            try:
                v = p.pre_check(tool, args, ctx)
            except Exception:  # noqa: BLE001
                v = None
            if not v:
                continue
            if not v.headline:
                v.headline = p.headline               # attach the producing plugin's plain-language message
            fired.append((plugin_alias(p.name), v.tactic or plugin_tactic(p.name)))
            if worst is None or _SEVERITY.get(v.effect, 0) > _SEVERITY.get(worst.effect, 0):
                worst = v
        if worst is not None:
            worst.flagged = fired
            worst.tactic = worst.tactic or plugin_tactic(worst.plugin)
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
