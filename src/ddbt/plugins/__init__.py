"""Plugin registry — build the enabled plugins from ddbt.json `"plugins"`.

Config accepts a list of names or a {name: options} map, e.g.
    "plugins": ["shell_deobfuscation", "provenance_taint", "destructive_guard"]
    "plugins": {"pii_dlp": {"min_entities": 2}}
Unknown names are ignored; plugins that accept `trusted_domains` get them from the policy's
email/web allow-lists so their "external destination" checks match the ticket.
"""

from __future__ import annotations

import inspect

from ddbt.plugins.base import Plugin, PluginContext, PluginManager, PreVerdict
from ddbt.plugins.destructive_guard import DestructiveGuard
from ddbt.plugins.exfil_budget import ExfilBudget
from ddbt.plugins.killchain import KillChain
from ddbt.plugins.mitre_guard import MitreGuard
from ddbt.plugins.net_filter import NetFilter
from ddbt.plugins.net_semantic import NetSemantic
from ddbt.plugins.pii_dlp import PiiDlp
from ddbt.plugins.policy_rules import PolicyRules
from ddbt.plugins.provenance_taint import ProvenanceTaint
from ddbt.plugins.shell_deobfuscation import ShellDeobfuscation
from ddbt.plugins.trajectory_score import TrajectoryScore

REGISTRY = {
    "shell_deobfuscation": ShellDeobfuscation,
    "provenance_taint": ProvenanceTaint,      # trajectory taint: edge-propagation + decode-then-match
    "exfil_budget": ExfilBudget,              # low-and-slow: cumulative volume / chunk-count / beacon / db-coverage
    "net_filter": NetFilter,                  # egress control: destination-provenance / SSRF / exfil-service denylist
    "net_semantic": NetSemantic,              # meaning-based egress review (Model2Vec): sensitivity + goal-relatedness, ASK-only
    "killchain": KillChain,                   # P3: correlate single-step signals into a multi-stage attack (Holmes)
    "trajectory_score": TrajectoryScore,      # P4: holistic session-risk score (context-exfil gap, burst, novelty, goal-drift)
    "policy_rules": PolicyRules,              # P5: declarative workspace trajectory DSL (ddbt.json "trajectory_rules")
    "destructive_guard": DestructiveGuard,
    "mitre_guard": MitreGuard,
    "pii_dlp": PiiDlp,
}

__all__ = ["Plugin", "PluginManager", "PluginContext", "PreVerdict", "REGISTRY", "build", "from_config"]


def build(spec, trusted_domains: tuple[str, ...] = ()) -> PluginManager:
    items = spec.items() if isinstance(spec, dict) else [(n, {}) for n in (spec or [])]
    plugins: list[Plugin] = []
    for name, opts in items:
        cls = REGISTRY.get(name)
        if cls is None:
            continue
        opts = dict(opts or {})
        params = inspect.signature(cls.__init__).parameters
        if "trusted_domains" in params and "trusted_domains" not in opts:
            opts["trusted_domains"] = trusted_domains
        try:
            plugins.append(cls(**opts))
        except Exception:  # noqa: BLE001 — a bad option must not break the whole manager
            try:
                plugins.append(cls())
            except Exception:
                continue
    return PluginManager(plugins)


def from_config(cwd=None) -> PluginManager:
    from ddbt.core import config

    spec = config.plugins(cwd)
    policy = config.grant_spec(cwd) or {}
    trusted = tuple((policy.get("email", {}) or {}).get("allow", [])) + \
        tuple((policy.get("web", {}) or {}).get("allow", []))
    # inject the top-level ddbt.json "trajectory_rules" into policy_rules (a clean key, not nested
    # under plugins) so the P5 DSL reads like the rest of the declarative config.
    rules = config.trajectory_rules(cwd)
    if rules and "policy_rules" in (spec if isinstance(spec, (list, dict)) else []):
        spec = dict(spec.items()) if isinstance(spec, dict) else {n: {} for n in spec}
        spec.setdefault("policy_rules", {})
        spec["policy_rules"] = {**(spec["policy_rules"] or {}), "rules": rules}
    return build(spec, trusted_domains=trusted)
