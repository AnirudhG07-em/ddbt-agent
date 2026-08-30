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

# canonical short name → class (what the code refers to internally)
_CLASSES = {
    "shell_deobfuscation": ShellDeobfuscation,
    "provenance_taint": ProvenanceTaint,      # trajectory taint: edge-propagation + decode-then-match
    "exfil_budget": ExfilBudget,              # low-and-slow: cumulative volume / chunk-count / beacon / db-coverage
    "net_filter": NetFilter,                  # egress control: destination-provenance / SSRF / exfil-service denylist
    "net_semantic": NetSemantic,              # meaning-based egress review (Model2Vec)
    "killchain": KillChain,                   # multi-stage attack correlation (Holmes)
    "trajectory_score": TrajectoryScore,      # holistic session-risk score
    "policy_rules": PolicyRules,              # declarative workspace trajectory DSL
    "destructive_guard": DestructiveGuard,
    "mitre_guard": MitreGuard,
    "pii_dlp": PiiDlp,
}

# INTUITIVE aliases → canonical name. These are what a human reads in ddbt.json — self-describing, so
# anyone understands what each plugin does. Either the intuitive OR the short name works in config.
ALIASES = {
    "reveal_hidden_commands":     "shell_deobfuscation",   # de-obfuscate shell (base64/hex/quote tricks)
    "stop_secret_exfiltration":   "provenance_taint",      # a secret read earlier can't leave, even re-encoded
    "stop_slow_data_leaks":       "exfil_budget",          # low-and-slow: bulk volume / chunked / beaconing
    "control_network_egress":     "net_filter",            # who data may be sent to (SSRF, exfil hosts, provenance)
    "review_sensitive_sends":     "net_semantic",          # ask a human before sensitive-looking data leaves
    "detect_multi_step_attacks":  "killchain",             # read→encode→exfil chains innocuous step-by-step
    "watch_session_risk":         "trajectory_score",      # the whole session's risk shape (drift, bursts)
    "custom_rules":               "policy_rules",          # your own cross-step rules in ddbt.json
    "block_destructive_commands": "destructive_guard",     # rm -rf /, DROP DATABASE, force-push, …
    "block_known_attacks":        "mitre_guard",           # MITRE ATT&CK signature library
    "redact_personal_data":       "pii_dlp",               # strip names/emails/SSNs/cards from outbound data
}

REGISTRY = {**_CLASSES, **{alias: _CLASSES[canon] for alias, canon in ALIASES.items()}}

# The out-of-the-box default — ALL plugins on, named intuitively, in pipeline order. One canonical
# list, used by ddbt.json's template, the demos, and the benchmarks.
DEFAULT_PLUGINS = [
    "reveal_hidden_commands", "stop_secret_exfiltration", "stop_slow_data_leaks",
    "control_network_egress", "review_sensitive_sends", "detect_multi_step_attacks",
    "watch_session_risk", "custom_rules", "block_destructive_commands",
    "block_known_attacks", "redact_personal_data",
]

__all__ = ["Plugin", "PluginManager", "PluginContext", "PreVerdict", "REGISTRY", "ALIASES",
           "DEFAULT_PLUGINS", "build", "from_config"]


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
    web = policy.get("web", {}) or {}
    # trusted destinations for the plugins' "external?" checks. `web.allow` = the grant's host ALLOW-LIST
    # (restrictive: non-listed hosts are denied) and is also trusted. `web.trusted` = trusted-ONLY (the
    # shell-sandbox union writes allowedDomains here): these lower exfil suspicion but do NOT restrict
    # other hosts, so a general shell can still curl anywhere while github/npm/pypi stay known-good.
    trusted = tuple((policy.get("email", {}) or {}).get("allow", [])) + \
        tuple(web.get("allow", [])) + tuple(web.get("trusted", []))
    # inject the top-level ddbt.json "trajectory_rules" into policy_rules (a clean key, not nested
    # under plugins) so the P5 DSL reads like the rest of the declarative config.
    rules = config.trajectory_rules(cwd)
    if rules and "policy_rules" in (spec if isinstance(spec, (list, dict)) else []):
        spec = dict(spec.items()) if isinstance(spec, dict) else {n: {} for n in spec}
        spec.setdefault("policy_rules", {})
        spec["policy_rules"] = {**(spec["policy_rules"] or {}), "rules": rules}
    return build(spec, trusted_domains=trusted)
