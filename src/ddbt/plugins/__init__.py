"""Plugin registry — build the enabled plugins from ddbt.json `"plugins"`.

Config accepts a list of names or a {name: options} map, e.g.
    "plugins": ["shell_deobfuscation", "dataflow_taint", "destructive_guard"]
    "plugins": {"pii_dlp": {"min_entities": 2}}
Unknown names are ignored; plugins that accept `trusted_domains` get them from the policy's
email/web allow-lists so their "external destination" checks match the ticket.
"""

from __future__ import annotations

import inspect

from ddbt.plugins.base import Plugin, PluginContext, PluginManager, PreVerdict
from ddbt.plugins.dataflow_taint import DataflowTaint
from ddbt.plugins.destructive_guard import DestructiveGuard
from ddbt.plugins.mitre_guard import MitreGuard
from ddbt.plugins.pii_dlp import PiiDlp
from ddbt.plugins.shell_deobfuscation import ShellDeobfuscation

REGISTRY = {
    "shell_deobfuscation": ShellDeobfuscation,
    "dataflow_taint": DataflowTaint,
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
    return build(spec, trusted_domains=trusted)
