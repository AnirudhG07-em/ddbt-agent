"""policy_rules — a declarative, workspace-extensible trajectory policy DSL (ddbt.json).

The deterministic plugins encode general defenses; this lets a workspace add its OWN cross-step rules
without code, the way Invariant Guardrails and AgentSpec do (trigger → predicate → enforcement over a
trace). Rules live in ddbt.json under "trajectory_rules"; each is:

    {"when": [ <condition>, ... ], "then": "deny"|"ask", "reason": "..."}

A rule fires when EVERY condition holds for the current step. Conditions (all optional, combine freely):

    {"tool": "<regex>"}                current tool name matches
    {"arg":  "<regex>"}                current arguments text matches
    {"dest_external": true|false}      this step sends to an external (non-trusted) destination
    {"tainted": true|false}            a secret was read earlier this session (provenance_taint state)
    {"after": {"tool": "<regex>"}}     some earlier executed step's tool matched (happened-before / flows-to)
    {"count": {"tool": "<regex>", "min": N}}   a tool matching regex has run ≥ N times this session

Example — "never send outside after reading a secret", and "cap mass deletes":
    "trajectory_rules": [
      {"when": [{"tainted": true}, {"dest_external": true}], "then": "deny",
       "reason": "a secret was read earlier; this sends data to an external destination"},
      {"when": [{"count": {"tool": "delete|destroy|rm", "min": 5}}], "then": "ask",
       "reason": "many destructive calls this session"}
    ]

Deterministic and LLM-free. A malformed rule/regex is skipped, never crashes a decision.
"""

from __future__ import annotations

import json
import re

from ddbt.core.ledger import EGRESS, Ledger, destinations, flatten, is_external
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

_SEV = {"ask": 1, "deny": 2}


def _rx(pattern: str):
    try:
        return re.compile(pattern, re.I)
    except re.error:
        return None


class PolicyRules(Plugin):
    name = "policy_rules"
    headline = "This breaks one of your workspace rules."

    def __init__(self, rules=None, trusted_domains: tuple[str, ...] = ()):
        self.trusted = tuple(d.lower() for d in trusted_domains)
        self.rules = self._compile(rules or [])

    def _compile(self, rules) -> list[dict]:
        out = []
        for r in rules if isinstance(rules, list) else []:
            if not isinstance(r, dict) or r.get("then") not in _SEV:
                continue
            conds = r.get("when")
            if not isinstance(conds, list):
                continue
            out.append({"when": conds, "then": r["then"],
                        "reason": str(r.get("reason", "workspace trajectory rule"))})
        return out

    def _tainted(self, ctx: PluginContext) -> bool:
        if ctx.store is None:
            return False
        try:
            d = json.loads(ctx.store.get_meta("provenance_taint") or "{}")
            return bool((d.get("label") or {}).get("secret"))
        except (ValueError, TypeError):
            return False

    def _external(self, tool: str, text: str) -> bool:
        if not (EGRESS.search(tool) or EGRESS.search(text)):
            return False
        dests = destinations(text)
        return (not dests) or any(is_external(d, self.trusted) for d in dests)

    def _cond_ok(self, cond: dict, tool: str, text: str, led: Ledger, ctx: PluginContext) -> bool:
        if not isinstance(cond, dict):
            return False
        for key, val in cond.items():
            if key == "tool":
                rx = _rx(str(val))
                if not (rx and rx.search(tool)):
                    return False
            elif key == "arg":
                rx = _rx(str(val))
                if not (rx and rx.search(text)):
                    return False
            elif key == "dest_external":
                if bool(val) != self._external(tool, text):
                    return False
            elif key == "tainted":
                if bool(val) != self._tainted(ctx):
                    return False
            elif key == "after":
                rx = _rx(str((val or {}).get("tool", "")))
                if not (rx and any(rx.search(r["tool"]) for r in led.rows())):
                    return False
            elif key == "count":
                rx = _rx(str((val or {}).get("tool", "")))
                mn = int((val or {}).get("min", 1))
                if not rx:
                    return False
                c = sum(1 for r in led.rows() if rx.search(r["tool"])) + (1 if rx.search(tool) else 0)
                if c < mn:
                    return False
            else:
                return False   # unknown condition key → never matches (fail safe)
        return True

    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        if not self.rules:
            return None
        text = flatten(args)
        led = Ledger(ctx.store)
        worst: PreVerdict | None = None
        for r in self.rules:
            try:
                if all(self._cond_ok(c, tool, text, led, ctx) for c in r["when"]):
                    v = PreVerdict(r["then"], f"Policy · {r['reason']}", self.name)
                    if worst is None or _SEV[v.effect] > _SEV[worst.effect]:
                        worst = v
            except Exception:  # noqa: BLE001 — one bad rule must not break the decision
                continue
        return worst
