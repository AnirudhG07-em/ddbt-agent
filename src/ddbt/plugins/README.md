# ddbt plugins — pluggable, per-workspace defenses

Optional modules that layer extra defenses onto the core engine, composing state-of-the-art
techniques into ddbt's pipeline. Enable them per project in `ddbt.json`:

```jsonc
"plugins": ["shell_deobfuscation", "dataflow_taint", "destructive_guard"]   // list of names
// or, with options:
"plugins": { "pii_dlp": { "min_entities": 2 }, "shell_deobfuscation": {} }
```

Empty/absent → pure core behaviour. A plugin only ever **tightens** a decision (DENY or ASK); it
never forces ALLOW. Each fails open: a plugin that errors is skipped, the core floor + judge still run.

| plugin | type | hook | what it does | idea from |
|---|---|---|---|---|
| **shell_deobfuscation** | deterministic | `normalize` | rewrites a shell arg to expose hidden intent — ANSI-C `$'\x72\x6d'`, adjacent-quote `'r''m'`, `$(cmd)`, `$VAR`, hex/oct escapes — never executes it | AgentTrust `ShellNormalizer` (arXiv:2605.04785) |
| **dataflow_taint** | deterministic, cross-call | `observe` + `pre_check` | marks the session tainted when a secret is read, then DENYs a later egress to an external sink — the read-then-exfil chain | AgentTrust `RiskChain`, Invariant Guardrails |
| **destructive_guard** | deterministic | `pre_check` + `suggest` | hard-DENY catastrophic commands (`rm -rf /`, `DROP DATABASE`, `--force` push, curl-pipe-to-shell) with a safer alternative | Destructive Command Guard, AgentTrust SafeFix |
| **pii_dlp** | deterministic (Presidio) | `pre_check` | on an egress carrying validated PII (Luhn cards, SSN, keys) to an external destination: `mode` = **ask** (confirm) / **sanitize** (redact-then-send) / **deny**. Presidio when installed (`.[pii]`), regex fallback otherwise | Presidio, Invariant PII detectors |

**SANITIZE** is a fourth outcome beyond ALLOW/ASK/DENY: with `pii_dlp: {"mode": "sanitize"}`, an egress
carrying PII to an external sink is **allowed with the PII redacted** — the recipient/destination is
preserved, only the content is masked (`<CREDIT_CARD_REDACTED>`, …). The engine returns the cleaned
args as `Decision.rewritten_input`, and the caller runs *that* — so the agent still does its job without
leaking. It's a terminal allow (the destination was already grant-checked); a `deny`/`ask` from another
plugin still wins over it.

## Where they hook the pipeline

```
tool call
  → normalize   (shell_deobfuscation)         # expose real intent
  → grant floor (policy allow/deny)           # core, deterministic
  → pre_check   (destructive/dataflow/pii)    # plugin hard rules — DENY short-circuits, ASK floors
  → judge       (sift, or LLM)                # core semantic decider
  → combine + heat                            # core; a plugin ASK escalates an ALLOW to ASK
  ─ record_result → observe (dataflow_taint)  # accumulate cross-call taint
```

This maps onto the deterministic-first design: plugins run **before** the semantic judge, so they hold
even when the ML is fooled — exactly where exfiltration is caught.

## Writing a plugin

Subclass `ddbt.plugins.base.Plugin`, override the hooks you need (all optional), and register it in
`ddbt/plugins/__init__.py`'s `REGISTRY`:

```python
from ddbt.plugins.base import Plugin, PreVerdict

class MyGuard(Plugin):
    name = "my_guard"
    def pre_check(self, tool, args, ctx):
        if bad(tool, args):
            return PreVerdict("ask", "looks risky", self.name, suggestion="do it this safer way")
```

`ctx.store` (get_meta/set_meta) gives cross-call state that survives the stateless per-call hook.

## Benchmarks to measure against

The shell/exfil behaviours these add are targeted by **AgentTrust's** 300 + 630 adversarial scenarios,
**AgentSafetyBench** (349), and **ToolEmu** (144) — natural next eval targets alongside the R-Judge /
InjecAgent / MCPTox suites the judge already runs.
