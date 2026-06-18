# ddbt-agent — Don't Do Bad Things

An **envelope-anchored, privilege-separated sandbox** for general-purpose coding agents
(Claude Code class). It prevents prompt-injection exfiltration and accidental destruction
*without suffocating the agent*, at near-zero latency on the common path.

> Design source of truth: [`doc.md`](./doc.md). This README is the implementation map.

## The one idea

Most agent-governance designs put an LLM "intent judge" in the loop — and that judge
**reads the untrusted content that may contain the injection**, so it can be injected and
made to stamp the attack `ALLOW`. ddbt fixes this with **privilege separation by input
trust**:

- **The policy judge decides but is blind to untrusted bytes.** It compares two clean
  things: the *scope envelope* (what's in-bounds) and *typed structural facts* about an
  action (an `untrusted`/`sensitive` value flowing to an outbound sink). Injected wording
  never reaches it.
- **The content inspector reads untrusted bytes but has no authority.** It can only ever
  *lower* trust (emit taint labels). The worst it can do is under-flag; it can never grant
  permission.

The anchor is a **structural envelope**, not an inferred goal: it starts at the workspace
root and grows only by explicit gates and pristine user grants. "Irrelevant + dangerous"
becomes a deterministic *out-of-envelope* check, not a fragile intent inference.

## Architecture

```
core/        agent-agnostic, deterministic, zero-LLM hot path
  labels       two-axis provenance label (origin × channel) + worst-label-wins
  provenance   taint tracker / content inspector (load-bearing; injectable, no authority)
  envelope     scope envelope: seed minimal + grow-by-gate + safe-direction rule
  checkpoint2  blind structural conformance → {ALLOW, AMBIGUOUS, ESCALATE, DENY}
  irreversibility  hard gate on {delete, truncate, drop, send, publish, push, overwrite}
  staging      lanes (pass-through / staged / gate-only) + real queue
  bootstrap    Boundary 0: config + MCP integrity (hash + regex)
  checkpoint3  commit-time review of the materialised batch (LLM judge pluggable, v0.3)
  audit        every decision + every trust transition, names the catching checkpoint
  engine       the pipeline orchestrator (the single security surface)
policy/      structural policy: tool classification, sensitive patterns, dangerous ops
store/       SQLite/WAL session store, keyed by session_id (cross-call taint state)
adapters/    claude_code (hooks, primary) · agentdojo (benchmark) · mcp (secondary)
```

One engine, many adapters: swapping Claude Code for another agent is a new adapter, not a
core change.

## Quick start

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest                      # deterministic core + provenance fuzzer
uv run python demo/run_demos.py    # the §7 walkthroughs (ssh-exfil, rm -rf, benign)
```

Wire it into a real Claude Code session:

```bash
uv run ddbt install --project /path/to/scratch/repo   # writes .claude/settings.json hooks
uv run ddbt audit  --session <session_id>             # inspect the decision trail
```

## Status

v0.1 — deterministic core + Claude Code hook adapter + demos (zero added LLM calls).
Roadmap: v0.2 benchmarks (AgentDojo, InjecAgent, AgentDyn, Saber/RedCode) · v0.3 blind
commit-time LLM diff-judge + MCP adapter.

## Honest limits (v0.1)

- At the hook layer we *allow / deny / ask*; we cannot redirect a built-in `Write` into an
  overlay, so "ambiguous-reversible" escalates to a human instead of silently staging.
- True packet-level egress control needs the OS substrate (seccomp/Landlock, doc §9); the
  staging queue is real at the tool/semantic layer.
- Provenance is resource-granularity (per file / per tool-result), not in-model data-flow —
  the envelope boundary is the primary protection; taint is the secondary toxic-flow signal.

MIT.
