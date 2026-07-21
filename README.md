# ddbt-agent — Don't Do Bad Things

A **judge-centric sandbox** for coding/agent systems (Claude Code class). For every
system-touching step, an LLM **step-judge** decides whether the step is *relevant to the
user's goal* and *harmful* — and takes strict action on anything stray. **No keyword
lists, no regex policy.**

> Architecture: [`ARCHITECTURE.md`](./ARCHITECTURE.md) (current). [`doc.md`](./doc.md) is
> the original envelope/privilege-separation design, kept for history.

## Why judge-centric

Fixed wordlists can't understand a tool or judge intent. The InjecAgent benchmark proved
it: `GmailReadEmail` got blocked because its name contains "email", while `unlock_door`
and `BinanceWithdraw` sailed through because they matched no sink/destroy keyword. So the
decider is an LLM that reasons about each step instead.

## How it works

For every step the **step-judge** (claude-haiku-4-5) is given the **trusted goal**, the
**agent's proposed action**, **provenance labels**, and the **quarantined tool outputs**,
and answers:

- **relevant?** does it serve the goal?  **harmful?** leak / destroy / high-impact action?
- **stray?** unrelated or induced by an injected instruction?

→ `relevant + benign → allow` · `uncertain / high-impact → gate (ask a human)` ·
`stray / harmful → deny`. Forgiving by default, **strict on stray**.

Every tool output is **quarantined** (held in isolation), so even if the judge is fooled,
data can't leave except via a judged-and-approved flow. The judge reads quarantined content
as *hostile-under-inspection* (detect, never obey), returns a structured verdict only, and
**fails closed**. Every step is written to a **lawful, append-only audit trail**.

## Layout

```
src/ddbt/
  core/engine.py     the per-step pipeline: parse → judge → enforce → audit
  core/bootstrap.py  Boundary 0 — config/MCP integrity (hashes + regex, startup)
  core/audit.py      lawful per-step audit
  judge/step_judge.py  the decider (AnthropicStepJudge) + StepFacts/Verdict
  judge/stub.py        deterministic stubs for CI/offline
  store/session.py   SQLite session store (goal, quarantine, audit), keyed by session_id
  adapters/claude_code/  PreToolUse/PostToolUse/lifecycle hooks + installer
  adapters/agentdojo/    benchmark element (judge-gated ToolsExecutor)
bench/   AgentDojo harness + InjecAgent static replay
```

## Quick start

```bash
uv venv && uv pip install -e ".[dev]"
export ANTHROPIC_API_KEY=...                 # the decider is an LLM (claude-haiku-4-5)
uv run pytest                                # uses deterministic stub judges (no key needed)
uv run python demo/run_demos.py              # real judge if key set, else scripted stub
uv run python demo/demo_mcp.py               # narrated walkthrough: benign · malicious · MCP
```

`demo/demo_mcp.py` replays one real InjecAgent record (honest step → hijacked step) and one
real MCPTox poisoned tool description, printing the exact facts the judge sees at each
step — then an honest report of what is still missing for MCP servers. `--stub` forces the
offline deterministic path; `--slow` paces it for presenting.

Wire into Claude Code (the judge runs on every tool call):
```bash
uv run ddbt install --project /path/to/repo  # writes .claude/settings.json hooks
# ensure ANTHROPIC_API_KEY is set in the env you launch Claude Code from
uv run ddbt audit --session <session_id>     # the lawful decision trail
```

## Benchmarks

```bash
uv run ddbt bench static --source injecagent --data bench/data/injecagent/ds_base.json
uv run ddbt bench agentdojo --suite slack --only-vulnerable --limit 8
```
The decider is now the judge, so benchmark runs call the LLM per step (no longer free).

## Honest limits

- The judge **reads tool outputs** to spot stray/injected steps — more capable, but it can
  be *targeted* by injection in that content (the LGA risk). Mitigated by quarantine
  (no-leak), hostile-under-inspection framing, structured-verdict-only, and fail-closed —
  reduced, not eliminated. Measured adversarially rather than claimed by-design.
- One LLM call per system-touching step (latency + cost). Stub judge keeps CI fast/free.

MIT.
