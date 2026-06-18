# ddbt benchmarks

Measures the security/utility tradeoff against the suites real defenses use, so ddbt's
numbers are directly comparable to CaMeL / Progent / FIDES / Agent-Sentry.

## AgentDojo (v0.2, implemented)

ddbt plugs in by swapping every `ToolsExecutor` in a standard AgentDojo agent for a
`DdbtToolsExecutor` (`src/ddbt/adapters/agentdojo/`), which gates each tool call through
the engine. The injection arrives in untrusted tool output; the blind judge only sees
that a sink's destination identifier wasn't named in the task → DENY.

```bash
uv pip install -e ".[bench]"          # installs agentdojo
export OPENAI_API_KEY=...             # or another provider; required to drive the agent
uv run ddbt bench agentdojo --suite workspace --model gpt-4o-mini-2024-07-18 --limit 5
```

Reports: **utility** (task completion, higher better), **ASR** (attack success rate,
lower better), and **ddbt blocks** (tool calls refused, with reasons). Comparable
headline from the literature: ASR ~30–41% → ~0–3% with single-digit utility drop.

Run an unprotected baseline (no ddbt) by benchmarking a stock AgentDojo pipeline for the
same suite/model, and report the deltas (the honest product claim, doc §12.7).

The splice + gating logic is unit-tested offline (no API key) in
`tests/test_agentdojo_adapter.py`. Only the live ASR/utility numbers need a key.

## Honest limits

Structural enforcement depends on the task naming its legitimate destinations. Tasks with
an *implicit* recipient ("email my manager") seed no identifier, so even the legitimate
sink is out-of-envelope → utility drops. This is the doc §8 envelope-seeding tension,
surfaced honestly by the benchmark rather than hidden.

## Roadmap

InjecAgent (fast static exfil smoke) · AgentDyn (over-defense / FPR) · Saber / RedCode
(accidental destruction, live Docker) — each as a sibling adapter under `bench/`.
