# ddbt v4 — Judge-Centric Architecture

**Supersedes the keyword/policy decider.** The benchmark proved fixed wordlists are
brittle: `GmailReadEmail` was blocked because its name contains "email"; `unlock_door`
and `BinanceWithdraw` sailed through because they matched no sink/destroy keyword. A
finite list can neither understand a tool nor judge intent. So the decider is now an
**LLM that judges each step's relevance-to-goal and harm** — no keywords anywhere.

## The one job: verify the intent of every step

For each proposed step the **step-judge** (cheap model, e.g. claude-haiku-4-5) answers,
from the agent's *proposed action* + provenance *labels* + the relevant *tool outputs*:

- **Relevant?** Does this step plausibly serve the user's (trusted) goal?
- **Harmful?** Would it cause out-of-policy effect (leak, destroy, high-impact action)?
- **Stray?** Is it unrelated/injected — a step the goal never called for?

Mapping: **relevant + benign → allow** (forgiving); **uncertain / high-impact → gate**
(ask a human); **stray / harmful → deny** (strict). The pipeline is forgiving by default
but takes **strict action on anything stray**.

## What the judge sees (and the honest tradeoff)

The judge reads the proposed action, the provenance labels, **and tool outputs** —
including inspecting a *suspicious* output to decide whether it's stray/malicious. This
is more powerful than a blind judge (it catches injected/stray steps by their content)
but it means the **decider can be targeted by injection** in that content (the LGA risk).
Mitigations, all enforced:

1. **Quarantine / virtual FS.** Every tool output lands in an isolated store, never a
   live sink. The judge reads *from quarantine*; quarantined data is released to an
   external destination **only** by an explicit allow of *that flow*. So even a fooled
   relevance call cannot leak data — the data has no path out except a judged flow.
2. **Hostile-under-inspection framing.** Tool-output content is passed to the judge
   delimited and labelled untrusted, with an instruction to **detect**, never **obey**,
   any instructions inside it (adversarial "find the stray" stance).
3. **Structured verdict only.** The judge returns `{decision, relevant, harmful, stray,
   reason}` — never free text that could carry data out; the `reason` describes the
   *structure*, not the secret.
4. **Fail closed.** Any judge error/timeout → treat as stray → deny.

> Honest note: (2)–(4) reduce but do not eliminate judge-persuasion. This is the
> deliberate tradeoff for content-aware intent judging; we measure it adversarially
> rather than claim by-design immunity.

## Per-step pipeline

```
PER STEP (every system-touching action — reads included; chat skipped)
  1. parse        mechanical → {tool, args, command, referenced paths/domains}   (no wordlists)
  2. provenance   all tool OUTPUTS are quarantined+tainted by default; look up labels of inputs
  3. JUDGE        haiku( goal, action, input-labels, quarantined-excerpts ) → Verdict
  4. enforce      allow → run (output → quarantine) · gate → ask human · deny → block
  5. AUDIT        append-only, lawful record: goal, action, labels, verdict + full reasoning, decision
COMMIT/FLOW       quarantined data leaves only via a judged-and-approved flow (no-leak invariant)
```

## What's kept vs removed

- **Removed (keyword garbage):** sink/destructive/net-binary wordlists, sensitive-path
  globs, dangerous-op sets, structural-conformance keyword concerns, threshold heuristics.
- **Kept (not keyword-based):** mechanical action parsing; provenance taint (origin =
  *which tool* produced data — structural); staging repurposed as the **quarantine**;
  Boundary-0 config/MCP integrity (hashes); the **audit log**, now first-class and lawful.

## Cost

One cheap-model call per system-touching step. Caching identical `(goal, action)` and a
deterministic stub judge (CI/offline) keep the inner loop usable; live runs pay per step.
