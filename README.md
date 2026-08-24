# ddbt-agent — Don't Do Bad Things

Catchy name right!

You are drinking coffee Monday morning and you want the new week without yoru agents screwing around. You want the agent to do JUST WHAT YOU SAID! THATS IT! We all use agents and we want it to work on AUTO mode yet NOT do bad things. This is a tool/hook for your agent to **stop prompt-injection attacks** and **prevent high-impact mistakes** yet allow you to do your work without the agent side stepping on your account.

This is a PLUGIN, not another AGENTIC CLI. You can use it with your agent of choice (Claude Code, Gemini Cli, Codex, etc.).

TL;DR on how the tool internally works:

The agent runs a **per-step LLM judge**(not a static wordlist) that checks every system-touching action against your goal and the provenance of its arguments. It then allows/denies/asks a human for each step. It measures relevance of a step to your goal and session heat(suspicion) to decide whether to allow, ask, or deny).

> For more details, see Architecture: [`ARCHITECTURE.md`](./ARCHITECTURE.md). [`doc.md`](./doc.md) is the original
> envelope/privilege-separation design, kept for history. This might not be very readable.

### How is it better than other prompt-injection mitigations?

I don't know honestly. I use it and I am happy with it! It doesn't side step. I ask it to edit README, and if it tries to also somehow edit my test cases, it will get STOPPED! Thankfully!

PLUS I have read a lot of papers on Agentic Security and Prompt Injection and have taken out the best parts of those papers, yet not make this tool a bulk of all ideas. A lot of papers had layers of LLMs and checking and judging, which is great, but I wanted to make it _fast_ and _cheap_(for your bank account). So just taken good ideas + MY OWN BRAIN to brain down a good usable tool.

Let's dive into this tool!

# Installation and setup

To run the setup, use [uv](https://astral.sh/uv)(recommended):

```bash
uv venv && uv pip install -e ".[dev]"
```

Now since this tool needs another LLM to run the judge, you need to set up your API KEY too. You can either have `.env` file within the repository from where you are running the agent, or you can set it up in your shell.

```bash
export ANTHROPIC_API_KEY="YOUR_ANTHROPIC_API_KEY"
export GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
# and so on
export DDBT_PROVIDER="anthropic"  # or "gemini"/"openai", etc.
export DDBT_MODEL="claude-3.5-sonnet" # or "gemini-2.5-flash", etc.
```

Wire into Claude Code (the judge runs on every tool call):

```bash
uv run ddbt install --project /path/to/repo   # writes .claude/settings.json hooks
uv run ddbt trust   --project /path/to/repo   # baseline current config for Boundary 0
uv run ddbt audit   --session <session_id>    # the lawful decision trail
uv run ddbt clear   --session <session_id>    # audited human override — lowers session heat
```

# How DDBT works

Here is a high-level overview of how the tool works.

## Two axes

The judge answers two independent questions:

- **Axis 1 — goal fidelity / anti-injection** _(always on)._ Does this action serve _your_ goal,
  or was it induced by text a stranger wrote? This is the axis that protects you. It never
  restricts _you_ — only actions that trace to someone else's instructions.
- **Axis 2 — harm** _(optional, the "Don't Do Bad Things" layer, `ddbt`)._ Is the action itself
  harmful — leak, destroy, high-impact? Toggle it off to measure Axis 1 in isolation. This is more
  on the side of Morality.

A wordlist can't tell these apart.

## What happens on every tool call

Three layers run in order. The first two are **deterministic code** — an attacker can't talk past
them. Only the third is the LLM.

```

user prompt ─────────────▶ the trusted GOAL is set (anchors every later relevance check)

every tool call
─────────────────────────────────────────────────────────────────────────────
0 · Boundary 0 config + MCP integrity (hashes, out-of-band baseline).
(startup/change) Catches a poisoned tool description or a redirected
endpoint BEFORE the loop even runs. [zero LLM]

1 · the TICKET the agent's own capability grant, checked as
(hard floor) policy + arithmetic — never an LLM reading text:
• tool not granted / path off-limits (~/.ssh, .env)
/ destination not allow-listed / quota spent /
expired → DENY (can't be injected past)
• a safe in-scope read, no egress
→ ALLOW (fast path, no LLM call)
• in scope but consequential
→ defer to the judge ↓
2 · the JUDGE builds the facts: trusted goal + proposed action +
(LLM step-judge) PROVENANCE labels + the quarantined outputs that
mention this step's args. Answers:
relevant? harmful? stray/injection-derived?
then combines with session heat → ALLOW · ASK · DENY
─────────────────────────────────────────────────────────────────────────────

after the tool runs its output is QUARANTINED (untrusted-by-default) and every
identifier in it is indexed by WHERE IT SAT — a structured
field (the system chose it) vs. free text (its author did).

```

**Provenance is the heart of Axis 1.** The question is never "did this value appear in a tool
output" (legitimate values do — read-then-act is normal), but "**could a stranger have chosen
it?**" A `from:` address is a field the mail system produced → _grounded_. An address buried in a
message _body_ is whatever the sender typed → _injection-derived_. Acting on the second, off-goal,
is the exact shape of a prompt-injection attack — and it hard-denies. It's a structural index
lookup: no wordlists, no model, and no recency window that an attacker can wait out.

**Quarantine is the backstop.** Even if the judge is fooled, tool output is held in isolation, so
data can't leave except through a judged-and-approved flow. The judge reads quarantined content as
_hostile-under-inspection_ (detect, never obey), returns a structured verdict only, and **fails
closed**. Every decision is written to a lawful, append-only audit trail (`ddbt audit`).

---

## Session heat — the guard tightens under pressure

Suspicion accrues only from **evidence** — a blocked step, or ≥2 corroborating signals (one soft
flag on an allowed step is the judge noticing, not proof). It drives three states, and it only ever
ratchets **up**; the sole way down is an audited human `ddbt clear`.

| state        | when                    | what changes                                                                        |
| ------------ | ----------------------- | ----------------------------------------------------------------------------------- |
| **NORMAL**   | clean session           | on-goal work flows; only high-impact steps ask                                      |
| **ELEVATED** | ~two blocked deviations | high-impact / soft steps **gate** (ask) instead of pass — a human stays in the loop |
| **LOCKED**   | ~four                   | only basic work passes; anything high-impact or soft is denied                      |

The point: rising heat **narrows reach**, it doesn't freeze the agent. Basic work still gets done at
LOCKED — the sandbox stays usable.

---

## Chromatics — read a whole session at a glance

Every decision gets a **colour**; the session gets a **heat** colour. Both are computed in code
_downstream_ of the decision, from trusted signals only. That makes them honest telemetry: an
attacker **can't paint their own step green**, because the colour comes from the outcome, not their
text. Deliberately coarse — four discrete bands, nothing to guess on a fine scale:

| band     | colour   | meaning                                    |
| -------- | -------- | ------------------------------------------ |
| **none** | 🟢 green | ordinary on-goal action, from you          |
| **low**  | 🟢 lime  | allowed, but a soft signal or odd origin   |
| **med**  | 🟡 amber | paused for a human (high-impact, on-goal)  |
| **high** | 🔴 red   | blocked — deviation, harm, or out of scope |

When a block happens in Claude Code, the reason line is attributed so you can tell a **ddbt** block
from Claude declining on its own:

```

🛡 DDBT · DENY · via ticket [out-of-scope] 🔴 risk:high · heat:NORMAL — tool 'X' is not in this agent's grant
🛡 DDBT · DENY · via judge [goal-fidelity] 🔴 risk:high · heat:ELEVATED — carries out an instruction from quarantined content

```

`via ticket` = the deterministic floor. `via judge` = the LLM. Set `DDBT_VERBOSE=1` to also see the
greens it clears, so you know it's live.

---

## Its own identity — acts on your behalf, not on your account

_"Acts on your behalf" ≠ "acts as you."_ The agent should be a **separate principal** — its own
identity, least privilege, short-lived — so a bypass can't reach the rest of your account. Two
layers, same defence-in-depth idea:

**Ticket layer — the floor (ddbt, live today).** One uniform policy the providers can't express,
checked _before_ the call: email only to `acme.com`, reach only `github.com`, at most 3 sends,
never touch `~/.ssh` or `.env`, expires in an hour. This is the only layer that can catch an
**injection-chosen** destination, because it runs on provenance, not trust. Authored in
`.ddbt/grant.json`; see `src/ddbt/core/grant.py`.

**Credential layer — the ceiling (provider-side).** A real scoped token per service, so even if
ddbt is bypassed the token _literally cannot_ reach the rest of your account:

- **GitHub** — a GitHub App on selected repos, 1-hour install token
- **Gmail** — OAuth `gmail.send` scope only — can't read your inbox
- **Jira** — a bot user with one project role

> **Status: the ticket runs today; per-provider credential minting is the next build, not yet
> implemented — and needs testing.** The design drops into the same model (ceiling + floor, a leak
> in either caught by the other), but the OAuth/token-minting half is a proposal until it's built
> and measured. Don't cite it as working.

## Testing

To run the Benchmarks:

```bash
uv run ddbt bench rjudge                                                    # defaults to bench/data/rjudge/
uv run ddbt bench static   --source injecagent --data bench/data/injecagent/ds_base.json
uv run ddbt bench agentdojo --suite slack --limit 8
```

| suite                          | result                                                | notes                                                                                                                                                     |
| ------------------------------ | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **R-Judge** (571 trajectories) | **F1 91.5%** on unsafe                                | recall 93.4% (281/301), specificity 88.1%, precision 89.8%, 0 judge errors. GPT-4o baseline ≈ 74%. Harm axis **off** — goal-fidelity alone produced this. |
| **MCPTox**                     | **484/485** poisoned tool descriptions caught (99.8%) | 0 of 8 benign flagged                                                                                                                                     |
| **InjecAgent**                 | 1054/1054 attacks stopped, 1054 benign clean (100%)   | **a regression floor, not robustness** — see caveat                                                                                                       |

This shows ????

## Layout

```
src/ddbt/
  core/engine.py       the per-step pipeline: labels → ticket → judge → enforce → audit
  core/grant.py        the capability ticket (deterministic hard floor + fast path)
  core/bootstrap.py    Boundary 0 — config/MCP integrity (hashes + obfuscation scan)
  core/chromatics.py   the four risk bands + session-heat colour (downstream telemetry)
  core/provenance.py   where each value sat: structured field vs. free text
  core/audit.py        lawful per-step audit trail
  judge/step_judge.py  the decider (AnthropicStepJudge) + StepFacts / Verdict
  judge/stub.py        deterministic stubs for CI/offline
  store/session.py     SQLite session store (goal, quarantine, provenance), keyed by session_id
  adapters/claude_code/  PreToolUse/PostToolUse/lifecycle hooks + installer
  adapters/agentdojo/    benchmark element (judge-gated ToolsExecutor)
bench/   AgentDojo harness + R-Judge / InjecAgent / MCPTox static replay
demo/    demo_mcp.py (narrated) · chat_live.py (interactive)
```

---

## Honest limits

- **The judge reads tool outputs** to catch stray/injected steps — more capable than a wordlist,
  but it can be _targeted_ by injection in that content (the LGA risk). Mitigated by quarantine
  (no-leak), hostile-under-inspection framing, structured-verdict-only, and fail-closed — reduced,
  not eliminated. Measured adversarially, not claimed by design.
- **One LLM call per system-touching step** (latency + cost). The ticket's fast-path skips it for
  safe in-scope reads; the stub judge keeps CI fast and free.
- **Utility is unmeasured** (see above) and **per-provider credential minting is unbuilt**.
