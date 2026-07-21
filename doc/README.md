# What other people built, and what we take from it

Eleven systems that try to stop AI agents from doing bad things. For each one:
**the good idea**, **how we use it**, and **do we actually have it yet**.

Written in plain English on purpose. The detailed per-paper notes are in the other
files in this folder.

---

## First, what ddbt does today (in one paragraph)

Before the agent runs any tool, we send the step to a small LLM (the "judge") and ask
three questions: *does this help the user's goal? is it harmful? is it a stray step
somebody snuck in?* Allow, ask a human, or block. Everything a tool returns goes into a
quarantine box, and every decision gets written to a log.

**The problem with that:** the judge is the only guard, and the judge *reads the
attacker's text*. If the attacker writes a convincing enough paragraph, the judge can be
talked into saying "allow" — and then our own audit log says the attack was fine. That is
the one weakness every system below either avoids or measures.

---

## The one lesson all eleven papers agree on

> **Don't let the LLM make the security decision if a dumb, mechanical rule could make it
> instead. And work out the rules from what the *user* said, before you read anything the
> internet said.**

An LLM can be argued with. A rule cannot. So use the LLM to *understand* things (what's
the plan, where did this value come from), and use plain code to *decide*.

Right now ddbt does the opposite: the LLM decides everything. That's what should change.

---

## The eleven systems

Legend for status: ✅ we have it · 🟡 we have a weak version · ❌ not built yet

### 1. LGA — *the cautionary tale* ([lga.md](lga.md))

**The good idea:** they built almost exactly what we built — an LLM judge checking intent —
and then honestly measured how well it holds up. Answer: it catches ~92% of attacks
normally, but only **50–63%** once someone spends 30 tries writing prompts specifically to
fool the judge. Their own conclusion: *the judge cannot be the only guard.*

**How we use it:** as proof, not as a design. It's the number we cite for why ddbt needs
mechanical guards underneath the judge. Two things worth copying: run a cheap judge on
everything and only call an expensive one when the cheap one is worried (they cut false
alarms from 34% to 2% that way), and keep the audit log where a hacked agent can't delete it.

**Status:** ❌ no cheap→expensive cascade · ✅ audit log already lives outside the project ·
❌ no "attacker tries 30 times" test in `bench/`

---

### 2. CaMeL — *decide the plan before you read the internet* ([camel.md](camel.md))

**The good idea:** two LLMs. The first one reads **only the user's request** and writes out
the plan as code. The second one reads the untrusted web data but is given **no power** — it
can't call tools, it just extracts values. Because the plan was written before any attacker
text was seen, attacker text can't change the plan.

**How we use it:** this is the single biggest fix for our weakness. At the start of a
session, from the user's message alone, write down "here is the set of actions this task
could legitimately need." Then the question for every step stops being "judge, what do you
reckon?" and becomes "is this action in the list?" — which is a lookup, not an opinion.

**Status:** ❌ not built. We judge every call from scratch with no plan to compare against.

---

### 3. FIDES — *give every piece of data two stickers* ([fides.md](fides.md))

**The good idea:** put two labels on every value: *can I trust where this came from?* and
*who is allowed to see this?* Then the rule is just arithmetic — an untrusted value may not
become an argument to something consequential, and a secret value may not go to someone not
on the allowed list. No LLM opinion involved, so it cannot be argued with. That alone
handled the whole AgentDojo attack set.

Also nice: **hide/reveal**. Don't dump secret content into the chat — keep it in the box and
give the agent a ticket number. If it genuinely needs the content, pull out just one field
through a strict form, so at most a tiny amount can escape.

**How we use it:** our quarantine table should store those two labels per row and pass them
along, and the check should run as a hard gate **before** the judge, not as a sentence in
the judge's prompt.

**Status:** 🟡 `engine._labels()` does mark arguments "user-named" vs "injection-derived" —
but it only *tells the judge* about it. The judge is still free to ignore it. It should be a
rule that blocks on its own.

---

### 4. Progent — *write down the allowed list, in a format code can check* ([progent.md](progent.md))

**The good idea:** a small policy language — for this task, these tools, with arguments
matching these patterns. It's plain JSON Schema, checked by an ordinary validator. And when
the agent wants more privilege, a solver checks that the new scope is *inside* the old one.
Narrowing happens automatically; widening always needs a human.

**How we use it:** this is the machinery for CaMeL's plan idea. It also makes our
"suspicion ratchet" real: instead of a score that vaguely makes the judge stricter, the
permitted set literally shrinks and provably never grows on its own.

Also worth copying: when we block something, tell the agent **why**, so it re-plans instead
of just failing.

**Status:** ❌ no policy layer at all.

---

### 5. Agent-Sentry — *only call the judge when you're actually unsure* ([agent-sentry.md](agent-sentry.md))

**The good idea:** three layers. A mechanical check settles about **96%** of calls. A list of
"values we've legitimately seen this session" (recipients, paths, accounts) settles most of
the rest. Only the genuinely confusing leftovers reach the LLM. That's ~30× fewer LLM calls,
and — more importantly — the LLM touches attacker text 30× less often.

Their sharpest finding: **where a value came from beats what it says.** Rewording an attack
defeats content matching; "this value came from an untrusted source and is heading into a
dangerous tool" survives any rewording.

**How we use it:** this is what turns our judge from *the* guard into *a specialist for hard
cases*. And it validates the provenance idea we already lean on — we just need to store the
lineage properly instead of recomputing it by string matching each step.

**Status:** ❌ the judge runs on every single call · 🟡 provenance is string-matching against
recent quarantine text, not a stored source→derivation→trust chain

---

### 6. DRIFT — *keep injected instructions out, not just data in* ([drift.md](drift.md))

**The good idea:** two halves. First, same as CaMeL — build the expected plan from the
trusted request only. Second, and this is the new part: before tool output enters the
agent's memory, **strip out the instructions hidden in it**.

That's the mirror image of what we do. Our quarantine stops data getting *out*. Their
isolator stops commands getting *in*. You want both.

Also a cheap, sharp rule: a step that only *reads* something is far less dangerous than one
that writes or executes. Let reads through and spend the expensive check on writes.

**How we use it:** add a masking pass before tool output reaches the agent's context, and
log both the raw and the masked version.

**Status:** ❌ neither half. The agent still reads raw tool output; we only gate the next
action.

---

### 7. AgentArmor — *turn the session into a graph and do taint analysis* ([agentarmor.md](agentarmor.md))

**The good idea:** treat the agent's history as a program. Build a graph of what flowed into
what, mark external data as dirty, mark dangerous operations as guarded, and refuse any path
from dirty to guarded. This is 40-year-old, well-understood security-tooling maths.

Two things this gives you that per-step judging can't: the verdict genuinely **cannot be
prompt-injected** (attacker text is a node in the graph, never an instruction to the
checker), and it catches **attacks split across steps** — read the secret in step 2,
reshape it in step 5, send it in step 9, where no single step looks bad on its own.

**How we use it:** the same lineage columns FIDES and Agent-Sentry want. Add a registry of
what each tool reads/writes so the checker knows which calls are dangerous.

**Status:** ❌ no graph, and no tool registry. We judge each call in isolation, which means
we're blind to the split-across-steps attack.

---

### 8. AgentSpec — *simple `if this, then that` rules* ([agentspec.md](agentspec.md))

**The good idea:** a tiny rule runtime — *when this kind of call happens, if this condition
holds, do this*. Rules are named and readable, so the audit log can say **which rule fired**
instead of just "the model felt uneasy." Rules get generated offline from the trusted task
description, so they're not injectable.

They also have four responses rather than two, and one is genuinely useful: *make the agent
re-think*, instead of only blocking.

**How we use it:** the cheap front layer that handles the obvious cases so the judge doesn't
have to.

**Careful:** AgentSpec has no concept of "is this off-goal" at all. It complements our
goal-fidelity axis; it can't replace it. Also note we deliberately **deleted** keyword rules
earlier — they scored ~2% on MCPTox. The lesson is not "keywords work," it's "mechanical
rules about *structure and provenance* work; mechanical rules about *wording* don't."

**Status:** ❌ no pre-filter · 🟡 the audit log does record which checkpoint fired

---

### 9. SAGA — *tickets with an expiry date and a usage limit* ([saga.md](saga.md))

**The good idea:** before an agent can use something, it gets a signed ticket carrying a
time limit and a maximum number of uses, tied cryptographically to *that specific* identity.
A stolen ticket doesn't work for anyone else. Expired means expired — no LLM opinion.

**How we use it:** this is the answer to "one bad MCP server has the same power as every
other one." Mint a per-session ticket per MCP server, tied to the hash Boundary 0 already
computes, with a call budget. If the server's identity changes, the ticket is dead.

**Status:** ❌ every MCP server currently gets unlimited, permanent, equal trust.

---

### 10. ARMO — *watch first, restrict later* ([armo.md](armo.md))

**The good idea:** don't demand a perfect policy on day one. Watch what normally happens,
build a picture of it, then start enforcing. A behaviour is only auto-approved after it has
recurred N times across M sessions. And when the tool list changes, throw the picture away
and start watching again.

**How we use it:** this is how we'd get a mechanical fast path without hand-writing rules,
and it fits our existing "suspicion only ever goes up" rule — only *proven* behaviour
relaxes anything, and suspicion still never falls.

**Status:** ❌ no learning · ✅ the never-lowers ratchet is already in `engine._strictness()`

---

### 11. Codex sandbox — *a wall the LLM can't argue with* ([codex-sandbox.md](codex-sandbox.md))

**The good idea:** the operating system enforces it. Network off unless allowed, writes
confined to specific folders — enforced by macOS Seatbelt / Linux bubblewrap, below the
agent entirely. If our judge gets fooled into "allow", the OS still refuses. That's the
difference between "we hope it's safe" and "it cannot happen."

Their second idea: edits are **patches**, reviewed and then applied. A separate reviewer
with fresh context and no tools reads the final diff. It can't be injected mid-run because
it never saw the run — it only sees the result.

**How we use it:** the floor under everything. Plus that diff reviewer is exactly the
"blind judge" idea from our own v3 design, already shipped by someone else.

**Status:** ❌ no OS sandbox · ❌ v4 dropped the v3 staging overlay, so a wrong "allow"
is immediately real and irreversible · ❌ no commit-time diff review

---

## Scoreboard: what we have

| Piece | Status |
| --- | --- |
| Quarantine every tool output | ✅ built |
| Audit log, outside the project, append-only | ✅ built |
| Suspicion ratchet that only goes up | ✅ built |
| Attacker text framed as hostile, judge returns a fixed form, fails closed | ✅ built |
| Boundary 0: config + MCP file hashing | ✅ built |
| Semantic tool-description poison scanner | 🟡 built and benchmarked, **not wired into the running system** |
| Provenance ("did this value come from the user or from the internet?") | 🟡 string matching, advisory only |
| Plan worked out from the trusted request first | ❌ |
| Mechanical rule layer in front of the judge | ❌ |
| Data-flow graph / multi-step attack detection | ❌ |
| Per-server tickets with expiry + quota | ❌ |
| OS sandbox floor | ❌ |
| Staging + blind diff review at the end | ❌ (was in v3, dropped in v4) |
| Cheap→expensive judge cascade | ❌ |
| Adaptive-attack regression suite | ❌ |

---

## Specifically for MCP servers

Run `uv run python demo/demo_mcp.py` for the live version of this. Short version:

**Working:** MCP tool calls arrive at our hook named `mcp__<server>__<tool>` and get judged
exactly like any built-in tool — no MCP-specific allowlist needed. Boundary 0 hashes
`.mcp.json`. The poisoned-description scanner exists and scores well on MCPTox.

**Not working:**

1. `src/ddbt/adapters/mcp/__init__.py` is an **empty file**. There is no MCP-specific code.
2. `bootstrap._scan_mcp()` looks for tool descriptions inside `.mcp.json` — but real
   `.mcp.json` files only hold `{command, args, env}`. Descriptions come from the running
   server at runtime. **So on a real project that scan never runs.**
3. `engine.on_session_start()` calls `bootstrap.verify(root)` with **no scanner**, so the
   poison scanner is skipped in production entirely.
4. No rug-pull detection — a server can be clean when approved and poisoned next session.
   We hash the config file, which doesn't change when the *server* changes.
5. The judge never sees the description of the MCP tool it's judging.
6. No per-server limits (the SAGA ticket idea).

Points 1–3 and 5 are one small module: ask each server for its tool list at session start,
hash it, run the existing scanner on anything new, and put the descriptions into `StepFacts`.
That is the highest-value MCP work available and it reuses code we already wrote.

---

## What to build first

1. **The plan, worked out from the user's request only** (CaMeL + DRIFT) — attacks our core
   weakness directly and cuts judge cost a lot.
2. **The label check as a real gate, plus proper lineage in the quarantine table**
   (FIDES + AgentArmor) — makes the exfiltration verdict impossible to argue with, and
   catches attacks spread over several steps.
3. **MCP: fetch the real tool list and wire up the scanner** — small, and finishes work
   that's already 80% done.
4. **OS sandbox + per-server tickets** (Codex + SAGA) — hard floors that don't depend on any
   model being right.
5. **Staging + blind diff review** (Codex, and our own v3 design) — makes a wrong "allow"
   undoable.
6. **Learn-then-enforce lifecycle** (ARMO) — tuning, once we have traces.

The judge cascade (LGA) and the `if this then that` rule form (AgentSpec) are cheap and can
be slotted in at any point.
