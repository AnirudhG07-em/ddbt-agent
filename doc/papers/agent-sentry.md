# Agent-Sentry — bounds an LLM agent by learning its benign execution provenance, then escalating only edge-case actions to an LLM judge

- **Source:** *Agent-Sentry: Bounding LLM Agents via Execution Provenance*, Rohan Sequeira, Stavros Damianakis, Umar Iqbal, Konstantinos Psounis. arXiv:2603.22868 (submitted Mar 24 2026; revised May 8 2026). https://arxiv.org/abs/2603.22868 — VERIFIED (arXiv abstract + HTML full text resolve; license CC BY 4.0).
- **Category:** Runtime intrusion-detection for tool-using agents via execution-provenance graphs + a learned structural bound, with a 3-layer progressive (residual) enforcement cascade. Anomaly/provenance-based, not capability-DSL based.

## Pipeline (stage by stage)

Agent-Sentry wraps the agent without modifying the agent, tools, or LLM. It observes the running trace, builds a provenance graph as tool calls happen, and decides allow/block per *action* tool call. The defense has an **offline learning phase** (build the bound from benign traces) and an **online enforcement phase** (a 3-layer cascade where each layer only handles what the previous one couldn't decide).

### Offline — learning the bound
1. **Collect execution traces.** A trace is `τ = (u, c₁, …, cₙ)`: the user prompt `u` followed by tool calls. Benign traces are labeled injection-free; malicious traces are labeled per-action against a ground-truth injection signature.
2. **Build provenance graphs.** Each tool call `cᵢ = (tᵢ, Aᵢ, rᵢ)` (tool name, argument set, return). Each argument is a tuple `(aₖ, vₖ, sₖ, dₖ)`:
   - `aₖ` = argument name,
   - `vₖ` = value,
   - `sₖ` = **provenance source set** ⊆ `{c₁…cᵢ₋₁, u}` — which prior tool calls and/or the user prompt contributed this value,
   - `dₖ ∈ {verbatim, derived, generated}` = how the value was produced from its sources.
   The calls plus per-argument source pointers form a **directed graph** of how values flow into later calls. Sources are typed by trust: user prompt `u`, trusted retrieval tools `T_R \ T_U`, and **untrusted retrieval tools `T_U`** (email bodies, files, web pages — the only injection-carrying surface).
3. **Train the structural classifier (the learned bound).** Two interchangeable designs:
   - **XGBoost** over a **17-dimensional feature vector** computed from the provenance graph, grouped as: *control flow* (position in sequence, types of preceding tools), *data flow* (distribution of source types, hop-distance from an untrusted source), *information flow* (sensitive-argument statistics, e.g. format checks), and *value tracing* (does the argument value actually appear in the untrusted retrieval text?). Outputs a maliciousness probability `p(cᵢ)∈[0,1]`, partitioned by thresholds `θ_L = 0.33`, `θ_H = 0.66` into Allow / Ambiguous / Block.
   - **Rule-based** alternative: 11 hand-defined detectors (e.g. "sensitive argument claims an untrusted source but its value does not appear verbatim in that source"), brute-force-composed into composite rules whose benign/attack/warn labels are mined from observation frequencies in labeled traces.
4. **Build the allowlist `W`.** For each *groundable* argument in benign traces, record the triplet `(tool, argument, value)`. Only sensitive, finite-pool arguments are included — recipients, accounts, credentials — explicitly **excluding free-text fields** like email bodies (which legitimately vary).

### Online — 3-layer progressive enforcement (per action tool call)
**Layer 1 — Structural classification (deterministic, learned).** Compute provenance features for the call, run XGBoost (or rules) → **Allow / Block / Ambiguous**. ~96% of actions are decided here.

**Layer 2 — Grounded argument verification (deterministic, no LLM).** Invoked *only* on Layer-1 Ambiguous. Check whether the call's groundable argument values are in allowlist `W` and came from trusted sources → **Allow** (value verified) or **Ambiguous** (value novel or from an untrusted source).

**Layer 3 — LLM intent-alignment judge (the residual).** Invoked *only* on Layer-2 Ambiguous (≈3% of all actions). The judge receives: the user prompt, the tool call under review, **per-argument provenance**, a short window of prior calls, and **bounded excerpts of untrusted retrievals wrapped in `<retrieved_data>` tags** with an explicit instruction that the wrapped text is *data, not commands*. It decides: allow if the value matches a normal content type for that argument (e.g. an email body), block if the value sits inside an imperative/authority passage (i.e. looks injected).

**Final decision logic (deny-wins on any Block):**
```
L1 Allow                               → Allow
L1 Block                               → Block
L1 Ambiguous, L2 Allow                 → Allow
L1 Ambiguous, L2 Ambiguous, L3 Allow   → Allow
L1 Ambiguous, L2 Ambiguous, L3 Block   → Block
```
Reported routing under XGBoost: **96.1% decided at L1, 0.8% → L2 allowlist, 3.1% → L3 LLM judge.** Latency ~0.073 s/trace (XGBoost path).

**Deterministic vs LLM split:** Layers 1 and 2 are fully deterministic (a learned tree + an exact-match allowlist over typed-provenance features). The LLM only sees the ~3% residual of structurally-ambiguous, value-novel actions — and even then it inspects *delimited excerpts*, not raw untrusted streams.

## Key mechanisms

**Provenance graph = the core data structure.** Every argument carries *where its value came from* (which prior call or the user) and *how* (verbatim / derived / generated), with source trust typed (user / trusted / untrusted). This lets the system reason about lineage — "this recipient value's lineage touches an untrusted email body" — which a value-only policy cannot express.

**Learned bound instead of enumeration.** Rather than enumerating all valid/invalid behaviors up front, Agent-Sentry *learns the shape of benign executions* (structural + provenance features) and flags out-of-distribution actions. Key empirical finding: detection keys on the **structural provenance signature, not the wording of the injection** — ABR stays 90.8–92.3% across three different injection-delivery mechanisms, i.e. it generalizes across phrasings.

**Residual/progressive enforcement.** The expensive, injectable component (the LLM judge) is invoked *only* on the residual that deterministic layers cannot categorically decide — typically when a legitimate task genuinely needs an unknown argument value drawn from untrusted retrieval, or a structural pattern that appears in *both* benign and malicious traces. This is the inverse of "LLM-judge on every call": cost and injection exposure scale with the ~3% ambiguous tail, not the whole trace.

**Allowlist of sensitive, groundable values.** Layer 2 is a precise, cheap deterministic check for the common case "is this recipient/account/credential one we've legitimately seen, from a trusted source?" — catching value-substitution attacks without an LLM.

## Strengths / what's genuinely good

- **Provenance is the right primitive for injection.** Tracking *lineage and trust* of each argument value catches the actual attack mechanism (untrusted data flowing into a sensitive action argument) regardless of how the injection is worded. This is strictly more expressive than constraining values alone.
- **Progressive enforcement is the efficiency/safety unlock.** Putting the LLM only on the ~3% residual gives near-deterministic latency (0.073 s/trace) *and* shrinks the injectable surface to a tiny, already-suspicious slice — and that slice is shown delimited excerpts, not raw streams.
- **No agent/tool/LLM modification** — pure observer, deployable as a wrapper.
- **Strong utility/security tradeoff:** 94.3% attack block rate at 95.1% benign-pass on the harder native-trace benchmark; 96.8% ABR / 96.4% utility on its own benchmark. Notably beats Progent's utility (~69%) and CaMeL's utility (~31%, 26.6 s latency) in their comparison because the learned bound is less rigid than a generated allowlist and far cheaper than full isolation.
- **Two classifier backends** (interpretable rules vs XGBoost) let you trade transparency for accuracy.
- **Defense-in-depth ordering with deny-wins** — any layer can block; allow requires passing the whole cascade.

## Limitations / failure modes

- **Needs representative benign traces.** The bound is only as good as the training distribution; a legitimate-but-novel workflow looks anomalous (false positive) and a not-collected attack-shaped-but-benign pattern can mis-route. Cold-start / low-data regimes hurt — their own native-trace utility drops to ~69% with only 126 benign traces.
- **Scope is indirect prompt injection into *action* tool calls only.** Explicitly out of scope: text-only attacks with no tool call, direct jailbreaks, and genuinely ambiguous user requests. It assumes agent scaffolding, tools, LLM, user, and network are trustworthy; only `T_U` retrievals carry payloads.
- **The L3 judge is still injectable in principle.** Mitigated (delimited `<retrieved_data>`, data-not-commands instruction, only ~3% of calls) but not eliminated — same residual risk ddbt already acknowledges, just confined to a much smaller slice.
- **Allowlist excludes free-text by design**, so injections that ride entirely inside a legitimately-free-text argument fall to L1 structure + L3 judgment rather than the precise L2 check.
- **Learned classifier = opacity + drift.** XGBoost decisions are less auditable than symbolic rules; thresholds (0.33/0.66) are tuned and could drift with new tools/agents.
- **Per-action, in-distribution attacks slip through** if an attack produces a provenance/structural signature indistinguishable from benign (the inherent anomaly-detection ceiling).

## Best pieces to steal for ddbt

ddbt already quarantines all tool outputs in SQLite and runs an LLM step-judge per system-touching call — but the judge reads untrusted content (injectable) and runs on *every* call. Agent-Sentry offers two high-value upgrades:

1. **Add argument provenance to the quarantine store, and make it a first-class judge input.** ddbt already isolates every tool output in per-session SQLite. Extend each stored record with `(source_call_id(s), derivation ∈ {verbatim,derived,generated}, trust ∈ {user,trusted,untrusted})`. Then, before invoking the LLM judge on a call, compute lineage of each argument: an argument whose value traces to an untrusted output entering a high-impact tool is exactly the gate condition. This turns ddbt's "high_impact → gate" from a content judgment into a **deterministic provenance check** over data you're already storing — directly attacking the injectable-judge tradeoff.

2. **Make the step-judge *residual*, not per-call (the single biggest steal).** Replace "LLM judge on every system-touching call" with Agent-Sentry's cascade: (L1) a cheap deterministic structural/provenance check decides the ~96% obvious cases; (L2) a per-session **allowlist of sensitive groundable values** (recipients, paths, accounts seen from trusted sources) decides value-novelty; (L3) ddbt's existing LLM step-judge runs *only on the residual ambiguous tail*. This cuts judge invocations ~30×, slashes cost/latency, and — critically — shrinks the injectable surface to the small, already-suspicious slice. The suspicion ratchet can drive the L1 thresholds (higher suspicion → more calls escalated to L3).

3. **Feed the judge delimited excerpts, never raw streams.** Even on the residual, adopt Agent-Sentry's L3 hygiene: pass only bounded excerpts wrapped in `<retrieved_data>` tags with a data-not-commands instruction, plus per-argument provenance and a short prior-call window — instead of whole untrusted outputs. This is a concrete, cheap hardening of ddbt's current injectable judge.

4. **Provenance signature > injection wording.** Their finding that detection keys on structural provenance (90.8–92.3% ABR across delivery mechanisms) argues ddbt should weight *lineage/structure* over *content phrasing* in its Axis-1 (anti-injection) decision — content scanning is brittle to rewording; "untrusted-source value entering sensitive sink" is not.

5. **Pair the learned bound with ddbt's Boundary 0.** ddbt already hashes config/MCP for integrity; Agent-Sentry's per-session benign bound (allowlist `W` + structural profile) is another integrity artifact that can be hash-pinned and append-only-audited alongside it, and reset per session to avoid cross-task drift.

## Sources

- [Agent-Sentry: Bounding LLM Agents via Execution Provenance — arXiv:2603.22868 (abstract)](https://arxiv.org/abs/2603.22868)
- [Agent-Sentry — full HTML text](https://arxiv.org/html/2603.22868)
- [Agent-Sentry v1](https://arxiv.org/abs/2603.22868v1)
