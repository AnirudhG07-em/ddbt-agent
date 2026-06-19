# Progent — a deterministic least-privilege policy layer that gates every LLM-agent tool call against symbolic rules

- **Source:** *Progent: Securing AI Agents with Privilege Control* (earlier title: *Progent: Programmable Privilege Control for LLM Agents*), Tianneng Shi, Jingxuan He, Zhun Wang, Hongwei Li, Linyu Wu, Wenbo Guo, Dawn Song. arXiv:2504.11703 (submitted Apr 16 2025; v3 May 14 2026). https://arxiv.org/abs/2504.11703 — VERIFIED (arXiv page + HuggingFace + dblp all resolve; both titles appear on official pages, the v3/current title is "Securing AI Agents with Privilege Control").
- **Category:** Deterministic privilege-control / capability DSL + LLM-authored, SMT-checked policy lifecycle. Defense-in-depth control point, *not* a content classifier.

## Pipeline (stage by stage)

Progent sits between the agent's LLM and the tool runtime. The agent loop is unchanged; Progent intercepts each proposed tool call and decides allow / block-with-fallback. There are three moving parts: an **LLM policy author** (trusted-input only), a **deterministic enforcer** (no LLM), and an **SMT-checked update gate** (no LLM in the decision).

1. **Initial policy generation (LLM, trusted input only).**
   - Input: the set of available tools `T` and the user query `o₀`. Under the threat model the user query is *trusted*; untrusted tool outputs are NOT fed in at this stage.
   - Output: a policy — a list of symbolic rules — emitted as a **JSON Schema** document (chosen because JSON Schema is native to modern LLM structured-output APIs and there is an off-the-shelf deterministic validator, Python `jsonschema`).
   - Effect measured in the paper: initial policy alone drops attack success rate from 39.9% → 2.5%. So most of the protection is from the *up-front* least-privilege envelope, before any update logic runs.

2. **Per-tool-call enforcement (deterministic, no LLM — Algorithm 2).**
   For each tool call the agent proposes:
   - Select the rules whose `ToolName` matches the called tool.
   - **Sort so `forbid` rules precede `allow` rules** (conservative / deny-wins ordering).
   - Iterate rules, substituting the call's *actual argument values* into each rule's conditions:
     - first matching `forbid` → **block**, then run the rule's fallback action;
     - first matching `allow` → **permit the call unchanged**.
   - If **no rule matches → default-deny** (block). The action space is closed by default.
   - This stage contains no model inference: it is pure predicate evaluation over concrete arguments, so it is not injectable.

3. **Fallback on block.** A blocked call does not silently fail. The rule's fallback is one of: terminate execution, request human inspection, or (default) return a structured error message back to the agent, e.g. *"The tool call is not allowed due to {reason}…"* — letting the agent re-plan within its remaining privilege.

4. **Policy update during execution (LLM proposes, SMT decides — Algorithm 3).**
   After each tool call returns (and now untrusted output exists), the policy may need to widen/narrow as new info arrives. Progent splits this into two LLM steps specifically to limit injection exposure:
   - **Step A — "is an update needed?"** decided by the LLM *without seeing the untrusted tool result* (so the trigger to update can't be injected).
   - **Step B — generate candidate policy `P′`** with full context, only if Step A said yes.
   - **SMT comparison (Z3), no LLM in the decision:** check whether the action set of the new policy is a subset of the old, `A(P′) ⊆ A(P)`.
     - **Narrowing** (`⊆` holds) → applied automatically.
     - **Expansion** (`⊆` fails) → requires explicit human/principal approval before it takes effect.
   - Guarantee — **monotonic confinement** (Eq. 6): `A(P₀) ⊇ A(P₁) ⊇ A(P₂) ⊇ …`. Without approval, the effective action space can only shrink. In practice ~6% of updates are expansions needing approval.

**Deterministic vs LLM split (the whole point):** The LLM is used only to *author* policy from trusted input and to *propose* updates. Every *security decision at runtime* — does this concrete tool call pass? is this proposed policy a widening? — is deterministic (predicate eval + Z3). The enforcement path never trusts model judgment about a specific call.

## Key mechanisms

**Policy DSL.** A policy is a list of rules; each rule:

```
Rule := Effect ToolName when {Conditions} fallback Action
```

- **Effect:** `allow` | `forbid`
- **ToolName:** the target tool identifier
- **Conditions:** a conjunction of boolean predicates over the tool's arguments
- **fallback Action:** what to do when this rule blocks (terminate / ask user / return error)

Concrete example (paper Fig. 1c):
```
allow send_slack_msg when {to == "alice", body == *}
```
"Slack messages allowed only to alice, any body." Another: `read_emails when {recent == 20}` pins an argument to a value.

**Condition language over arguments.** Literals and argument variables; comparisons `<`, `≤`, `==`; membership `in`; regex `match`; array ops (`p[n]`, `p.length`); logical `and`/`or`/`not`. Rich enough to constrain recipients, paths, amounts, counts, and string shapes — but it is a *constraint* language, not arbitrary code.

**Default-deny + deny-wins ordering.** No matching rule = block; `forbid` evaluated before `allow`. The agent's reachable action space is the explicit allow-set minus forbids, and nothing else.

**SMT-checked monotonicity.** The novel piece: instead of trusting the LLM to "tighten" a policy, Z3 *proves* whether a proposed policy is a subset of the current one. Subset → safe to auto-apply; not-subset → needs approval. This converts "did the model widen privileges?" from a judgment call into a decidable check.

**Two integration modes:** a **library** (embedded in the agent) and a **proxy** (transparent, intercepts tool calls with no agent code change). Validated on LangChain and OpenAI Agents SDK. Implementation: JSON Schema policy format, `jsonschema` validator, Z3 for the subset check.

**Generic / reusable policies.** Beyond per-task generated policies, Progent supports manually authored "generic" policies composed sequentially with multi-layer priority ordering (org-wide guardrails layered under task-specific rules).

## Strengths / what's genuinely good

- **Enforcement is decoupled from the LLM.** The single most important property: even if untrusted tool output fully hijacks the agent's LLM, the deterministic enforcer still evaluates the *concrete* call against rules the LLM cannot rewrite at runtime. The attacker can change what the agent *wants* to do, not what it is *allowed* to do.
- **Monotonic confinement is a real invariant, not a heuristic.** Z3 gives a provable "this update only narrows" check; privilege can only auto-shrink. This is a much stronger guarantee than a suspicion score that "tends" to tighten.
- **Most protection is front-loaded.** Initial policy alone gives 39.9%→2.5% ASR. The expensive lifecycle machinery is a refinement, not the load-bearing part — good news for adoption since a static policy already buys most of the win.
- **Cheap and benchmark-validated.** Strong ASR reduction with high utility on AgentDojo and ASB; works as a transparent proxy so no agent rewrite.
- **Actionable feedback loop.** Blocks return a reasoned error to the agent so it can re-plan, preserving utility instead of dead-ending the task.
- **Human-in-the-loop is bounded and principled** — approval only for the ~6% of updates that genuinely widen authority, not for every action.

## Limitations / failure modes

- **Policy quality is bounded by the LLM author and the user query.** If the generated policy is too loose, the deterministic enforcer faithfully enforces a loose policy. Garbage-in, garbage-enforced. (Agent-Sentry's eval reports Progent at ~69% utility on richer traces precisely because rigidly-generated allowlists can be too tight or too coarse for real workflows.)
- **DSL expressiveness ceiling.** Conditions are predicates over a single call's arguments. It does not natively reason about *cross-call data provenance* — e.g. "block if this recipient value originally came from an untrusted email body." It constrains values, not their lineage. (This is exactly the gap Agent-Sentry fills.)
- **Trust hinge on the user query.** The whole model assumes `o₀` is trusted and untrusted content never reaches the initial-policy stage. Ambiguous or under-specified user intent → either over-broad policy or broken tasks.
- **Step-A injection surface is reduced, not zero.** Update logic deliberately keeps untrusted output out of the "should we update?" decision, but the candidate-generation step (Step B) does see untrusted context; the SMT subset check is what contains the damage there.
- **Expansion approvals are a UX cost** and an attack pressure point — social-engineering a human into approving an expansion bypasses the guarantee.
- **No anomaly/provenance signal.** A call fully inside the allow-set that is nonetheless attacker-induced is allowed. Progent is least-privilege, not intrusion detection.

## Best pieces to steal for ddbt

ddbt's known tradeoff is that its **step-judge reads untrusted content and is therefore injectable**. Progent's central lesson is *don't put the LLM on the enforcement path at all for the decisions you can make deterministically.* Concrete mappings:

1. **Add a deterministic privilege envelope below the step-judge (Boundary between judge and tools).** Today the LLM judge is the gate. Borrow Progent's model: derive a per-session **allow-set of (tool, argument-constraints)** from the *trusted user task* at session start, enforced by pure predicate evaluation. The judge then operates *inside* that envelope. An injected judge can at worst allow something already inside the envelope — it can't grant a tool/recipient/path the envelope never permitted. This directly bounds the injectable-judge tradeoff. (Aligns with the v3 "structural scope envelope" idea — Progent is a concrete, benchmarked instantiation.)

2. **Make the suspicion ratchet a provable monotonic-confinement check, not just a score.** ddbt's session-suspicion "never lowers." Progent shows how to make scope *itself* monotonically shrink with a decidable check: when the agent's plan implies a policy change, use a subset test (Z3 or, more cheaply, a structural containment check over the constraint sets) to auto-apply *narrowing* and force a gate only on *expansion*. This turns "high_impact → gate" from a per-call LLM judgment into a deterministic "this requires more privilege than currently granted → gate."

3. **Split the policy/update decision to keep untrusted content out of the trigger.** Mirror Progent's two-step update: decide *whether* scope needs to change using only trusted context (user task + tool schema), and only generate the *new* constraints with full context — then run the deterministic containment check. This shrinks the surface of the injectable component without removing the LLM's planning value.

4. **JSON-Schema-as-policy + off-the-shelf validator** is a cheap, robust enforcement substrate that plugs into structured-output APIs and needs no custom parser — a good fit for a hook-based sandbox. Pair it with ddbt's existing **Boundary 0 hash integrity** so the active policy itself is integrity-checked.

5. **Return reasoned blocks to the agent** (Progent fallbacks) rather than hard-deny, to preserve utility under tight scope — complements ddbt's allow/gate/deny so a denied call yields a re-plan signal, not a dead session.

6. **Generic + task policies layered with priority** maps onto ddbt's Axis 1 (always-on) vs Axis 2 (toggleable): encode always-on guardrails as a generic policy layer beneath the per-session generated policy, with deny-wins ordering — making the two axes a deterministic policy stack rather than two LLM prompts.

## Sources

- [Progent: Securing AI Agents with Privilege Control — arXiv:2504.11703 (abstract)](https://arxiv.org/abs/2504.11703)
- [Progent — full HTML text](https://arxiv.org/html/2504.11703)
- [HuggingFace paper page](https://huggingface.co/papers/2504.11703)
- [dblp record](https://dblp.org/rec/journals/corr/abs-2504-11703.html)
