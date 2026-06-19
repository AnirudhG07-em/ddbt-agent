# AgentSpec — a DSL + runtime interceptor that enforces hand-written/LLM-generated safety rules on every agent action

- **Source:** "AgentSpec: Customizable Runtime Enforcement for Safe and Reliable LLM Agents", Haoyu Wang, Christopher M. Poskitt, Jun Sun (Singapore Management University), arXiv:2503.18666 (March 2025 preprint). https://arxiv.org/abs/2503.18666
- **Category:** runtime policy enforcement (deterministic rule engine over an agent's action loop; DSL-driven; optional LLM rule synthesis)

## Pipeline (stage by stage)

AgentSpec sits *between* the agent's reasoning loop and the actual execution of tool/actions, intercepting at well-defined hook points. It is fundamentally a **deterministic rule engine**; the LLM is used only (a) optionally, offline, to *author* rules, and (b) optionally, at runtime, as one of several *enforcement* responses (`llm_self_examine`).

1. **Rule authoring (offline).** Rules are written in a small DSL (see grammar below). Two ways to produce them:
   - **Manual:** a domain expert writes rules + Python predicate implementations.
   - **LLM-assisted:** the system prompts a strong model (paper uses OpenAI o1) with the agent/tool descriptions, 3 example rules, and ~10% in-context examples; the model emits both the DSL rule specs *and* the Python predicate code. This is a one-time generation step, not in the hot path.

2. **Rule parsing (deterministic, startup).** Rules are parsed with an ANTLR4 parser into an in-memory rule set. ~1.42 ms average; happens once.

3. **Interception at the agent loop (runtime).** AgentSpec hooks the agent framework (implemented on LangChain v0.3.13, hooking `iter_next_step`) at three decision points:
   - `before_action` / `AgentAction` — the agent has *proposed* an action `a_i` but it has not run yet.
   - `state_change` / `AgentStep` — after an observation comes back.
   - `agent_finish` / `AgentFinish` — task completion.

4. **Trigger matching (deterministic).** For each active rule, check whether its trigger event `η_r` fired at this hook (e.g. `PythonREPL` about to run, `pedestrian_detected`, `pick`).

5. **Predicate evaluation (deterministic).** If triggered, evaluate all of the rule's predicates `p_r(u, τ_i)` — Python boolean functions over the user input `u` and current trajectory `τ_i` (e.g. `is_destructive_cmd`, `obstacle_distance_leq(n)`). A rule is "violated" iff *every* predicate evaluates true. ~2.83 ms (code) / ~1.11 ms (embodied). Note predicates can themselves be LLM-generated code, but at runtime they execute as ordinary Python.

6. **Enforcement (mostly deterministic).** On violation, apply the rule's enforcement action(s):
   - `stop` — terminate the action immediately (agent ends task). Deterministic, negligible cost.
   - `user_inspection` — pause and ask a human to proceed/abort. Deterministic gate; cost = human latency.
   - `invoke_action(<params>)` — run a predefined corrective action (e.g. set AV speed). Deterministic.
   - `llm_self_examine` — invoke an LLM reflection step that perceives the violation context and plans an alternative action `a_c = Δ(u, s'_i)` that continues toward the original goal. This is the only runtime-LLM enforcement path.

7. **Trajectory update & continue.** The trajectory `τ_i` is updated; the loop either halts or proceeds with the original/modified action.

### DSL grammar (as published)
```
rule <Id>
  trigger <Event>
  check   <Pred>*
  enforce <Enforce>+
end
```
Triggers are general (`state_change`, `before_action`, `agent_finish`) or domain-specific (`PythonREPL`; robotics `pick`/`pour`/`throw`; ADS `red_light_detected`/`pedestrian_detected`). Predicates support negation (`!`). Enforcement is one or more of the four actions above.

## Key mechanisms

- **Trigger / predicate / enforce triple as the unit of policy.** Cleanly separates *when to look* (trigger), *what's wrong* (predicate), and *what to do* (enforce). Predicates are arbitrary Python, so policy expressiveness is unbounded while the matching engine stays simple.
- **Deterministic hot path.** Parsing, trigger matching, predicate evaluation and `stop`/`invoke_action` enforcement are all deterministic and millisecond-scale. The LLM is off the critical path except for the optional `llm_self_examine` repair.
- **Offline LLM rule synthesis.** A strong model turns natural-language tool/agent descriptions into DSL rules + predicate code, lowering the authoring cost. One rule generalizes to ~30 risky code instances / ~21 embodied instances in their data.
- **Multiple graded responses, not just block.** `stop`, `user_inspection`, `invoke_action`, and `llm_self_examine` give a spectrum from hard-halt to human-gate to autonomous repair.
- **Framework-agnostic interception via fixed hook points** (proposed-action / post-observation / finish), portable across CodeAct, ReAct, Apollo (AV), etc.

## Strengths / what's genuinely good

- **Very low, predictable overhead** (single-digit ms vs. tens of seconds of agent runtime) because the decision engine is deterministic — no per-action LLM call required.
- **Auditable, inspectable policy.** Rules are explicit text; a human can read exactly what is enforced, unlike a monolithic judge prompt. No prompt-injection surface in the *matching* itself.
- **Strong empirical safety where rules exist:** >90% prevention of unsafe code executions (250/271), elimination of all hazardous actions across 10 embodied categories, 100% compliance in tested AV law-violation scenarios.
- **Graceful repair path** (`llm_self_examine`) lets the agent recover toward the goal instead of just dying.
- **Generalization per rule is decent** (one rule covers many concrete cases), so the policy set stays small.

## Limitations / failure modes

- **Coverage is exactly the rule set — no rule, no protection.** LLM-generated rules overfit to the provided examples and miss un-enumerated-but-similar risks (e.g. deleting a config file that wasn't named). This is the core weakness vs. a semantic judge.
- **False negatives from shallow predicates.** Predicate code relies on source-pattern/string matching; misses multi-step risks (e.g. picking a *lighted* candle) and compositional object properties ("kettle filled with wine, then heated"). Authors suggest data-flow analysis would help.
- **False positives from over-rigid rules.** Auto-generated rules can be "one-size-fits-all" (ban *all* pour actions; always-stop AV) when context would permit the action.
- **No native anti-prompt-injection notion.** AgentSpec checks the *action* against rules; it has no concept of "is this action a deviation caused by injected text in tool output." It would only catch an injection if the resulting action happens to trip a hand-written rule.
- **Authoring burden / subjectivity.** Manual rules need expert validation; LLM-generated rules need review. Quality of protection = quality of the rule set.

## Best pieces to steal for ddbt

- **Adopt the explicit deterministic pre-filter layer in front of our LLM step-judge.** ddbt currently routes *every* system-touching call to the LLM step-judge (the cost and the injectable-decider risk both live there). Put an AgentSpec-style `trigger → predicate → enforce` deterministic rule engine *before* the judge: hard-deny obviously-destructive ops (`rm -rf`, secret exfil patterns, writes outside workspace) and hard-allow obviously-safe ones (read-only, in-workspace) with zero LLM involvement. Only the ambiguous middle reaches the judge. This cuts latency and shrinks the attack surface that touches untrusted bytes.
- **Steal the four graded enforcement actions and map them onto our allow/gate/deny.** `stop`→deny, `user_inspection`→gate, `invoke_action`→a deterministic remediation (e.g. force a write into the staging overlay), and crucially `llm_self_examine`→a structured "re-plan toward the trusted goal" step we can trigger when the suspicion ratchet hits ELEVATED, instead of only blocking.
- **Use offline LLM rule synthesis to seed Boundary 0 and the deterministic layer.** At session/config load, generate ddbt deny/allow predicates from the *trusted* task description + the registered tool/MCP descriptions — one-time, off the hot path, exactly like AgentSpec's o1 step. These predicates read only trusted inputs, so they are not injectable, complementing our (injectable) content-reading judge.
- **Borrow the DSL's auditability for our audit log.** Record, per gated/denied call, *which deterministic rule (id) or which judge axis* fired. AgentSpec's named, text-readable rules make post-hoc audit far clearer than a judge verdict alone — append the rule id to our append-only log.
- **Note what NOT to copy:** AgentSpec has no anti-injection / goal-fidelity axis at all. It is a *complement* to ddbt's Axis 1, not a replacement — use it for the cheap, certain cases and keep the semantic judge for "is this action a deviation from the trusted goal."

## Sources
- [arXiv abstract: AgentSpec (2503.18666)](https://arxiv.org/abs/2503.18666)
- [AgentSpec full HTML (v1)](https://arxiv.org/html/2503.18666v1)
- [AgentSpec PDF](https://arxiv.org/pdf/2503.18666)
- [Hugging Face paper page](https://huggingface.co/papers/2503.18666)
- [alphaXiv overview (v3)](https://www.alphaxiv.org/overview/2503.18666v3)
