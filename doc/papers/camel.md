# CaMeL — a dual-LLM + capability/data-flow defense that makes prompt injections structurally unable to alter control or data flow

- **Source:** "Defeating Prompt Injections by Design," Edoardo Debenedetti, Ilia Shumailov, Tianqi Fan, Jamie Hayes, Nicholas Carlini, Daniel Fabian, Christoph Kern, Chongyang Shi, Andreas Terzis, Florian Tramèr (Google / Google DeepMind / ETH Zurich), 2025. arXiv:2503.18813 (v2, 24 Jun 2025). PDF: https://arxiv.org/pdf/2503.18813 . Code: https://github.com/google-research/camel-prompt-injection . CaMeL = "CApabilities for MachinE Learning."
- **Category:** Privilege-separated dual-LLM + control-flow-integrity + capability-based data-flow control (deterministic interpreter mediates all tool calls). Defends against indirect prompt injection (PIA) by design, without modifying the underlying LLM.

## Pipeline (stage by stage)

CaMeL turns a natural-language query into a deterministically-executed program. The trusted user query drives control flow; untrusted tool data can only ever be *data*, never instructions.

1. **P-LLM (Privileged LLM) — plan as code [LLM].** The P-LLM receives ONLY the trusted user query plus a system prompt listing available tools/classes as Python function signatures. It emits a code block (Markdown-fenced) of *pseudo-Python* expressing the user's intent as a sequence of tool calls and data transformations. Crucially the P-LLM **never sees tool outputs or Q-LLM outputs** — tool return values are bound to variables and the P-LLM only sees that a variable exists, not its content. This is the structural guarantee: injected content in tool outputs can never reach the planner, so it cannot change the plan.

2. **CaMeL custom Python interpreter — execute [deterministic].** A custom interpreter (built on Python's `ast`, over a *restricted subset* of Python — no arbitrary function definitions, restricted constructs) walks the AST node-by-node. It (a) executes tool calls against real APIs, (b) maintains a **data-flow graph** tracking which values each variable depends on, (c) propagates **capabilities**, and (d) checks **security policies** before every consequential tool call. The interpreter retries the P-LLM up to 10 times on exceptions (feeding back redacted error location/type), preserving interpreter state across retries.

3. **Q-LLM (Quarantined LLM) — parse untrusted data [LLM, sandboxed].** When the plan needs to extract structure from unstructured/untrusted text (e.g. "find Bob's email in this email body"), the interpreter calls the Q-LLM, which the P-LLM sees merely as a callable function (e.g. `query_quarantined_llm(prompt, output_schema=...)`). The Q-LLM has **no tool access**, **does not see the system prompt**, and returns only data conforming to a P-LLM-specified Pydantic schema (structured output / constrained decoding). An injected `have_enough_information: bool` field lets it signal failure; if `False`, the interpreter raises `NotEnoughInformationError` (the Q-LLM **cannot** free-text back to the P-LLM — that channel would itself be an injection vector).

4. **Capability propagation [deterministic].** Every value carries a capability tag recording its **sources** (provenance: `User` for literals from the query, `CaMeL` for derived values, or a specific tool id; tools can also tag an "inner source" e.g. the sender of a fetched email) and its **readers** (allowed readers: the `Public` singleton or a set of users/emails). Data dependencies propagate capabilities through the data-flow graph (e.g. `c = a + b` → `c` depends on `a` and `b`; readers intersect, sources union). For control-flow constructs there are STRICT and NORMAL modes — STRICT adds the `if`/loop condition as a dependency of everything assigned in the block (closing a side-channel), NORMAL does not.

5. **Policy enforcement at tool-call time [deterministic].** Before executing any consequential tool, the interpreter runs the relevant **security policy** — an ordinary Python function `policy(tool_name, kwargs) -> Allowed | Denied(reason)` — against the arguments' capabilities (and their full transitive dependencies in the graph). On `Denied`, execution halts; in a real deployment this becomes a user-confirmation prompt rather than a hard block. Policies are arbitrary Python (chosen over a DSL for expressiveness), e.g. "`send_email` only allowed if every recipient is in the readers set of the data being sent."

Deterministic vs LLM split: **Deterministic** = the interpreter, data-flow graph, capability propagation, policy engine. **LLM** = P-LLM (planning/codegen, sees only the query) and Q-LLM (data parsing, sees only the data it's handed, no tools). The two LLMs can be different models — the Q-LLM can be cheaper and even run locally, so the privileged model provider never sees tool outputs.

## Key mechanisms

1. **Control-flow / data-flow separation by construction.** Because the plan is fixed code generated *before* any untrusted data is seen, injections cannot redirect *which* operations run. This is the core "by design" property — it generalizes Willison's Dual-LLM pattern by extracting an explicit control-flow plan, not just isolating the planner.
2. **Capabilities = provenance (sources) + authorization (readers) attached to every value.** Inspired by libcap / Capsicum / CHERI. Lets policies reason per-value about where data came from and who may read it, far more granular than coarse "trusted/untrusted" tainting.
3. **Quarantined LLM with constrained structured output.** Untrusted text is only ever processed by a tool-less LLM forced into a typed schema, bounding what an injection can do (it can corrupt a field's *value* but cannot call tools or change the plan).
4. **Policies as arbitrary Python checked against the dependency graph.** Expressive, per-tool, can encode "data flows only to authorized readers," "consequential tools need trusted sources," etc.
5. **Fail-shut interpreter with bounded retries and redacted error feedback.** Exceptions that depend on untrusted data are redacted before being shown to the P-LLM (so error messages can't smuggle injections back into the planner).

## Strengths / what's genuinely good

- **Provable, by-design guarantee against control-flow hijacking**, independent of model robustness — the LLM is never trusted to "resist" injection.
- **Empirically strong:** on AgentDojo, even with NO security policies (isolation alone), CaMeL drops successful attacks dramatically (e.g. Gemini 2.5 Pro: 300 → 0). With policies it solves 77% of tasks with provable security vs 84% undefended — a small utility cost. Of 949 attacks, the only "successful" ones against CaMeL are explicitly outside its threat model (not actual injections).
- **Provenance for free:** the data-flow graph can tell the user where any displayed content originated (useful for anti-phishing UI), even where CaMeL can't block.
- **Fine-grained, expressive policies** without per-prompt enumeration; shifts security decisions off the user (reduces confirmation fatigue) onto the capability system.
- **Model-agnostic and privacy-friendly:** P-LLM provider never sees tool outputs; Q-LLM can be a cheap/local model with ~1% utility drop.

## Limitations / failure modes

- **Out of scope: text-to-text attacks with no data/control-flow consequence** — e.g. an injection making the assistant mis-summarize an email, or phishing the user via `print` (the AgentDojo travel-suite "Riverside View Hotel" review attack succeeds precisely because it rides the legitimate display channel). CaMeL explicitly does not defend these.
- **"Data requires action" failures:** if the *plan itself* depends on data only the Q-LLM can read (e.g. "do the actions specified in this email"), the P-LLM can't write the plan and the task fails. This is an inherent Dual-LLM-pattern limitation.
- **Q-LLM can still be wrong/manipulated within its schema** (e.g. coerced to return an empty summary); structured output bounds but doesn't eliminate this.
- **Underdocumented tool APIs hurt utility** (P-LLM can't predict output structure → can't write parsing code); travel suite suffered most.
- **No atomicity/rollback** for partially-executed plans with side effects.
- **Requires the P-LLM to write correct restricted-Python**, and the whole approach assumes tool wrappers correctly label provenance.

## Best pieces to steal for ddbt

- **For the step-judge → add a control-flow plan anchor (the single biggest idea).** ddbt's judge reads untrusted tool output and is therefore injectable (the known tradeoff). CaMeL's lesson: derive the *intended* plan/scope from the trusted user request *before* untrusted data arrives, and judge each tool call against that fixed plan rather than re-deciding from injectable context. Even a lightweight version — extract an allowed-action envelope from the initial trusted prompt and make Axis-1 (goal-fidelity/anti-injection) check "is this call consistent with the pre-committed plan?" — moves ddbt closer to a structural guarantee and shrinks the judge's reliance on untrusted content.
- **For quarantine → adopt the Q-LLM constrained-extraction pattern.** ddbt already quarantines tool outputs in SQLite. CaMeL shows the right way to *consume* quarantined data: never feed raw untrusted text into a tool-capable / decision-making LLM; instead extract only the needed fields via a tool-less LLM forced into a typed schema. ddbt could expose quarantined rows to the agent only through such schema-constrained extraction, drastically cutting the injection surface of the no-leak path.
- **For policies → capabilities (provenance + readers) per quarantined value.** Tag each quarantined output with sources (which tool/origin) and allowed-readers, and have the step-judge / a deterministic pre-check enforce "consequential tool args must come from trusted sources" and "egress only to authorized readers." This is a deterministic guard that runs *before* the LLM judge and catches the clear exfiltration cases without an injectable LLM in the loop — directly strengthening ddbt's no-leak invariant.
- **For Boundary 0 / audit → keep a data-flow/provenance graph.** Recording per-value provenance gives ddbt's audit log a "where did this come from / who can read it" trace and enables the same anti-phishing UI CaMeL describes.
- **For the suspicion ratchet → fail-shut + bounded retry with redacted feedback.** CaMeL redacts untrusted content out of error messages before they reach the planner; ddbt should likewise ensure that nothing fed back into the judge/agent on a deny/retry carries untrusted content that could re-inject.

## Sources

- [Defeating Prompt Injections by Design — arXiv:2503.18813](https://arxiv.org/abs/2503.18813)
- [Full PDF (v2)](https://arxiv.org/pdf/2503.18813)
- [CaMeL code release (google-research/camel-prompt-injection)](https://github.com/google-research/camel-prompt-injection)
- [AgentDojo benchmark (Debenedetti et al., NeurIPS 2024)](https://arxiv.org/abs/2406.13352)
