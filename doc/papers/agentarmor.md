# AgentArmor — program analysis over agent runtime traces (CFG/DFG/PDG + type system) against prompt injection

- **Source:** "AgentArmor: Enforcing Program Analysis on Agent Runtime Trace to Defend Against Prompt Injection." Peiran Wang, Yang Liu, Yunfei Lu, Yifeng Cai, Hongbo Chen, Qingyou Yang, Jie Zhang, Jue Hong, Ye Wu. arXiv:2508.01249 (2025; v2). https://arxiv.org/abs/2508.01249 — VERIFIED (arXiv + Semantic Scholar + ResearchGate consistent). Specific venue/peer-review status not confirmed (treat as arXiv preprint).
- **Category:** Static program analysis applied to *runtime* agent traces. Treats an agent's execution trace as a structured program, lifts it to an intermediate representation (CFG/DFG/PDG), attaches security types, and enforces information-flow policy via a type system. Architecture-controlled deployment; pre-execution blocking.

## Pipeline (stage by stage)

The core insight: **an agent's runtime trace is a program with analyzable semantics.** Once you accept that, the decades-old toolbox of compiler/program analysis (control-flow graphs, data-flow graphs, program-dependence graphs, type systems, information-flow control) becomes available to reason about whether untrusted data is illegitimately influencing sensitive actions. Three components run in sequence.

1. **Trace collection (deterministic hook).** AgentArmor "hooks the runtime" and collects the raw message stream: **system messages, user messages, tool messages, assistant messages.** These are normalized into "formatted traces." The threat model assumes the defender *controls the agent architecture* and can instrument internal thought steps before tool execution.

2. **Graph constructor — trace → IR (hybrid deterministic + LLM).** The formatted trace is lifted into graph-based intermediate representations capturing "intent dependency, control flow, data flow, and side effects." 
   - **Node types (≈9 semantic units):** `SystemPrompt`, `UserPrompt`, `LLM` (a model invocation), `Thought`, `ToolName`, `ToolParam`, `Tool`, `Observation`, `Data`.
   - **Three graphs built:**
     - **CFG (control-flow graph):** control-flow edges (execution order) + **control-dependency edges** (inferred semantic attribution of *why* a step happened).
     - **DFG (data-flow graph):** principal input/output edges (data into and out of tools) + **data-dependency edges** (relationships between data entities — e.g., an `Observation` from one tool flows into a later `ToolParam`).
     - **PDG (program-dependence graph):** integrates the two by copying data-related edges from the DFG and control-dependency edges from the CFG — the unified object policy is checked against.
   - **Dependency recovery is LLM-assisted.** A **dependency analyzer** (LLM) infers latent dependencies that aren't syntactically explicit in the trace: for each action it builds a prompt from preceding context and returns "a list of source elements," recovering hidden data/control dependencies (e.g., the model paraphrased a value rather than copying it verbatim). This is the key bridge — natural-language traces don't have explicit variable bindings the way code does, so an LLM reconstructs the implicit dataflow.

3. **Property registry — attach security metadata (lookup + typing).** A registry attaches security-relevant metadata to tools and data:
   - **Tool registry entries:** input parameters, return values, side-effect inputs/outputs, data types, semantic roles, **security types (confidentiality + integrity levels)**, and a **tool-level dataflow graph** mapping how a tool's parameters relate to its internal/external state changes (its read/write footprint).
   - **Data registry entries:** content, **type** (e.g., `local_folder`, `remote_file`, `remote_api`), and a **security type indicating integrity and confidentiality levels**. Provenance (local vs remote) drives integrity: remote/external data is low-integrity (untrusted).

4. **Type system — static inference + checking over the IR (deterministic).**
   - **Type:** `Type := {security_type, rule_type}` where `security_type` = (confidentiality, integrity) and `rule_type` encodes logical constraints over node behavior.
   - **Lattice ordering (information-flow / Denning-style):** information must not flow from high to low confidentiality, and must not be influenced by low-integrity inputs. Levels: **low / mid / high.**
   - **Type inference:** single-source propagation inherits the source type directly; **multi-source join uses lattice operations** — take the most restrictive confidentiality and the least-restrictive (lowest) integrity across sources (so any untrusted input taints the result).
   - **Two-phase checking:**
     - **Intra-node:** validate internal `rule_type` predicates on a node.
     - **Inter-node:** for **every edge**, verify `source.confidentiality ≤ dest.confidentiality` AND `source.integrity ≥ dest.integrity` (no high→low confidentiality leak; no low→high integrity influence).
   - **On violation:** **blocking** — rejection of the pipeline before the offending tool executes.

5. **Runtime mode.** Runs as detection + **pre-execution blocking**: traces are collected, the graph rebuilt, and static checking performed *before* tool execution, so a violating call is stopped rather than merely flagged after the fact.

**Determinism split.** Deterministic: trace hooking/normalization, graph edge construction from explicit structure, the type lattice inference and edge checking, blocking. LLM-based: the dependency analyzer that recovers implicit/latent dependencies (and any semantic-role inference feeding the registry).

## Key mechanisms

- **Trace-as-program reframing.** The conceptual core. Recasts opaque agent behavior as a CFG/DFG/PDG so that information-flow control — a rigorous, well-understood discipline — can be applied instead of ad-hoc LLM judgement.
- **PDG + security type system = taint tracking for agents.** Untrusted (remote, low-integrity) data is a taint source; sensitive sinks (side-effecting tools) are guarded; the inter-node integrity check is exactly "untrusted data must not influence a sensitive action." This is principled IFC, not heuristic.
- **LLM only where structure is missing.** The expensive/fallible LLM is confined to *dependency recovery* (turning prose into edges). The *decision* (policy check) is deterministic lattice arithmetic — so the security verdict is reproducible and auditable, and an injection in the data can't directly talk the type checker into allowing a flow.
- **Property registry as a declarative capability/sensitivity model.** Per-tool confidentiality/integrity labels + a per-tool dataflow footprint give a reusable, inspectable description of what each tool reads and writes — independent of any single session.
- **Configurable strictness.** Restrictive vs. permissive settings trade detection (TPR) against utility for ambiguous cases like "transfer execution."

## Strengths / what's genuinely good

- **Excellent measured results at near-zero utility cost.** On AgentDojo: overall ASR ~3% (from ~41% baseline, ~38pp reduction) with only ~1% utility drop (~72% vs ~73%). Average TPR ~93%, FPR ~2.6%. Robust across models (Claude-3.7 ~0.03% ASR, GPT-4o ~5.2%, GPT-4o-mini ~2%, Gemini-2.0 ~0.3%, Llama-3.3-70B ~0.8%).
- **Favorable on the security/utility frontier vs. peers.** Reported comparisons: SecAlign (~1% ASR but requires model fine-tuning); Progent (policy-based, ~2% ASR, ~64% utility); CaMeL (info-flow, ~0% ASR but ~48% utility). AgentArmor keeps utility high (~72%) at low ASR.
- **Auditable, reproducible verdicts.** Because the decision layer is a deterministic type check over an explicit graph, you can show *which edge* violated *which* policy — far more defensible than an LLM's opaque allow/deny.
- **Reuses mature theory.** Denning-style lattice IFC is decades-proven; the contribution is the lifting, not inventing new security semantics.
- **Whole-trace context.** Reasoning over the accumulated PDG catches multi-step / cross-tool laundering of tainted data that a per-call judge in isolation would miss.

## Limitations / failure modes

- **Dependency analyzer is an LLM and is the soft spot.** If it mis-recovers a dependency (misses an edge), tainted data can reach a sink "invisibly"; if it over-connects, false positives. The whole soundness of the downstream type check rests on the graph being right, and the graph is partly LLM-built.
- **"Transfer execution" failure mode (explicitly stated).** When the agent is *legitimately* instructed to read content and follow instructions inside it (e.g., "read file and follow instructions precisely"), the injected-instruction-vs-legitimate-instruction distinction collapses; the paper offers only a restrictive/permissive knob, not a clean answer.
- **Heavy overhead.** Graph construction dominates runtime (~69.6% of time) and the dependency analyzer adds significant token cost — non-trivial for latency-sensitive agents.
- **Strong deployment assumption.** Requires controlling the agent architecture and instrumenting internal thoughts before tool execution. Explicitly out of scope: compromised tool binaries / malicious backends, and model-level attacks (backdoors, poisoning).
- **Registry must be authored and kept current.** Per-tool confidentiality/integrity labels and dataflow footprints are manual metadata; wrong/stale labels silently weaken the guarantee. New/unknown tools have no registry entry.
- **Preprint.** Specific peer-reviewed venue not confirmed.

## Best pieces to steal for ddbt

ddbt currently makes per-call LLM judgements with quarantined outputs and a suspicion ratchet, and explicitly worries that the judge reads untrusted content (injectable). AgentArmor's deterministic IFC layer is the strongest available answer to "make the security *decision* uninjectable."

1. **Add a deterministic information-flow check as a layer beneath the LLM step-judge.** This is the single biggest steal. Maintain a running data-flow/taint graph over the session: label tool outputs from external/remote sources as **low-integrity (tainted)**, label sensitive sinks (network send, file write outside workspace, credential use, command exec) as guarded, and *deterministically deny* any call where tainted data influences a guarded sink — regardless of what the LLM judge thinks. Because this verdict is lattice arithmetic over an explicit graph, it is **not injectable** (the attacker's text is *data in* the graph, never an instruction to the checker). This directly closes ddbt's acknowledged "judge is injectable" tradeoff for the most dangerous class of actions, and it complements the v3 blind-judge idea.

2. **Build a property registry for ddbt's tools / MCP servers.** ddbt already has Boundary-0 hash-based config/MCP integrity. Extend it: for each tool/MCP method, record its **read/write footprint and confidentiality/integrity labels** (does it read external data? does it have side effects? does it touch secrets?). This declarative capability model lets the deterministic checker know which calls are sinks and which produce taint, and ties cleanly into the existing hash-gated integrity scanner (hash the registry too, so labels can't be silently edited).

3. **Confine the LLM to dependency recovery, keep the verdict deterministic.** AgentArmor's architectural lesson: use the LLM only to turn opaque history into structure (which earlier output flowed into this argument?), then decide with deterministic rules. ddbt could use its judge/an LLM to *recover provenance* ("this command argument was derived from the contents of `fetched_page.html`") and then let a deterministic taint rule make the allow/deny call. Verdicts become reproducible and audit-friendly — log the offending edge and policy into the append-only audit log.

4. **Whole-session PDG to catch multi-step laundering.** ddbt judges per call; an attacker can split an exfiltration across steps (read secret → transform → send) so no single call looks bad. Accumulate a session-level dependency graph (it lives naturally next to the SQLite quarantine store) so the integrity check sees the *path* from tainted source to sink across calls. This also gives the session-suspicion ratchet a concrete, structural signal to ratchet on (e.g., tainted-data-approaching-sink raises suspicion).

5. **Adopt the restrictive/permissive knob explicitly, mapped to ddbt's axes/suspicion.** Use a stricter IFC setting when Axis 2 (intrinsic harm) is enabled or session suspicion is high, permissive otherwise — a principled way to wire AgentArmor's strictness control into ddbt's existing toggles.

6. **Heed the "transfer execution" gap.** The hardest case (agent legitimately told to follow instructions found in data) is unsolved by AgentArmor too — ddbt should treat any flow where tool-output content becomes *instructions/commands* as a high-impact gate (never silent-allow), since the deterministic IFC layer alone won't disambiguate it.

## Sources

- [arXiv abstract — AgentArmor (2508.01249)](https://arxiv.org/abs/2508.01249)
- [arXiv abstract — v2](https://arxiv.org/abs/2508.01249v2)
- [arXiv HTML (v2)](https://arxiv.org/html/2508.01249v2)
- [Semantic Scholar entry](https://www.semanticscholar.org/paper/AgentArmor:-Enforcing-Program-Analysis-on-Agent-to-Wang-Liu/46a4e8c7d5fb84288c067c9ee769273a591226f2)
- [ResearchGate record](https://www.researchgate.net/publication/394293301_AgentArmor_Enforcing_Program_Analysis_on_Agent_Runtime_Trace_to_Defend_Against_Prompt_Injection)
