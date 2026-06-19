# DRIFT — secure-planner + dynamic-validator + injection-isolator defense for LLM agents

- **Source:** "DRIFT: Dynamic Rule-Based Defense with Injection Isolation for Securing LLM Agents." Hao Li, Xiaogeng Liu, Hung-Chun Chiu, Dianqi Li, Ning Zhang, Chaowei Xiao (SaFo-Lab). NeurIPS 2025. arXiv:2506.12104 (v1 13 Jun 2025; last revised 26 Mar 2026). https://arxiv.org/abs/2506.12104 — VERIFIED (arXiv + OpenReview + NeurIPS poster + GitHub SaFo-Lab/DRIFT all consistent).
- **Category:** Plan-anchored runtime monitor. System-level (architecture-agnostic) defense against direct and indirect prompt injection. Combines an upfront plan (control-flow + data-flow spec), per-step dynamic policy adaptation, and memory-stream sanitization. No model fine-tuning required.

## Pipeline (stage by stage)

DRIFT (the paper's expansion is "Dynamic Rule-based Isolation Framework for Trustworthy agentic systems") wraps an existing tool-using agent with three components that run in a fixed order. The defining design choice: the *user query alone* — captured before any environment interaction — is treated as the only fully-trusted intent signal, and everything downstream is validated against it.

1. **Plan construction (once, upfront, LLM).** A **Secure Planner** receives only the user query (no tool outputs yet, so it is not yet injectable) and emits two artifacts:
   - a **minimal function trajectory** — an ordered sequence of subtasks/tool calls decomposed from the query. This is the *control-flow* constraint. "Minimal" matters: it is the smallest set of calls needed to satisfy the query, so anything extra is by construction suspect.
   - a **JSON-schema-style parameter checklist** per function node — required parameters and their value dependencies. This is the *data-flow* constraint, letting the system detect parameter tampering even when the right tool is called.
   In the released code this stage is gated behind a `--build_constraints` flag.

2. **Agent execution (unmodified agent loop).** The wrapped coding/tool agent runs normally, proposing tool calls one at a time.

3. **Per-step validation (after every tool call, mixed deterministic + LLM).** The **Dynamic Validator** intercepts each proposed/executed call:
   - It integrates the call into the running trajectory and **compares against the minimal trajectory** and the parameter checklist (largely deterministic structural comparison).
   - **If the call is aligned** with the plan → approved automatically.
   - **If the call deviates** (function not in plan, or parameters mismatch the checklist), the validator assigns the deviated function a **privilege category — Read / Write / Execute**:
     - **Read** (read-only, e.g. `get_inbox`): low risk → approved automatically even though it deviates.
     - **Write** (data modification) and **Execute** (triggers third-party side effects): high risk → escalated to an **LLM intent-alignment check** that asks "does this deviated function still align with the user's original intent?" using a curated prompt.
   - **Dynamic policy update (the "drift" the name refers to):** if the intent-alignment check passes, the deviated function and its parameters are *incorporated into the minimal function trajectory and parameter checklist*. The plan is therefore not static — it ratchets/expands to absorb legitimate, intent-consistent deviations, so the same deviation won't re-trigger review later. If the check fails, the call is rejected.

4. **Output sanitization (after tool returns, LLM detector + deterministic mask).** The **Injection Isolator** inspects each tool output for instructions that conflict with the user's original query (an LLM detector with a curated system prompt). Conflicting instructions are **masked by an external (program/deterministic) component before the message is written into the agent's memory stream**, yielding a "safe memory stream." This protects long-horizon sessions where an injected instruction would otherwise persist in context and fire on a later turn.

5. **Loop.** Cleaned output → memory → next agent reasoning cycle.

**Determinism split.** Deterministic: trajectory/checklist structural comparison, Read/Write/Execute categorization, the masking operation itself. LLM-based: initial planning, the Write/Execute intent-alignment judgement, and injection detection in outputs.

## Key mechanisms

- **Pre-commitment to a minimal plan from the trusted query.** Because the plan is built before any untrusted tool output is seen, it is an *uninjectable* reference. All later untrusted content is checked against it rather than trusted on its own terms. This is structurally stronger than judging each call in isolation.
- **Dual constraint: control flow (trajectory) + data flow (parameter checklist).** Catches both "wrong tool / extra tool" (control deviation) and "right tool, poisoned argument" (data deviation, e.g. exfiltration to an attacker-supplied address).
- **Privilege-graded deviation handling (Read/Write/Execute).** Not all deviation is equal. Read deviations are auto-allowed (utility preservation); only side-effecting deviations pay the cost of an LLM intent check. This is a cheap, principled gate.
- **Monotonic plan expansion.** Approved deviations are folded back into the plan, so the validator adapts to legitimate open-ended behavior without re-litigating every step — addressing the brittleness of purely static-policy defenses.
- **Memory-stream isolation.** Injected instructions are removed *before entering memory*, not merely ignored at decision time. This is the explicitly-stated answer to "long-term risk": a poisoned instruction that survives in context can be triggered many turns later.

## Strengths / what's genuinely good

- **Trusted-root design.** Anchoring everything to the query-only plan gives a clean, hard-to-inject trust root. The planner never reads attacker content.
- **Dynamic without giving up the anchor.** It updates rules at runtime (its headline claim vs. static-policy defenses like Progent) but each update is itself gated by an intent check tied back to the original query, so adaptation does not silently erode security.
- **Strong empirical results at low utility cost.** On AgentDojo (GPT-4o-mini): DRIFT ~1.35% ASR vs. Progent's ~9.39%; benign utility ~57% (reported higher than the CaMeL baseline's ~35%). On ASB: ~4.8% ASR vs. Progent's ~15.8%. Evaluated across multiple model providers and agent suites (banking, slack, travel, workspace, shopping, github, dailylife). Also reports on the AgentDyn benchmark.
- **Architecture-agnostic, no fine-tuning.** Pure wrapper around an existing agent; portable across models — directly relevant to a hook-based sandbox.
- **Defense-in-depth layering.** Control-flow, data-flow, and content-injection are handled by separate components, so a miss in one layer can be caught by another.

## Limitations / failure modes

- **The intent-alignment validator and the injection detector are themselves LLMs that read untrusted content** — the same injectability tradeoff ddbt already acknowledges for its step-judge. A sufficiently clever injection can target the validator's intent check or the isolator's detector. DRIFT mitigates (the *planner* is blind to untrusted content) but does not eliminate this.
- **Plan quality is a single point of failure.** A bad or over-broad initial plan from the Secure Planner either over-blocks (utility loss) or over-permits. Garbage plan → garbage enforcement.
- **Monotonic plan expansion can be gamed.** If an attacker can get one borderline Write/Execute deviation past the intent check, it is permanently folded into the plan and never re-examined — analogous to a ratchet that only loosens.
- **Weak on open-ended / exploratory tasks.** The paper reports reduced completion on open-ended tasks (~17.8% vs ~25.7% baseline) — a minimal pre-plan poorly fits work whose shape isn't known up front. For short tasks (trajectory length ≤ 2) static policies actually beat DRIFT, so the dynamic machinery only pays off on longer trajectories.
- **Masking semantics underspecified.** The exact mechanism for *how* conflicting instructions are excised from tool output is not fully detailed; aggressive masking risks destroying legitimate content the agent needs.
- **Benchmark scope.** Authors note benchmark domains do not fully cover real-world tasks/attacks.

## Best pieces to steal for ddbt

ddbt today judges each system-touching call largely in isolation (Axis 1 goal-fidelity, Axis 2 intrinsic harm) with an adaptive session-suspicion ratchet. DRIFT's plan anchor is the missing "what was this session even supposed to do?" reference.

1. **Add an uninjectable plan root computed from the original task before any tool output is seen.** This is DRIFT's strongest idea and maps cleanly onto ddbt's v3 "blind judge / structural scope envelope" direction. Generate a **minimal expected tool trajectory + parameter/argument checklist** from the user task at session start, while the planner LLM is exposed only to trusted input. Store it in the per-session SQLite alongside the audit log. ddbt's step-judge then evaluates "does this call fit the trusted plan?" instead of (or in addition to) judging the call in a vacuum — directly hardening Axis 1 against injection, because the *reference* can't be poisoned.

2. **Privilege-graded gating keyed to side effects (Read/Write/Execute), not just high_impact.** ddbt currently gates on `high_impact`. Borrow DRIFT's cheaper, sharper rule: auto-allow read-only deviations, reserve the expensive LLM judgement for Write/Execute deviations. This reduces judge calls (and judge attack surface) while focusing scrutiny where damage happens.

3. **Memory/context isolation, not just output quarantine.** ddbt quarantines tool outputs in SQLite (no-leak invariant) but the agent still consumes raw tool output into its context. Adopt DRIFT's **isolator before memory write**: run a detector that flags instructions in tool output conflicting with the trusted task, and mask/strip them before they enter the agent's working context. This complements ddbt's quarantine: quarantine stops exfiltration *out*, isolation stops injected instructions getting *in*. Keep the mask operation deterministic and log both raw and masked versions to the append-only audit log.

4. **Make the suspicion ratchet bidirectional in a controlled way via plan expansion.** ddbt's session-suspicion only goes up. DRIFT's complement: intent-consistent deviations expand the plan so they stop re-triggering review. ddbt could add a *plan-amendment* path (gated, audited, never lowering global suspicion) so legitimate exploratory work isn't endlessly gated — addressing DRIFT's own open-ended-task weakness while keeping the security ratchet.

5. **Heed the failure mode:** keep the plan-amendment gate from being a one-way ratchet an attacker can permanently widen. Unlike DRIFT, ddbt should re-examine plan-expanded calls when session suspicion is high (use ddbt's suspicion level to re-gate even previously-approved deviation classes).

## Sources

- [arXiv abstract — DRIFT (2506.12104)](https://arxiv.org/abs/2506.12104)
- [arXiv PDF](https://arxiv.org/pdf/2506.12104)
- [OpenReview forum (NeurIPS 2025)](https://openreview.net/forum?id=oY1Xnt83oJ)
- [OpenReview PDF](https://openreview.net/pdf/7e05f767d463d43be3b045378b14be5760ea2fc1.pdf)
- [NeurIPS 2025 poster page](https://neurips.cc/virtual/2025/poster/116028)
- [GitHub — SaFo-Lab/DRIFT (official implementation)](https://github.com/SaFo-Lab/DRIFT)
