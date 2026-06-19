# ARMO — runtime-derived least privilege for AI agents via staged "progressive enforcement"

- **Source:** ARMO (armosec.io) engineering blog series on AI-agent sandboxing & progressive enforcement. Primary posts: *AI Agent Sandboxing & Progressive Enforcement: The Complete Guide* and *Runtime-Derived Least Privilege for AI Agents: From Observed Behavior to Enforcement*. Vendor/product material, 2025–2026, **not a peer-reviewed paper**. ([Progressive enforcement guide](https://www.armosec.io/blog/ai-agent-sandboxing-progressive-enforcement-guide/) · [Runtime-derived least privilege](https://www.armosec.io/blog/runtime-derived-least-privilege-for-ai-agents/)) — **VERIFIED as vendor content** (ARMO is a real Kubernetes-security company; these are product/marketing engineering posts, *not* an academic publication — treat method claims as vendor-described, not independently benchmarked).
- **Category:** Runtime-derived, evidence-based least-privilege enforcement. Observe real agent behavior → derive an enforcement envelope → tighten progressively. Kernel-level (eBPF), Kubernetes-native, multi-substrate (network / syscall / app-layer).

## Pipeline (stage by stage)

ARMO's core thesis: you cannot *declare* an AI agent's correct behavior up front (the agent is non-deterministic and tool-using), so **let the agent demonstrate its behavior, then enforce the demonstrated envelope.** This is the inverse of writing a policy first. The lifecycle is a four-stage maturity model, and the *derivation* step (turning evidence into policy) is broken out as its own four-decision pipeline.

All of this is **deterministic** observation + statistics + kernel enforcement. There is **no LLM in the enforcement path** — the "AI" is the workload being constrained, not the constraint mechanism.

### Stage 1 — Discovery ("Flying Blind" → inventory)
Automated detection builds a runtime-derived **"AI Bill of Materials" (AI-BOM)**: every agent, model, connected RAG source, and external tool across the clusters — **without manual tagging or developer self-reporting**. This inventory is also the *invalidation trigger* later (see re-baseline).

### Stage 2 — Observation ("See Everything, Enforce Nothing")
Deploy in **visibility-only mode** and record, per agent/container, the full behavioral footprint: tools invoked, APIs called, network destinations, spawned processes, file access, data flows. This builds the behavioral profile ARMO brands **"Application Profile DNA"** — a representation of each container's *actual* runtime behavior, used both for anomaly detection and as the eventual enforcement source. Typical window: **7–14 days**, but length is **coverage-driven, not calendar-driven** (see below).

### Stage 3 — Selective Enforcement ("Trust but Verify")
Promote observed behaviors into enforcement policies, **starting with the highest-risk agents first** (external-facing, sensitive-data access, elevated privileges). Crucially, **mixed enforcement postures are allowed**: for high-confidence agents, *block* deviations outright; for the rest, *alert* on deviations without blocking — visibility without production-disruption risk. This graduated rollout is the mechanism for keeping false positives from breaking prod.

### Stage 4 — Full Least Privilege ("Enforced by Evidence")
Every agent runs inside a behavioral boundary derived from its observed behavior; deviations are blocked in real time. Enforcement is treated as **continuous**, not a one-time config: drift detection runs forever and baselines are re-derived on upstream change.

### The derivation sub-pipeline (evidence → enforceable artifact)
ARMO calls this out as where "most teams stall" and forces **four explicit decisions** — defaulting any of them creates "invisible constraints" that quietly break least privilege:
1. **Granularity** — how finely to express the rule (e.g. exact path vs structural envelope; per-method HTTP vs per-host).
2. **Closure** — *structural* closure, not *literal*. Policies encode "the structural envelope around the observed set" rather than the exact observed sequences, so legitimate variation is tolerated while critical dimensions stay constrained.
3. **Confidence** — a behavior is included only if it **appears more than N times across more than M distinct sessions** (suggested **N=5, M=3** for a stable 14-day window). Behaviors below threshold are **surfaced in a review report**, neither silently allowed nor silently dropped.
4. **Validity** — when the policy must be re-derived (event-driven, below).

Each generated policy **surfaces its closure rule, confidence threshold, validity triggers, and substrate selection** — i.e. the enforcement artifact is self-describing/auditable.

## Key mechanisms

- **"Application Profile DNA" / behavioral baseline** — per-container observed-behavior fingerprint that *is* the policy source of truth. Evidence-based; eliminates guesswork in policy authoring.
- **Coverage-stop, not calendar-stop** — the observation window is "long enough" when the **rate of newly-observed API surfaces / syscalls / network destinations drops below a threshold** (example: fewer than one new dimension per 24h). This is the deterministic "is the baseline complete?" test.
- **Confidence threshold (N×, M sessions)** — separates stable behavior (enforce) from rare/one-off behavior (report only), the primary false-positive control.
- **Multi-substrate enforcement from one evidence stream** — a single sensor produces policies across three layers simultaneously so they "don't drift independently":
  - **Network/identity:** Kubernetes NetworkPolicy, IRSA, IAM boundary policies.
  - **Syscall/process:** seccomp profiles, Linux capabilities, syscall sequences.
  - **Application-layer:** HTTP methods/paths, **MCP tool invocations**, model-API parameters.
- **eBPF kernel-level enforcement** — operates at the Linux kernel "without modifying application code, injecting sidecars, or requiring developer cooperation." Stated overhead: **1–2.5% CPU, ~1% memory**. Security team deploys independently of developers.
- **Selective / graduated rollout** — block-for-high-confidence, alert-for-the-rest, riskiest agents first.
- **Event-driven re-baseline (validity triggers)** — model version updates, prompt-template commits, and tool-catalog changes each **trigger a re-baseline**, caught via the AI-BOM. Plus controlled bypasses: **alert-only mode for low-confidence policies, time-boxed exception windows for incident response, and a re-baseline trigger when new evidence justifies new behavior.**
- **Post-enforcement detection retention** — behaviors that didn't clear the confidence threshold **stay visible to detection** after enforcement deploys, so their re-occurrence raises an alert rather than a silent allow.

## Strengths / what's genuinely good

- **Policy authoring without a spec.** The hardest part of sandboxing an agent — knowing what to allow — is solved empirically. No human guesses the allow-list.
- **Deterministic enforcement path.** Once derived, enforcement is kernel-level eBPF/seccomp/NetworkPolicy — no LLM in the loop, low overhead, hard to prompt-inject.
- **Explicit confidence semantics.** N-times-across-M-sessions plus "report, don't silently include/exclude" is a genuinely good rule for distinguishing signal from one-offs and keeping the policy auditable.
- **Graceful rollout model.** Alert-only → selective-block → full-block, riskiest-first, is a pragmatic adoption path that avoids the classic "lock it down and break prod" failure.
- **Structural (not literal) closure** tolerates legitimate variation, reducing brittleness vs naive "replay exactly what I saw" allow-lists.
- **Self-describing policies + re-baseline triggers** make the system maintainable as the underlying agent/model/tools evolve.

## Limitations / failure modes

- **Vendor material, not independently verified.** Overhead numbers, the N=5/M=3 heuristic, and the coverage-stop threshold are vendor-stated; no peer-reviewed benchmark. Treat as design guidance, not proven results.
- **Learning-phase exposure.** During Stages 1–2 there is **no enforcement** — an agent compromised *before* baselining will have its malicious behavior learned as "normal." Baseline poisoning is the central attack: feed the agent attacker-desired behavior during observation and it becomes part of the allowed envelope.
- **Drift vs legitimate change.** Distinguishing malicious deviation from a legitimate new behavior is unsolved in general; the system leans on humans approving re-baselines and time-boxed exceptions.
- **Coarse on *intent*.** Enforcement is on *mechanism* (this host, this syscall, this path), not *purpose*. An agent that does something harmful *within* its learned envelope (e.g. exfiltrating to an already-observed destination) is not caught.
- **Kubernetes/Linux/eBPF-bound.** The concrete enforcement substrate assumes containerized Linux workloads — not directly applicable to a local CLI coding agent on macOS without re-platforming.
- **Confidence-threshold tuning is load-bearing.** Too strict → false positives in prod; too loose → over-broad envelope. The "right" N/M depends on workload variability.

## Best pieces to steal for ddbt

1. **Add an observe→baseline→enforce lifecycle around ddbt's per-call judge.** ddbt today judges every system-touching call live with an LLM. ARMO's lesson: *learn* the per-session/per-project behavioral envelope deterministically, then let the cheap, deterministic envelope handle the common case and reserve the LLM step-judge for **out-of-envelope** calls. This cuts judge invocations (cost + injection surface) dramatically and gives a deterministic fast-path.
2. **Confidence semantics for ddbt's session memory.** Adopt "behavior must recur N times across M sessions before it's auto-allowed; otherwise surface it in a review report." This is a principled, auditable way to graduate a tool/destination from "always gate" to "allow" — and it composes with ddbt's append-only audit log and the never-lowering suspicion ratchet (only behavior that clears the bar relaxes; suspicion still only ratchets up).
3. **Structural-closure scope envelope = the v3 doc's "structural scope envelope," made concrete.** Encode allowed file roots / network hosts / MCP tools as *structural envelopes* (host-pattern, path-prefix, tool-id set) derived from observed behavior, enforced **deterministically before the judge runs** — exactly answering ddbt's KNOWN TRADEOFF by shrinking what the injectable LLM judge has to decide.
4. **Coverage-stop metric for "is this session's profile stable?"** Use ARMO's "rate of newly-observed dimensions" idea to decide when ddbt can trust a per-project baseline vs when it's still in exploratory/gate-everything mode.
5. **Event-driven re-baseline tied to Boundary 0.** ddbt already hashes config/MCP descriptors. Wire **hash change = invalidate the learned envelope = re-enter gate-everything mode**, mirroring ARMO's "tool-catalog change triggers re-baseline." This is a natural fusion of Boundary 0 with a learned-envelope layer.
6. **Alert-only vs block, riskiest-first** maps onto ddbt's allow/gate/deny: low-confidence learned rules → *gate* (the alert-equivalent), high-confidence → *allow*, never-seen high-impact → *gate/deny*. A clean confidence-to-action mapping for the existing three-way decision.

## Sources

- [ARMO — AI Agent Sandboxing & Progressive Enforcement: The Complete Guide](https://www.armosec.io/blog/ai-agent-sandboxing-progressive-enforcement-guide/)
- [ARMO — Runtime-Derived Least Privilege for AI Agents: From Observed Behavior to Enforcement](https://www.armosec.io/blog/runtime-derived-least-privilege-for-ai-agents/)
- [ARMO — What Is AI Agent Sandboxing? Kubernetes-Native Enforcement Explained](https://www.armosec.io/blog/what-is-ai-agent-sandboxing-kubernetes-native-enforcement-explained/)
- [ARMO — Runtime Observability for AI Agents](https://www.armosec.io/blog/runtime-observability-for-ai-agents/)
- [ARMO — AI Agent Governance: From Policy Framework to Runtime Enforcement](https://www.armosec.io/blog/ai-agent-governance/)
