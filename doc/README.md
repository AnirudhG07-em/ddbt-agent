# Prior art — pipeline summaries & what ddbt should steal

This folder summarizes the agent-security systems whose pipelines are worth mining for
ddbt. Each file follows the same template (Pipeline → Key mechanisms → Strengths →
Limitations → **Best pieces to steal for ddbt** → Sources). Sources were verified against
primary material (arXiv PDFs, official repos, vendor docs); verification caveats are noted
per file.

| File | System | One line | Source status |
|---|---|---|---|
| [lga.md](lga.md) | **LGA** | Four-layer governance with an L2 intent judge | Verified — arXiv:2603.07191 (single author Yuxu Ge, York; broader real title). *This is the injectable-judge design ddbt critiques.* |
| [camel.md](camel.md) | **CaMeL** | Dual-LLM: privileged planner emits code, quarantined LLM never gains authority | Verified — arXiv:2503.18813 (Google/DeepMind/ETH), repo live |
| [fides.md](fides.md) | **FIDES** | Information-flow control: integrity×confidentiality labels, hide/reveal | Verified — arXiv:2505.23643 (Microsoft), repo live |
| [progent.md](progent.md) | **Progent** | Programmable least-privilege DSL; SMT-checked monotonic scope | Verified — arXiv:2504.11703 |
| [agent-sentry.md](agent-sentry.md) | **Agent-Sentry** | Provenance graph + learned bounds; LLM judge is *residual* | Verified — arXiv:2603.22868 |
| [drift.md](drift.md) | **DRIFT** | Secure planner builds an uninjectable plan root + dynamic validator | Verified — arXiv (repo live) |
| [agentarmor.md](agentarmor.md) | **AgentArmor** | Lift the agent trace to a program graph; deterministic taint analysis | Verified preprint (venue unconfirmed) |
| [agentspec.md](agentspec.md) | **AgentSpec** | Deterministic `trigger → predicate → enforce` rule runtime | Verified — arXiv:2503.18666 (SMU) |
| [saga.md](saga.md) | **SAGA** | Inter-agent auth: per-pair capability tokens (TTL + quota), crypto-decided | Verified — arXiv:2504.21034, NDSS 2026 |
| [armo.md](armo.md) | **ARMO** | Progressive enforcement lifecycle (observe → baseline → selective → least-priv) | Vendor material, not peer-reviewed |
| [codex-sandbox.md](codex-sandbox.md) | **Codex sandbox** | OS sandbox (Seatbelt/bubblewrap) × approval axis + `/review` diff agent | Verified — OpenAI official docs |

---

## The one convergent lesson

Across eleven independent systems, the same conclusion recurs: **keep the LLM off the
enforcement decision wherever the decision can be expressed structurally, and derive the
structure from the *trusted* input before any untrusted bytes are seen.** The LLM is for
recovering structure (plan, provenance, dependency graph) and for the small ambiguous tail —
never the sole gate.

This is exactly ddbt's known weakness. ddbt's v4 step-judge **is** the gate and it **reads
untrusted tool output**, so a successful injection launders itself into an `allow` and the
audit log vouches for the attack. Every system here either avoids that flaw by design or
empirically measures it:

- **LGA** is the cautionary data point: its own paper reports the L2 intent judge collapses
  from ~92% to 50–63% interception under just 30 adaptive probes, and concludes the judge
  **cannot be the sole gatekeeper**. ddbt independently arrived at the same tradeoff — LGA
  proves it quantitatively.
- **CaMeL / DRIFT / Progent** remove the flaw by anchoring authority to a plan/policy built
  from the trusted request, so untrusted content can at most stay inside an envelope, never
  widen it.
- **FIDES / AgentArmor** remove the flaw by making the *verdict itself* deterministic
  (label arithmetic / taint lattice over a graph) — attacker text is data in the graph,
  never an instruction to the checker.
- **Agent-Sentry / AgentSpec / ARMO** shrink the flaw by making the judge **residual** —
  deterministic pre-filters decide ~96% of calls; only the ambiguous tail reaches the LLM.
- **SAGA / Codex** add deterministic floors *underneath* everything — crypto capabilities
  and an OS sandbox — so even a fully fooled judge cannot exfiltrate or escape the workspace.

ddbt should evolve from "one injectable judge decides everything" to **"a deterministic
spine with the judge as a residual specialist on the ambiguous middle, and hard floors
underneath."**

---

## Target architecture for ddbt (composed from the best pieces)

```
STARTUP
  Boundary 0 (have)            hash config/MCP integrity + semantic tool-desc scan
  + OS sandbox floor (Codex)   Seatbelt/bubblewrap: network-off-by-default, workspace-scoped FS
  + capability mint (SAGA)     per-session, per-tool/MCP caps: TTL + request quota, bound to B0 identity hash

PER USER TASK
  + plan root (CaMeL/DRIFT)    derive an allowed-action envelope from the TRUSTED query only,
                               before any tool output is seen → this anchors Axis 1

PER SYSTEM-TOUCHING STEP
  1. capability + IFC check    deterministic, uninjectable:
       (Progent/FIDES/SAGA)      - cap exists, not expired, quota left?
                                 - consequential args trusted? egress reader permitted? (FIDES labels)
                                 - action ⊆ plan-root envelope?
       → in-envelope+clean = ALLOW (no LLM)   ;   destructive/egress = route on
  2. provenance lineage        extend the SQLite quarantine record with source/derivation/trust
       (Agent-Sentry/AgentArmor) lineage; taint flows over the session graph (worst-label-wins)
  3. residual step-judge       ONLY on the ambiguous tail or when suspicion ≥ ELEVATED;
       (have, hardened)          fed delimited <retrieved_data> excerpts, not raw streams;
                                 cascade cheap→expensive model (LGA: FPR 34%→2%)
  4. enforce                   allow / gate / deny  +  suspicion ratchet (have)

COMMIT (per batch)
  + staging overlay (Codex/v3) writes/deletes/egress staged, not live
  + blind diff review (Codex)  fresh-context, write-disabled reviewer over the MATERIALIZED diff
                               → realizes the v3 "privilege-separated blind judge"

ALWAYS
  audit log (have)             every decision + every declassify/cap-grant, append-only
  progressive enforcement      observe→baseline→graduate a behavior to ALLOW only after N×/M-sessions
       (ARMO/Agent-Sentry)     — and only ever ratchet suspicion UP
```

Deterministic layers (1, 2, capability mint, OS floor) are **uninjectable** and do most of
the work. The judge (3) becomes a small, hardened, residual component. The diff review is a
**blind** judge by construction (it reads the diff, not the untrusted prose that caused it).

---

## Adoption shortlist, by ddbt component

| ddbt component | Steal from | Concrete change |
|---|---|---|
| **Step-judge → residual** | Agent-Sentry, AgentSpec, LGA | Add a deterministic pre-filter that hard-allows in-envelope-clean and hard-denies obvious cases; only the ambiguous tail hits the LLM. Cascade cheap→expensive model; run the expensive judge only when stage-1 flags or suspicion ≥ ELEVATED (maps onto the existing ratchet). |
| **Axis 1 (goal fidelity)** | CaMeL, DRIFT | Derive a **plan root / allowed-action envelope from the trusted query only**, before any tool output. Judge "does this call fit the trusted plan?" instead of judging each call in a vacuum. Anchors Axis 1 to uninjectable structure. |
| **Pre-judge deterministic gate** | FIDES, Progent | A two-label IFC check (consequential args must be trusted; egress only to permitted readers) + a least-privilege predicate set, evaluated *before* the LLM. Make scope changes monotonic (SMT/subset check) so an injected judge can never widen the envelope. |
| **Quarantine → provenance lineage** | Agent-Sentry, AgentArmor | Extend each SQLite quarantine row with source/derivation/trust lineage; build a session data-dependency graph; **deny tainted→sink flows by lattice arithmetic, not LLM opinion**. Catches multi-step exfil that per-call judging misses. Pair quarantine (blocks data *out*) with DRIFT-style instruction isolation (blocks instructions *in*). |
| **Boundary 0 → capabilities + OS floor** | SAGA, Codex | Mint per-session, per-tool/MCP capability tokens (TTL + quota) bound to the B0 identity hash, checked deterministically before the judge. Add an OS sandbox floor: network-off-by-default + allowlist egress, workspace-scoped FS — a hard floor a fooled judge can't cross. |
| **Commit / no-leak invariant** | Codex, FIDES, v3 doc | Staging overlay + a **blind, fresh-context, write-disabled diff reviewer** over the materialized diff at commit. Layer FIDES hide/reveal (handles + capacity-bounded declassification) on the quarantine to keep utility high. |
| **Suspicion ratchet → lifecycle** | ARMO, Agent-Sentry | Wrap the judge in observe→baseline→graduate: auto-allow a behavior only after it recurs N times across M sessions; otherwise surface it in a review report. Keep the "only ratchet up" rule. |

---

## What to build first (priority order)

1. **Plan root + deterministic pre-filter (CaMeL/DRIFT + Agent-Sentry).** Highest leverage:
   directly attacks ddbt's core flaw and cuts judge cost/latency ~30×. Derive the trusted-only
   envelope; decide in-envelope-clean calls deterministically; the judge becomes residual.
2. **IFC label check + provenance lineage (FIDES + AgentArmor).** Makes the *verdict*
   uninjectable for the exfiltration class and catches multi-step flows. Builds on the
   quarantine store you already have.
3. **OS sandbox floor + capability TTL/quota (Codex + SAGA).** Hard floors under everything;
   independent of LLM correctness.
4. **Staging overlay + blind commit-time diff review (Codex/v3).** Realizes the
   privilege-separated blind judge and makes wrong `allow`s reversible.
5. **Progressive-enforcement lifecycle (ARMO).** Tuning layer; add once traces exist.

The judge-cascade and second-model-on-escalation (LGA) and the deterministic
`trigger→predicate→enforce` rule form (AgentSpec) are cheap wins layerable at any point.
