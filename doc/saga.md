# SAGA — cryptographic inter-agent authentication & user-governed access control for multi-agent systems

- **Source:** *SAGA: A Security Architecture for Governing AI Agentic Systems* — Georgios Syros, Anshuman Suri, Jacob Ginesin, Cristina Nita-Rotaru, Alina Oprea (Northeastern University). NDSS 2026. arXiv:2504.21034. ([arXiv abstract](https://arxiv.org/abs/2504.21034) · [HTML](https://arxiv.org/html/2504.21034) · [NDSS camera-ready PDF](https://www.ndss-symposium.org/wp-content/uploads/2026-s869-paper.pdf)) — **VERIFIED** (arXiv ID, authors, and NDSS 2026 acceptance all confirmed).
- **Category:** Identity / authentication / access-control protocol for *inter-agent* communication in multi-agent systems (not a per-tool sandbox). Provider-mediated PKI + per-pair capability tokens with formal (ProVerif) security proofs.

## Pipeline (stage by stage)

SAGA's premise: in a world of many user-owned LLM agents that discover, contact, and delegate to each other, the user must keep *comprehensive control* over who their agent may talk to and how much work it will accept. The architecture inserts a trusted-ish coordinator (the **Provider**) plus a cryptographic handshake so that two agents only communicate after policy + identity + capability checks pass.

Three roles:
- **User** — owns one or more agents; assigns tasks; authors access-control policy.
- **Agent** — autonomous LLM-driven software entity that acts for a user.
- **Provider** — centralized registry holding user/agent metadata and access-control policies; brokers first contact between agents and helps enforce policy. Trust model: **honest-but-curious** (can observe metadata/traffic, won't actively subvert the protocol).

Everything below is **deterministic cryptography and policy evaluation** — the LLM does the *task*, but none of the security decisions are made by an LLM. This is the cleanest contrast with ddbt, whose security decision (the step-judge) is an LLM reading untrusted content.

### Stage 0 — User registration (deterministic)
"User Account Setup": email identifier + passphrase; user generates a signature key pair; obtains a CA-issued certificate; authenticates against an external identity-verification service. The result is a cryptographic identity the user can use to vouch for their own agents.

### Stage 1 — Agent registration (deterministic)
For each agent, the user generates and the Provider stores (in the **Agent Registry 𝒟A**):
- **TLS credentials** `(PKA, SKA)` + CA cert — for the transport channel.
- **Access-control key pair** `(PACA, SACA)` — long-term keys used to *derive* per-pair tokens (the heart of the scheme).
- A **batch of N one-time key pairs** `(OTKAi, SOTKAi)`, each signed by the user (`σOTKiU`). These are ephemeral DH public values; the user's signature binds each OTK to that user/agent.
- An **Agent Contact Policy `CPA`** — declarative rules naming which *initiating* agents are allowed to contact this agent, and how many OTKs each matching initiator is granted.

The Provider returns a Provider signature `σAProv` confirming registration. This signature is later what an initiating agent presents as "the Provider vouches that I am a registered, in-good-standing agent."

### Stage 2 — Contact request & policy check (deterministic, Provider-side)
When agent **B** wants to talk to agent **A**:
1. B opens TLS to the Provider.
2. B requests A's information by identity. The Provider **evaluates A's Agent Contact Policy** against B. If B matches a rule (and OTK budget remains), the Provider returns A's "access information": A's user certificate `CertU1`, A's device/network info `(aidA, EDA)`, A's TLS + access-control public keys `(CertA, PACA)`, and **one signed one-time key** `OTKAi, σOTKiU1`.
3. B verifies all signatures (user cert chain, OTK signature).

Policy specifics worth stealing:
- Rules are **patterns with a budget**, e.g. `('*@company.com:email_agent', 10)` = any company.com email-agent may contact, with 10 OTKs allotted.
- **Most-specific rule wins** if several match.
- **OTK budget** is the access-rate control: `BudgetOTK(aidA, aidB)` returns `-1` (deny) if no rule matches, else the budget of the most specific matching rule `r*`. The Provider maintains `CounterOTK[aidA][aidB]` and **decrements per OTK issued** — so a contact policy doubles as a quota.
- **Blocking** is just a rule with budget `-1`. Policies are **updatable live** via the Provider interface.

### Stage 3 — Agent-to-agent mutual handshake (deterministic)
4. B opens TLS directly to A with mutual certificate verification.
5. B sends its own info + its Provider signature `σBProv` + the `OTKAi` it received.
6. A verifies B's Provider signature (B is a registered, in-good-standing agent) and that the OTK is one A actually issued/valid.

### Stage 4 — Token derivation (deterministic, capability minting)
7. The two sides run **Diffie–Hellman** over the access-control keys and the one-time key:
   - `DHA = DH(SOTKAi, PACB)` (A side: its OTK secret × B's access-control public key)
   - `DHB = DH(SACB, OTKAi)` (B side: its access-control secret × A's OTK public)
   - Both reach the same shared key `SDHK = KDF(DHA) = KDF(DHB)` (HKDF-SHA256).
8. A mints an **access token**:
   `token = EncSDHK(⟨N, Tissued, Texpire, Qmax, PACB⟩)`
   — nonce `N`, issue/expiry timestamps, **max request quota `Qmax`**, and B's access-control public key `PACB` (so A can later confirm the token is being used by the intended B).

### Stage 5 — Authorized communication (deterministic)
B attaches the token to every subsequent request over the TLS channel. The token is **reused until expiry or until `Qmax` requests are spent**, at which point a new handshake/derivation is needed. Token granularity is a **tunable knob**: short-lived / low-quota tokens = smaller vulnerability window but more crypto overhead; the paper measures this tradeoff explicitly.

## Key mechanisms

- **Provider-brokered first contact + direct agent-to-agent thereafter.** The Provider is the policy decision point and key distributor for *introductions*; the actual session is peer-to-peer over TLS. This keeps the Provider off the data path (honest-but-curious is enough).
- **Per-pair capability tokens, not bearer tokens.** A token is derived from a DH exchange that *cryptographically binds* it to the specific initiator's access-control key (`PACB` is inside the token). A stolen token is not freely replayable to a different agent identity.
- **Contact policy = ACL + rate limit in one object.** Pattern rules with per-rule OTK budgets unify "who may contact me" and "how often", with most-specific-match resolution and a `-1` deny sentinel.
- **One-time keys as the unforgeable introduction.** Each OTK is user-signed and Provider-counted; consuming OTKs is what bounds contact volume and gives the Provider a tamper-evident ledger of introductions.
- **Explicit token-granularity tradeoff** (`Texpire`, `Qmax`) — security/perf is a dial, not a fixed policy.
- **Formal verification.** The whole protocol was modeled in **ProVerif** under a Dolev–Yao attacker (observe, intercept, modify, replay, reorder, synthesize). Proven properties: secrecy of the SAGA token; authentication agent↔Provider; authentication agent↔agent.

## Strengths / what's genuinely good

- **Security decisions are deterministic and provable.** No LLM is in the trust path — the access decision is policy evaluation + crypto, machine-checked in ProVerif. This is exactly the property ddbt's LLM step-judge lacks.
- **User-centric governance.** The user, not the agent, authors the contact policy; the agent literally cannot reach a counterparty the user hasn't authorized. Compromise of the *agent's reasoning* (prompt injection) does not grant it new contacts, because contacts are gated by signed policy + OTK budget the agent cannot mint.
- **Capabilities are scoped and expiring.** Tokens carry quota + expiry and are bound to a counterparty key — a clean least-privilege primitive for delegation.
- **Strong threat model coverage.** Adversary capabilities C1–C6 include social-engineering of contact policies, compromised-but-legitimate agents, unregistered self-replication, credential sharing/impersonation, Sybil, and network attacks.
- **Negligible overhead, real scale.** Crypto ops are ~ms; protocol overhead <0.6% of the fastest end-to-end task; <25ms once an agent pair exchanges 4–5+ requests; ~242K OTK req/min single-node, scaling linearly with sharders to a stated ~300M-agent capacity with 10 sharders + 24h tokens. RAFT fault-tolerance costs 12–15%.

## Limitations / failure modes

- **Centralized Provider = single trust/availability anchor.** Honest-but-curious is assumed, not enforced; a malicious Provider could deny service or misuse metadata. It also sees the social graph (who contacts whom).
- **Governs *who/how-much*, not *what*.** SAGA authenticates and rate-limits inter-agent contact; it does **not** inspect message *content* or stop a fully-authorized agent from doing harmful work within its quota. Prompt injection that operates *within* an already-authorized channel is out of scope.
- **Credential-sharing / replication (C3, C4) is mitigated by policy + counting, not prevented.** A compromised agent that leaks its keys to a child still has SAGA's accounting working against it, but the keys themselves are copyable.
- **Designed for multi-agent topologies.** ddbt is (today) single-agent-over-tools; SAGA's *protocol* doesn't map onto a hook-gated single agent without reframing "tools/MCP servers" as "agents."
- **OTK batch exhaustion / rotation** is operational overhead the user/Provider must manage.

## Best pieces to steal for ddbt

1. **Move the security decision off the LLM where you can.** SAGA's headline lesson for ddbt's KNOWN TRADEOFF (injectable LLM judge): wherever a decision *can* be expressed as deterministic policy + crypto, do it there, and reserve the LLM judge for genuinely semantic calls. Concretely, ddbt's **Boundary 0** (hash-based config/MCP integrity) is already this style — SAGA validates extending it: treat MCP servers / external tool endpoints as *identities* with signed, hash-pinned descriptors, and gate "may this agent even talk to this endpoint" deterministically *before* the LLM judge ever sees content.
2. **Capability tokens with quota + expiry for tool/MCP access** → map onto ddbt's gate/deny + session model. SAGA's `⟨N, Tissued, Texpire, Qmax, PACB⟩` token is a ready-made structural scope envelope: per-session, per-tool capabilities that carry a request quota and TTL, minted once a tool is approved, and auto-revoked on expiry/quota. This is a deterministic complement to the per-call LLM judge and directly answers the v3 doc's "structural scope envelope" wish.
3. **Contact policy = pattern rule + budget + most-specific-match + `-1` deny.** A compact, user-authored ACL design ddbt can adopt for "which MCP servers / network destinations / file roots this session may touch," unifying allow-list and rate-limit in one object with deterministic resolution — and updatable live, feeding the same audit log.
4. **The session-suspicion ratchet gains a crypto counterpart.** SAGA's OTK counter is a *tamper-evident, monotonic* consumption ledger. ddbt's suspicion ratchet (never lowers) is the policy analog; pair it with a per-session monotonic quota counter in the SQLite store so high-impact tool budgets deplete and cannot be silently reset.
5. **Bind capabilities to identity, not bearer.** Putting the counterpart's key *inside* the token (so it can't be replayed by a different identity) suggests ddbt tokens/capabilities should be bound to the specific tool/MCP identity hash from Boundary 0 — a stolen/forwarded capability won't validate against a different tool descriptor.

## Sources

- [SAGA: A Security Architecture for Governing AI Agentic Systems — arXiv:2504.21034 (abstract)](https://arxiv.org/abs/2504.21034)
- [SAGA — arXiv HTML full text](https://arxiv.org/html/2504.21034)
- [SAGA — NDSS 2026 camera-ready PDF (paper s869)](https://www.ndss-symposium.org/wp-content/uploads/2026-s869-paper.pdf)
- [Northeastern Khoury — Security of LLM Agents project page](https://www.khoury.northeastern.edu/research_projects/security-of-llm-agents/)
