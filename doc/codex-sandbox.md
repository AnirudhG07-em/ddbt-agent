# Codex sandbox model — OS-level per-turn execution sandbox + diff-review/approval workflow

- **Source:** OpenAI Codex official developer docs (developers.openai.com/codex), 2025–2026. Primary pages: [Sandboxing concept](https://developers.openai.com/codex/concepts/sandboxing), [Agent approvals & security](https://developers.openai.com/codex/agent-approvals-security), [CLI features](https://developers.openai.com/codex/cli/features), [Best practices](https://developers.openai.com/codex/learn/best-practices), [Config reference](https://developers.openai.com/codex/config-reference). — **VERIFIED** (official OpenAI documentation).
- **Category:** OS-native process sandbox for an agentic coding CLI/app. Two orthogonal controls — **Sandbox mode** (what's *technically* possible) and **Approval policy** (when to *stop and ask*) — plus a human-in-the-loop **diff review** and a separate **reviewer agent**.

## Pipeline (stage by stage)

Codex's model is two independent layers that combine, applied **per turn**:

> "Sandboxing and approvals are different controls that work together. The sandbox defines technical boundaries. The approval policy decides when Codex must stop and ask before crossing them."

Both layers are **deterministic OS/process enforcement and policy** — **no LLM in the security-enforcement path**. The LLM proposes commands and edits; the sandbox and approval policy (and the human) decide whether they execute. (Note: the optional `/review` *reviewer agent* is an LLM, but it is advisory — it reports findings, it does not gate execution.)

### Stage 1 — Model proposes an action (LLM)
The Codex model emits a shell command, a file edit (as a patch/diff), or a tool/MCP call as part of its turn.

### Stage 2 — Sandbox boundary check (deterministic, OS-level)
Every model-generated command runs inside an OS sandbox whose policy is the current **Sandbox mode**:
- **`read-only`** — Codex can inspect files but cannot edit files or run state-changing commands without approval.
- **`workspace-write`** (default) — Codex can read files, **edit within the workspace**, and run routine local commands inside that boundary. **Network access is OFF by default** in this mode.
- **`danger-full-access`** — no sandbox restrictions; **removes filesystem and network boundaries**. Use only for trusted repos/tasks.

Implementation is **OS-native, same idea across platforms**:
- **macOS:** the built-in **Seatbelt** framework (`sandbox-exec`).
- **Linux / WSL2:** **`bubblewrap` (`bwrap`)**, with a bundled fallback helper using unprivileged user namespaces (this is where Landlock/seccomp-style kernel confinement lives).
- **Windows (native):** native Windows sandbox in PowerShell; Linux sandbox under WSL2.

Per-turn / per-session filesystem scoping:
- `sandbox_workspace_write.writable_roots` — extends writable directories beyond the workspace **without dropping the sandbox** ("If you need Codex to work across more than one directory, writable roots let you extend the places it can modify without removing the sandbox entirely.").
- Network within `workspace-write`: enable via `network_access = true` under `[sandbox_workspace_write]`; constrain via a `network_proxy` **allowlist** (exact host, wildcard `*.example.com`, or `*`). Local/private binds blocked by default (`allow_local_binding = false`).

### Stage 3 — Approval decision (deterministic policy)
If the proposed action *would cross* the sandbox boundary (network, write outside workspace, side-effecting command, side-effecting app/MCP tool call), the **Approval policy** decides whether to auto-allow, auto-deny, or **prompt the human**:
- **`never`** — no prompts; runs autonomously within sandbox constraints (used for CI / non-interactive).
- **`on-request`** (a.k.a. the **Auto** preset behavior) — Codex works inside the sandbox by default and **asks when it needs to go beyond the boundary** (e.g. edit files outside the workspace, run a command needing network).
- **`untrusted`** — auto-runs known-safe read operations; **requires approval for anything that can mutate state or trigger external execution**.

Optional `approvals_reviewer = "auto_review"` routes eligible approval requests through an **automatic reviewer agent** before execution.

### Stage 4 — Escalation on sandbox failure / boundary need
When a sandboxed action fails or needs elevation, Codex escalates to the approval system per the active `approval_policy`. Triggers: leaving the sandbox, network requests, side-effecting app/MCP tool calls.

### Stage 5 — Diff review & apply (human-in-the-loop)
File changes are produced as **patches/diffs**. In the TUI/app the user sees **syntax-highlighted diffs**; Codex **"explain[s] its plan before making a change, and [you] approve or reject steps inline."** In the app's diff panel, clicking a row leaves feedback that is **fed as context into the next Codex turn**. Recommended workflow: treat Codex output like any PR — patch-based (`git diff` / `git apply`), targeted verification, decisions documented in commit messages for auditing.

### Stage 6 — Optional separate reviewer agent
`/review` launches a **dedicated reviewer agent** that "reads the diff you select and reports prioritized, actionable findings **without touching your working tree**." It can review staged/unstaged changes, specific commits, or a base-branch merge, and appears as **its own turn in the transcript**. This is a *second, fresh LLM pass* over the diff, advisory only.

## Key mechanisms

- **Two orthogonal controls** — sandbox (capability) × approval (interaction). You tune "what's possible" and "when to ask" independently.
- **Per-turn application** — both policies apply per turn; mode is switchable mid-session via `/permissions`, current boundaries shown via `/status`.
- **OS-native confinement** — Seatbelt / bubblewrap+user-namespaces, not a homegrown filter; kernel-level, same semantics across OSes.
- **Network off by default** in the working mode, with **allowlist proxy** for controlled egress — egress is opt-in and scoped, not all-or-nothing.
- **Writable-roots** — extend FS scope surgically without disabling the sandbox.
- **Presets** that pair sandbox+approval sensibly: **Auto** (`workspace-write` + `on-request`), **Read-only** (`read-only` + `on-request`), **CI** (`read-only` + `never`), **Conservative** (`workspace-write` + `untrusted`), **Full Access** (`danger-full-access`).
- **Diff as the review unit** — changes surfaced as reviewable, approvable patches; inline reject feedback loops back into the next turn.
- **Separate fresh-context reviewer agent** (`/review`) — a clean-room LLM pass that *cannot* edit, only report.

## Strengths / what's genuinely good

- **Deterministic enforcement, OS-backed.** The actual confinement is Seatbelt/bubblewrap, not LLM judgment — prompt injection cannot talk the *sandbox* into allowing network or out-of-workspace writes; it can only produce commands the sandbox then blocks.
- **Clean separation of capability vs interaction.** Sandbox-mode × approval-policy is an elegant 2-axis design that's easy to reason about and configure per trust level.
- **Network-off-by-default + allowlist egress** is a strong default against the classic exfiltration/injection-to-callout pattern.
- **Diff-centric, human-gated changes.** Nothing lands without a reviewable patch; inline reject feedback is a tight correction loop.
- **Fresh-context reviewer agent that can't write** — a real privilege-separation pattern: the reviewer's only power is to *report*, so a compromised reviewer can't act.
- **Sensible presets** lower the chance of misconfiguration; per-turn `/permissions` switching matches changing trust within a session.

## Limitations / failure modes

- **Approval fatigue → users widen the policy.** `on-request`/`untrusted` prompts push users toward `danger-full-access` or `never` for convenience, collapsing the protection. The docs explicitly warn to keep it tight and loosen only for trusted repos.
- **`danger-full-access` removes everything** — one mode flip drops *both* FS and network boundaries; no middle "full FS but no network" without config.
- **In-workspace harm is uncontained.** The sandbox protects the *rest of the machine*, not the workspace itself — a malicious edit to files inside the writable workspace (e.g. poisoning a build script) executes freely. Sandbox enforces *location*, not *intent*.
- **Diff review depends on the human.** With `approval_policy = never` or auto-approve, the human-gate stage is skipped; the security then rests entirely on the sandbox boundary.
- **Reviewer agent is advisory.** `/review` reports findings; it doesn't block a merge — value depends on the user acting on it. And it's still an LLM reading a (possibly attacker-influenced) diff.
- **Network allowlist is host-level, not content-level** — an allowed host can still be an exfil channel.

## Best pieces to steal for ddbt

1. **Split ddbt's single LLM-judge axis into capability × interaction, with the capability layer deterministic.** Codex's biggest lesson for ddbt's KNOWN TRADEOFF: put a **deterministic OS sandbox underneath the LLM judge** so that *even if the injectable judge is fooled into "allow," the OS still blocks network egress / out-of-workspace writes.* ddbt's judge would become the "approval policy" axis; add a Seatbelt (macOS) / bubblewrap (Linux) "sandbox-mode" axis as a hard floor. This is defense-in-depth the current ddbt design lacks.
2. **Network-off-by-default + allowlist egress proxy.** Directly supports ddbt's **no-leak invariant**. Today ddbt quarantines tool *outputs*; Codex shows you should *also* deterministically block *outbound* network at the OS level by default, with an explicit per-session host allowlist — closing the exfil path the LLM judge currently has to reason about.
3. **The v3 doc's "commit-time diff judge" is exactly Codex's `/review`.** Codex validates v3's proposal: a **separate, fresh-context, write-disabled reviewer** that reads the staged diff and reports findings — i.e. a **privilege-separated BLIND judge** over the *aggregate diff*, not the per-call stream. Steal this directly: a second judge that sees only the final workspace diff, has no tools, and cannot be injected mid-stream because it runs once over the committed change.
4. **Staging overlay + commit-time review.** Codex's "edits are patches, reviewed then applied" maps onto the v3 "staging overlay": route ddbt's file writes into an overlay, present the aggregate diff, and gate the *commit* (deterministic apply) on the diff judge — rather than judging each write live.
5. **Writable-roots as the structural FS scope envelope.** A concrete, deterministic FS-scope primitive (allowed roots) ddbt can adopt for the "structural scope envelope," enforced by the OS sandbox below the judge.
6. **Per-turn / per-session permission switching with a visible status.** Codex's `/permissions` + `/status` model (and the suspicion-driven tightening it implies) pairs naturally with ddbt's **session suspicion ratchet**: as suspicion ratchets up, deterministically *tighten the sandbox mode* (e.g. revoke network, narrow writable roots) — not just bias the LLM judge.

## Sources

- [Codex — Sandbox (concept)](https://developers.openai.com/codex/concepts/sandboxing)
- [Codex — Agent approvals & security](https://developers.openai.com/codex/agent-approvals-security)
- [Codex — CLI features](https://developers.openai.com/codex/cli/features)
- [Codex — Best practices](https://developers.openai.com/codex/learn/best-practices)
- [Codex — Configuration reference](https://developers.openai.com/codex/config-reference)
- [DeepWiki — openai/codex: Sandbox and Approval Policies](https://deepwiki.com/openai/codex/2.4-sandbox-and-approval-policies)
