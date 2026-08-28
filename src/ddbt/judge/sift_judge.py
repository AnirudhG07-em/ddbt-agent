"""SiftJudge — the non-LLM decider, a drop-in for AnthropicStepJudge/GeminiStepJudge.

Same contract: judge(StepFacts) -> Verdict. Instead of an LLM, it uses the trained sift model
(embedding ⊕ structural), loaded once via sift.serve.SiftScorer. The mapping to the 9-boolean Verdict
is deliberately split by what each layer is actually good at (the two-axis design):

  * STRUCTURAL flags (exact, from sift.features.structural) fill the data-flow booleans directly:
        accesses_secrets ← payload_sensitive        external_exfil ← external dest + not user-chosen
        high_impact      ← destructive or egress     requests_secrecy ← secrecy_framing
  * PROVENANCE comes from StepFacts.input_labels (ddbt already computes it — the embedding cannot):
        injection_suspected ← any input label marked injection-derived / unknown-origin
  * The SEMANTIC risk (calibrated) drives axis 2 and off-goal:
        harmful  ← risk ≥ band.tau_deny            (intrinsic badness — the embedding's home turf)
        deviation ← injection_suspected AND risk in/above the ASK band (follows injected content)
        serves_goal ← low risk and not deviation

The engine's _combine() then turns this Verdict into ALLOW/ASK/DENY exactly as it does for the LLM —
so heat, chromatics, the grant floor, and the whole pipeline are unchanged; only the decider swapped.

Fails CLOSED like the LLM backends: any error → an errored Verdict (deviation=True, error=True), so a
missing model or bad load defers to a human rather than silently allowing.
"""

from __future__ import annotations

from dataclasses import dataclass

from ddbt.judge.step_judge import StepFacts, Verdict

# STRONG injection evidence — the engine's exact per-arg label (engine.py: a value that appears ONLY
# inside untrusted free text → whoever wrote it chose this). Enough to hard-DENY an on-scope step.
# NOTE: match this precise phrase, NOT bare "untrusted" — the generic "session has ingested N
# quarantined (untrusted) tool output(s)" note also contains that word and is NOT per-action evidence.
_INJECTION_DERIVED = ("injection-derived",)
# WEAK: unknown/unclear origin — worth flagging (injection_suspected) but NOT a hard deny on its own,
# or every step-2 read-then-act in a benign multi-step task gets denied.
_UNKNOWN_MARKERS = ("unknown origin",)


@dataclass
class SiftJudge:
    scorer: object  # sift.serve.SiftScorer

    @classmethod
    def load(cls, artifact_path: str | None = None, cwd: str | None = None) -> "SiftJudge | None":
        """Build from a saved artifact, loading this workspace's behaviors (ddbt.json). Returns None
        if the sift package / model isn't available (caller then falls back to the flagged LLM)."""
        try:
            import sys
            from pathlib import Path
            # sift lives in the sibling `sift/` project; add it to the path best-effort
            for up in Path(__file__).resolve().parents:
                if (up / "sift" / "sift" / "serve.py").is_file():
                    sys.path.insert(0, str(up / "sift"))
                    break
            from sift.data import behaviors as _beh
            from sift.serve import SiftScorer

            from ddbt.core import config as _cfg
            scorer = SiftScorer(artifact_path) if artifact_path else SiftScorer.find()
            if not scorer:
                return None
            # route the LAYERED, folded config through (out-of-band + in-project + referenced rulesets),
            # not a raw ddbt.json read — so `ddbt create-rules` packs actually reach the judge. No retrain.
            deny, allow = _beh.parse(_cfg.behaviors(cwd))
            scorer.set_behaviors(deny, allow)
            return cls(scorer)
        except Exception:
            return None

    def judge(self, facts: StepFacts) -> Verdict:
        try:
            # injection is decided by THIS action's provenance labels (did a value come from
            # injection-derived / unknown-origin content?), NOT by the mere presence of quarantined
            # output — the engine quarantines EVERY tool result, so a quarantine-exists test would
            # falsely flag every step after the first as injected → spurious deviation DENYs.
            prov = "; ".join(facts.input_labels).lower()
            injection_derived = any(m in prov for m in _INJECTION_DERIVED)   # strong → can deny
            injected = injection_derived or any(m in prov for m in _UNKNOWN_MARKERS)  # broad → flag only
            history = "\n".join(facts.history[-4:]) if facts.history else ""
            s = self.scorer.score(facts.tool, facts.args, goal=facts.goal,
                                  history=history, sink_provenance=("tool" if injection_derived else "user"))
            st = s.struct
            bands = self.scorer.bands
            matched_behavior = bool(s.matched_behavior)
            # harmful (→ DENY via ethics) comes ONLY from the trained malicious signal, not from a
            # workspace rule. A matched workspace rule is a SOFT signal (side_task) → the engine
            # gates it to ASK, so "you didn't ask me to commit" prompts a human instead of blocking.
            # deterministic bulk-harm: a mass operation that destroys / sends-out / touches sensitive
            # data is harmful regardless of the model (which blurs 'all' vs 'scoped'). Import lazily
            # from the sift package that the scorer came from.
            try:
                from sift.features.structural import bulk_harm_rule
                bulk_harm = bool(bulk_harm_rule(st))
            except Exception:
                bulk_harm = False
            harmful = bool(s.model_risk >= bands.tau_deny or bulk_harm)
            # deviation hard-denies ONLY on STRONG injection evidence (not mere unknown-origin) — else
            # benign multi-step read-then-act flows get spuriously denied.
            deviation = injection_derived and s.model_risk >= bands.tau_ask
            return Verdict(
                serves_goal=(s.risk < bands.tau_ask and not deviation and not matched_behavior),
                deviation=deviation,
                harmful=bool(harmful),
                # high_impact = "warrant a human check even when on-goal" — a matched workspace rule
                # is exactly that, so it gates to ASK immediately (not only under elevated heat).
                high_impact=bool(st.is_destructive or st.is_egress or matched_behavior),
                requests_secrecy=bool(st.secrecy_framing),
                side_task=bool(deviation or matched_behavior),
                accesses_secrets=bool(st.payload_sensitive),
                external_exfil=bool(st.has_external_dest and (st.sink_from_tool_output or st.sink_unknown)),
                injection_suspected=bool(injected),
                reason=(f"bulk data operation over all records (Impact TA0040) · high · risk={s.model_risk:.2f}"
                        if bulk_harm and s.model_risk < bands.tau_deny else s.reason),
            )
        except Exception as exc:  # fail CLOSED, flagged as error (not a real detection)
            return Verdict.errored(f"sift judge unavailable ({type(exc).__name__}: {exc})"[:200])
