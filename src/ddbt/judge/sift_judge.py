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

_INJECTION_MARKERS = ("injection", "inject", "untrusted", "quarant) ", "unknown", "stranger")


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
            from sift.serve import SiftScorer
            scorer = SiftScorer(artifact_path) if artifact_path else SiftScorer.find()
            if not scorer:
                return None
            scorer.load_behaviors(cwd or ".")   # workspace deny/allow rules — no retrain
            return cls(scorer)
        except Exception:
            return None

    def judge(self, facts: StepFacts) -> Verdict:
        try:
            prov = "; ".join(facts.input_labels).lower()
            injected = any(m in prov for m in _INJECTION_MARKERS) or bool(facts.quarantined)
            history = "\n".join(facts.history[-4:]) if facts.history else ""
            s = self.scorer.score(facts.tool, facts.args, goal=facts.goal,
                                  history=history, sink_provenance=("tool" if injected else "user"))
            st = s.struct
            bands = self.scorer.bands
            matched_behavior = bool(s.matched_behavior)
            # harmful (→ DENY via ethics) comes ONLY from the trained malicious signal, not from a
            # workspace rule. A matched workspace rule is a SOFT signal (side_task) → the engine
            # gates it to ASK, so "you didn't ask me to commit" prompts a human instead of blocking.
            harmful = s.model_risk >= bands.tau_deny
            deviation = injected and s.model_risk >= bands.tau_ask
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
                reason=s.reason,
            )
        except Exception as exc:  # fail CLOSED, flagged as error (not a real detection)
            return Verdict.errored(f"sift judge unavailable ({type(exc).__name__}: {exc})"[:200])
