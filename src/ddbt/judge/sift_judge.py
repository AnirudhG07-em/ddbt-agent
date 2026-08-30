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

# The graded human-check gate: impact_severity ≥ this → ASK. Lower = catch more (attacks AND benign),
# higher = quieter. One knob for the security/utility balance. (0.20 lifts R-Judge to ~70 F1 but costs
# a few points of InjecAgent benign; 0.35 keeps InjecAgent benign at 94% — the shipped balance.)
GATE_SENS = 0.35

# MITRE tactics that mean "sensitive DATA is present" — drive the content gate (a yellow read/send flag).
_CONTENT_TACTICS = frozenset({"exfiltration", "secret_theft", "surveillance", "financial_harm"})
# HARMFUL-ACTION tactics that lift the impact score (→ a gate/ASK). DELIBERATELY NARROW and unambiguous:
# fraud/impersonation, malware/phishing, reverse-shell C2, crypto-mining. The broad tactics were tried
# and reverted — they matched benign work ("production", "commit", "all users", "cron") or session
# history ("silently"/"quietly"). Everything here should be attack-specific; their lexicons are pruned to
# phrases that don't plausibly occur in normal dev/shell work. (financial_harm already gates via content.)
_HARM_TACTICS = frozenset({"impersonation", "harmful_content", "backdoor", "resource_abuse"})


def _friendly_name(category: str) -> str:
    """Plain phrase for a detected sensitive category, for the one-line ASK. Best-effort."""
    try:
        from sift.data import mitre
        return mitre.friendly_name(category)
    except Exception:
        return "sensitive or personal files"


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
            # DDBT_SIFT_MODEL lets you pin a specific artifact (e.g. an encoder variant) without editing
            # config — used by the encoder sweep in bench/embash_sim. Explicit arg still wins.
            import os as _os
            artifact_path = artifact_path or _os.environ.get("DDBT_SIFT_MODEL") or None
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

    def trajectory_risk(self, transcript: str) -> float | None:
        """P(unsafe) for the whole session transcript so far — the session-level view that recovers
        signal the per-step judge loses. None if the scorer can't do it (e.g. an LLM/stub judge)."""
        fn = getattr(self.scorer, "score_text", None)
        if fn is None:
            return None
        try:
            return float(fn(transcript))
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
            # deviation hard-denies ONLY on STRONG injection evidence (not mere unknown-origin) — else
            # benign multi-step read-then-act flows get spuriously denied.
            deviation = injection_derived and s.model_risk >= bands.tau_ask

            # ================= GRADED RISK ACCOUNTING (weighted sums, not saturating ORs) =================
            # Every signal contributes PROPORTIONALLY so combinations add up — a single weak signal stays
            # low, several together escalate ALLOW→ASK→DENY. Follows data-exfiltration methodology
            # (mindpointgroup: conducting & detecting data exfiltration): WHAT leaves × WHERE it goes ×
            # WHO chose the destination × HOW MUCH × whether it's hidden. No `or` that lets one flag saturate.
            # Content-sensitivity counts only DATA tactics — the content that is actually sensitive to read
            # or send. Recon/supply-chain/etc. lexicons still NAME an action for other layers, but must NOT
            # drive the content gate: reading package.json (supply_chain) or `whoami` (discovery) is not
            # "touching sensitive data" and shouldn't prompt.
            mitre_hit, mitre_cat, harm_hit, harm_cat = 0.0, "", 0.0, ""
            try:
                from sift.data import mitre as _mitre_lex
                cat = _mitre_lex.sensitive_tactic(f"{facts.tool} {facts.args}") or ""
                mitre_cat = cat if cat in _CONTENT_TACTICS else ""   # data present → content gate (yellow)
                mitre_hit = 1.0 if mitre_cat else 0.0
                harm_cat = cat if cat in _HARM_TACTICS else ""       # specific harmful action → impact
                harm_hit = 1.0 if harm_cat else 0.0
            except Exception:
                pass
            # WHAT: graded content sensitivity — the narrow secret/PII regex AND the broad MITRE lexicon
            # (228 terms / 17 tactics) both contribute (this is how MITRE DRIVES the decision, not just names it).
            content_sensitive = min(1.0, 1.0 * st.payload_sensitive + 0.75 * mitre_hit)
            # WHO: an attacker-CHOSEN destination (from tool output) is the top exfil signal; unknown-origin weaker.
            dest_provenance = min(1.0, 1.0 * st.sink_from_tool_output + 0.5 * st.sink_unknown)
            # EXFIL severity = egress channel × (what + where + who + how-much) + hiding-it. Each term adds;
            # sensitive content alone clears the gate (0.5 ≥ 0.35), destination/provenance/bulk pile on top.
            exfil_sev = st.is_egress * (0.50 * content_sensitive
                                        + 0.20 * st.has_external_dest
                                        + 0.25 * dest_provenance
                                        + 0.15 * st.bulk_scope
                                        + 0.10 * st.arg_scale) \
                + 0.15 * st.secrecy_framing
            # IMPACT severity = exfil + destruction (worse in bulk) + a matched workspace rule.
            impact_sev = exfil_sev + 0.6 * st.is_destructive * (0.6 + 0.4 * st.bulk_scope) \
                + 0.5 * float(matched_behavior) + 0.5 * harm_hit   # a SPECIFIC harmful-action match lifts impact
            # HARM = learned model risk, FLOORED by the deterministic mass-harm rule, LIFTED by impact —
            # so a full-signal exfil (sensitive + external + attacker-chosen + bulk) reaches DENY even if
            # the model alone was unsure, and a mass-destruction always denies. (Replaces `model or bulk`.)
            harm_score = max(s.model_risk,
                             0.9 if bulk_harm else 0.0,
                             min(1.0, 0.7 * s.model_risk + 0.5 * impact_sev))
            harmful = harm_score >= bands.tau_deny
            high_impact = impact_sev >= GATE_SENS   # RED gate: exfil / destruction / bulk (data at risk)
            # Touching sensitive content LOCALLY (reading a secret, base64-ing a key) with no egress is a
            # softer, YELLOW heads-up — worth a look, not a red alert. content_sensitive already blends the
            # narrow secret/PII regex with the MITRE lexicon, so `cat secrets.txt` scores here.
            content_flag = content_sensitive >= 0.5
            # VERB-PHRASE finding chosen by WHAT drove the gate. NEVER surface "clean" on a flagged action.
            if not harmful and (exfil_sev >= 0.30 or content_flag):
                reason = f"involves {_friendly_name(mitre_cat)}"          # sensitive content (read or sent)
            elif st.is_destructive and (high_impact or harmful):
                reason = "could delete or overwrite data"
            elif harm_cat and (high_impact or harmful):
                reason = f"involves {_friendly_name(harm_cat)}"           # a specific harmful action
            elif bulk_harm and s.model_risk < bands.tau_deny:
                reason = "is a bulk operation over many records at once"
            elif s.reason and s.reason != "clean":
                reason = s.reason
            else:
                reason = "clean"    # genuinely benign; the engine won't gate, so this is never shown on an ASK
            return Verdict(
                serves_goal=(s.risk < bands.tau_ask and not deviation and not matched_behavior),
                deviation=deviation,
                harmful=bool(harmful),
                high_impact=bool(high_impact),
                requests_secrecy=bool(st.secrecy_framing),
                side_task=bool(deviation or matched_behavior),
                # sensitive content touched (secret read/staged) — the engine gives a YELLOW gate
                accesses_secrets=bool(content_flag or st.payload_sensitive),
                external_exfil=bool(st.has_external_dest and (st.sink_from_tool_output or st.sink_unknown)),
                injection_suspected=bool(injected),
                reason=reason,
            )
        except Exception as exc:  # fail CLOSED, flagged as error (not a real detection)
            return Verdict.errored(f"sift judge unavailable ({type(exc).__name__}: {exc})"[:200])
