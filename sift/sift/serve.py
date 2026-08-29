"""In-process inference for the trained sift judge — load once, score many.

The bake-off re-embeds per call; a live judge must not. `SiftScorer` loads the joblib artifact
(fusion head + calibrator + conformal bands + encoder name) ONCE and keeps the encoder warm, so each
`score()` is just encode+predict — turning the ~60 ms cold single-query path into the few-ms warm one.

It also folds in WORKSPACE BEHAVIORS (sift.data.behaviors, from ddbt.json): the action embedding is
compared to the user's declared deny/allow prototypes, and that similarity is combined with the
trained model's risk. This is how a natural-language rule takes effect with no retraining. It returns
the calibrated risk, the deterministic structural flags, and the reason (incl. any matched behavior).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from sift.data import behaviors as _behaviors
from sift.data import mitre as _mitre
from sift.data.dataset import to_dataset
from sift.features import structural
from sift.features.text import decode_and_normalise, _flatten

# how strongly a declared behavior must match before it drives risk on its own (cosine margin).
_BEHAVIOR_MARGIN = 0.25
_BEHAVIOR_K = 10.0    # sigmoid steepness for the embedding signal
_LEXICAL_MIN = 0.5    # fraction of a rule's content words in the action (alt to the ≥2 abs-count rule)

import re as _re

_STOP = {
    "the", "a", "an", "or", "and", "to", "of", "in", "on", "for", "with", "without", "me", "my",
    "i", "you", "your", "it", "its", "any", "all", "from", "into", "do", "not", "no", "that", "this",
    "unless", "explicitly", "specifically", "did", "didn", "t", "am", "is", "are", "be", "been",
    "asking", "asked", "named", "name", "want", "should", "would", "could", "them", "they", "he",
    "she", "we", "us", "our", "at", "by", "as", "so", "if", "then", "else", "also", "just",
}


def _content_tokens(text: str) -> set[str]:
    """Lowercased content words (≥3 chars, non-stopword) — for lexical rule matching."""
    return {t for t in _re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 3 and t not in _STOP}



# ---- chunked max-pool: read a long trajectory the way an LLM's attention would (OFF by default) ----
# The idea: a static embedder mean-pools token vectors, so a risky clause buried in a long turn could
# be AVERAGED AWAY; split the render into overlapping windows, score each, take the MAX (attention to
# the worst span), each window keeping the anchor line so it stays in-distribution for the head.
#
# MEASURED RESULT: no benefit on this model, so it ships OFF. The current head is SATURATED-HIGH on any
# egress/exfil surface features (it over-scores rather than dilutes), so the full view already scores
# ~1.0 on a buried injection and max-pool has nothing to raise. Chunking only helps a head that
# UNDER-scores a buried span — a future, better-discriminating encoder. Kept, off, for that (set
# _CHUNK_AGG = "softmax" | "max" | "top2" below to turn it on).
_CHUNK_MIN_CHARS = 600     # below this: no chunking
_CHUNK_WINDOW = 500        # window size (chars of body)
_CHUNK_OVERLAP = 150       # overlap so a span isn't split
_CHUNK_CAP = 16            # max windows (bounds latency)
_CHUNK_AGG = "off"         # off | max | top2 | softmax  (off by default — no benefit on the current model)


def _split_sentences(body: str) -> list[str]:
    """Break on sentence / line / turn boundaries — cheap, no model."""
    parts = _re.split(r"(?<=[.!?])\s+|\n+", body)
    return [p for p in (s.strip() for s in parts) if p]


def _chunk_render(text: str) -> list[str]:
    """[full render, *windowed views]. Each view = the anchor line (GOAL/TOOL tags, kept so the head
    sees an in-distribution render) + one overlapping ~window slice of the remaining body. Short
    inputs return [text] unchanged, so short structured actions (e.g. InjecAgent) are never chunked."""
    if _CHUNK_AGG == "off" or len(text) <= _CHUNK_MIN_CHARS:
        return [text]
    nl = text.find("\n")
    anchor = text[:nl] if 0 <= nl <= 200 else ""
    body = text[len(anchor):]
    # pack sentences into ~_CHUNK_WINDOW-char windows with ~_CHUNK_OVERLAP carry-over
    windows, cur = [], ""
    for sent in _split_sentences(body):
        if cur and len(cur) + len(sent) + 1 > _CHUNK_WINDOW:
            windows.append(cur)
            cur = (cur[-_CHUNK_OVERLAP:] + " " + sent) if _CHUNK_OVERLAP else sent
        else:
            cur = (cur + " " + sent) if cur else sent
    if cur:
        windows.append(cur)
    views = [text] + [((anchor + "\n" + w) if anchor else w) for w in windows]
    return views[: _CHUNK_CAP + 1]


def _aggregate(raws) -> float:
    """Pool per-window risks into one. Softmax (log-sum-exp, temperature 0.25) ≈ a soft max: it
    lets the single most-dangerous window dominate without a hard max's brittleness to one noisy
    window. `max` and `top2` (mean of the two highest) are available for the sweep."""
    import numpy as _np
    a = _np.atleast_1d(_np.asarray(raws, dtype=float))
    if a.size == 1 or _CHUNK_AGG in ("max", "off"):
        return float(a.max())
    if _CHUNK_AGG == "top2":
        return float(_np.sort(a)[-2:].mean())
    t = 0.25
    return float(t * _np.log(_np.mean(_np.exp(a / t))))


_SEVERITY = {"ALLOW": 0, "ASK": 1, "DENY": 2}


def _more_severe(a: str, b: str) -> str:
    return a if _SEVERITY.get(a, 0) >= _SEVERITY.get(b, 0) else b


def _effect_text(tool: str, args) -> str:
    """The action's EFFECT, rendered like a behavior rule (no goal) so cosine matches the rule."""
    return f"TOOL={tool} ARGS: {decode_and_normalise(_flatten(args))[:400]}"


@dataclass
class SiftScore:
    risk: float                 # calibrated P(bad) in [0,1], after folding in behaviors
    model_risk: float           # the trained model's risk alone (before behaviors)
    decision: str               # "DENY" | "ASK" | "ALLOW" from the conformal bands
    struct: structural.Structural
    reason: str
    matched_behavior: str | None = None


class SiftScorer:
    def __init__(self, artifact_path: str | Path):
        import joblib
        a = joblib.load(artifact_path)
        self.encoder = a["encoder"]
        self.model = a["model"]          # fitted Fusion (its .clf is present; ._enc reloads)
        self.protos = a.get("prototypes")
        self.calibrator = a["calibrator"]
        self.bands = a["bands"]
        self.trained_on = a.get("trained_on", [])
        self._deny_texts: list[str] = []
        self._deny_tokens: list[set] = []
        self._allow_tokens: list[set] = []
        _ = self.model.enc                # warm the encoder now, not on first score()

    @classmethod
    def find(cls, start: str | Path | None = None) -> "SiftScorer | None":
        here = Path(start or __file__).resolve()
        for up in [here, *here.parents]:
            for cand in (up / "sift" / "models" / "sift_judge.joblib", up / "models" / "sift_judge.joblib"):
                if cand.is_file():
                    return cls(cand)
        return None

    # ---- workspace behaviors (ddbt.json) ----

    def load_behaviors(self, cwd: str | Path | None = None) -> "SiftScorer":
        deny, allow = _behaviors.load(cwd)
        return self.set_behaviors(deny, allow)

    def set_behaviors(self, deny_texts: list[str], allow_texts: list[str]) -> "SiftScorer":
        self._deny_texts = list(deny_texts)
        self._deny_tokens = [_content_tokens(t) for t in deny_texts]
        self._allow_tokens = [_content_tokens(t) for t in allow_texts]
        return self

    def _behavior_signal(self, effect_text: str):
        """(behavior_risk in [0,1], matched deny text or None). PURELY LEXICAL: a rule fires when the
        action shares ≥2 salient words with it (e.g. "git"+"commit"). Static embeddings are too loose
        here ("read a file" ≈ "read the database"), and workspace rules name concrete things, so a
        precise keyword match is both reliable and interpretable. The trained model already carries
        the semantic/paraphrase axis; behaviors are the exact keyword layer on top. An `allow` rule
        that overlaps at least as much suppresses the deny (declared-good beats declared-bad)."""
        if not self._deny_tokens:
            return 0.0, None
        act = _content_tokens(effect_text)
        allow_overlap = max((len(t & act) for t in getattr(self, "_allow_tokens", [])), default=0)
        best_shared, best_j = 0, -1
        for j, rule in enumerate(self._deny_tokens):
            shared = len(rule & act)
            if shared > best_shared:
                best_shared, best_j = shared, j
        if best_shared < 2 or best_shared <= allow_overlap:
            return 0.0, None
        risk = min(1.0, 0.55 + 0.15 * best_shared)
        return float(risk), self._deny_texts[best_j]

    def score(self, tool: str, args, goal: str = "", history: str = "",
              sink_provenance: str = "unknown", trusted_domains=("acme.com",)) -> SiftScore:
        rec = {"tool": tool, "args": args, "goal": goal, "history": history,
               "sink_provenance": sink_provenance, "label": 0}
        ds = to_dataset([rec], trusted_domains=trusted_domains)
        # CHUNKED MAX-POOL: score the full render plus overlapping windows of it, and pool. The
        # structural row is identical across windows (regex flags already scan the full text — a
        # buried egress/secret still trips them); only the diluted SEMANTIC view is de-averaged here.
        views = _chunk_render(ds.texts[0])
        emb = self.model.enc.encode(views)                    # (n_views, dim)
        struct_row = ds.struct[0]
        X = np.hstack([emb, np.tile(struct_row, (len(views), 1))])
        raws = self.model.clf.predict_proba(X)[:, 1]
        raw = _aggregate(raws)
        model_risk = float(np.atleast_1d(self.calibrator.transform(np.array([raw])))[0])

        # behaviors match the action's EFFECT (tool+args), not the goal-laden full render
        behavior_risk, matched = self._behavior_signal(_effect_text(tool, args))
        risk = max(model_risk, behavior_risk)                 # a declared rule can only tighten

        # DECISION composition: the trained model can DENY (universal-malicious); a WORKSPACE rule
        # only escalates to ASK — a convention violation ("you didn't ask me to commit") is a
        # human-confirm, not a hard block. So behavior matches never DENY on their own.
        decision = self.bands.decide(model_risk)
        if matched:
            decision = _more_severe(decision, "ASK")

        st = structural.Structural(*ds.struct[0].tolist())
        # output speaks MITRE ATT&CK, but ONLY when something is flagged — a clean ALLOW must not be
        # labelled with the nearest bad tactic (nearest-centroid always returns *some* bad category).
        if decision == "ALLOW" and not matched:
            reason = "clean"
        elif matched:
            reason = "matches a rule you set for this workspace"   # verb phrase; wrapper adds the lede
        else:  # ASK / DENY → name the tactic in plain words (no ATT&CK codes)
            cat = ""
            if self.protos is not None:
                try:
                    _dom, cat = self.protos.explain(ds)[0]
                except Exception:
                    cat = ""
            reason = _mitre.describe(cat, decision)
        return SiftScore(risk=risk, model_risk=model_risk, decision=decision,
                         struct=st, reason=reason, matched_behavior=matched)

    def score_text(self, text: str, trusted_domains=("acme.com",)) -> float:
        """Calibrated P(unsafe) for a whole rendered TRANSCRIPT (a pre-rendered blob, the same shape
        as the R-Judge trajectories in training). This is the trajectory/session-level view: the SAME
        model scores a benign action ~0.03 and an unsafe multi-step session ~0.96, but reading the
        WHOLE session at once recovers signal the per-step judge loses (measured: held-out R-Judge
        F1 0.64 per-step → 0.75 as a max-over-prefixes session score, LLM-free). Used by the engine's
        session-trajectory gate to catch a slow attack whose individual steps each look fine."""
        if not text:
            return 0.0
        ds = to_dataset([{"text": text, "label": 0}], trusted_domains=trusted_domains)
        X = np.hstack([self.model.enc.encode(ds.texts), ds.struct])
        raw = float(self.model.clf.predict_proba(X)[:, 1][0])
        return float(np.atleast_1d(self.calibrator.transform(np.array([raw])))[0])
