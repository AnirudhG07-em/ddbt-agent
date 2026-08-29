"""Method 7: the product. Semantic embedding ⊕ structural features → one calibrated classifier.

Every source we surveyed points the same way: a semantic detector alone is evadable, and the fix is
an ENSEMBLE of embedding + rule/structural signals rather than a single detector ("Bypassing LLM
Guardrails", arXiv:2504.11168, §Recommended Mitigations; DLP practice = content + context + taint).
Fusion concatenates the frozen embedding with the deterministic structural row (egress, sensitivity,
provenance, blast-radius) and lets a gradient-boosted tree learn the interaction — so "sensitive
payload + external sink + tool-derived destination" can dominate regardless of surface wording.

This is also where ddbt earns its keep: the structural columns can be sourced from ddbt's own
provenance/quarantine + grant floor (see sift.features.ddbt_bridge) instead of the lexical proxies,
making the fusion's exfil signal as exact as the ticket.
"""

from __future__ import annotations

import numpy as np

from sift.data.dataset import Dataset
from sift.features.embed import get_encoder


def goal_relatedness(enc, texts, goals):
    """The cross-attention analogue for a static embedder: cosine(render, goal) per row — "is this
    action even about what the user asked?". Both vectors are L2-normalised, so the dot IS the cosine.
    This is the axis that separates an on-goal high-impact action (authorised → safe) from an
    off-goal one lifted from injected content (→ the injection shape). Returned as one extra feature
    column so the GBT can gate 'high-impact BUT on-goal' apart from 'high-impact AND off-goal'."""
    emb = enc.encode(texts)
    gemb = enc.encode([g or "" for g in goals])
    rel = np.sum(emb * gemb, axis=1, keepdims=True).astype(emb.dtype)
    return emb, rel


class Fusion:
    name = "fusion"
    citation = ("ensemble of embedding + structural features (evasion-defence, arXiv:2504.11168); "
                "GBT over [emb ‖ structural]")

    def __init__(self, encoder_name: str = "model2vec"):
        self.encoder_name = encoder_name
        self._enc = None

    def available(self) -> bool:
        return True

    @property
    def enc(self):
        if self._enc is None:
            self._enc = get_encoder(self.encoder_name)
        return self._enc

    # NOTE: a goal-relatedness feature (goal_relatedness, above) was trained and A/B'd here. On the
    # prose-harm sets (ToolEmu/ASB/R-Judge) the model is at the static-embedding ceiling — AUC ≈ 0.5
    # regardless of features — so the extra column was empirically neutral-to-negative (ToolEmu AUC
    # 0.46→0.41) while injection stayed perfect (AUC 1.0). Kept the helper for a future stronger
    # encoder; the deployed head stays [emb ‖ structural] so it composes with the current model.
    def _X(self, ds: Dataset) -> np.ndarray:
        emb = self.enc.encode(ds.texts)
        return np.hstack([emb, ds.struct])

    def fit(self, train: Dataset):
        from sklearn.ensemble import HistGradientBoostingClassifier
        # class_weight="balanced" (sklearn ≥1.3) offsets the injection-heavy corpus so the benign
        # class isn't drowned — directly targets the over-flagging that tanks specificity. Fall back
        # gracefully on older sklearn. early_stopping tempers overfit on the now-larger training set.
        kw = dict(max_iter=600, learning_rate=0.06, l2_regularization=1.0,
                  early_stopping=True, validation_fraction=0.12, random_state=0)
        try:
            self.clf = HistGradientBoostingClassifier(class_weight="balanced", **kw).fit(self._X(train), train.y)
        except TypeError:
            self.clf = HistGradientBoostingClassifier(**kw).fit(self._X(train), train.y)
        return self

    def predict_proba(self, ds: Dataset) -> np.ndarray:
        return self.clf.predict_proba(self._X(ds))[:, 1]
