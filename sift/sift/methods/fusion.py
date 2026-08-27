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

    def _X(self, ds: Dataset) -> np.ndarray:
        emb = self.enc.encode(ds.texts)
        return np.hstack([emb, ds.struct])

    def fit(self, train: Dataset):
        from sklearn.ensemble import HistGradientBoostingClassifier
        self.clf = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.06,
                                                   l2_regularization=1.0).fit(self._X(train), train.y)
        return self

    def predict_proba(self, ds: Dataset) -> np.ndarray:
        return self.clf.predict_proba(self._X(ds))[:, 1]
