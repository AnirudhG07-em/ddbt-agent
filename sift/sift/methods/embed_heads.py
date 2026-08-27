"""Methods 1–3 and 6: a shared encoder with different heads on top.

All four share one insight from production guardrails — freeze a cheap embedding, put a light head
on it — which is how NVIDIA NemoGuard-JailbreakDetect (random forest on Snowflake embeddings) and
the embedding+XGBoost injection detector (97.7% F1 @ ~1µs/sample, CEUR Vol-3920 paper15) both work.

  1. StaticLinear   — encoder + logistic regression. The fast floor.
  2. StaticGBT      — encoder + histogram gradient boosting. Non-linear; the NemoGuard pattern.
  3. Prototypes     — nearest-centroid cosine over the taxonomy. Zero-shot, interpretable, extensible.
                      Rocchio/NN-centroid (Manning IIR ch.14); Prototypical Networks (Snell,
                      arXiv:1703.05175). Risk = margin (bad_sim − good_sim), squashed.
  6. Anomaly        — Mahalanobis distance to the BENIGN manifold, trained on label==0 only. Catches
                      novel attacks no prototype covers. Mahalanobis OOD: Lee et al., arXiv:1807.03888.

The encoder is chosen by name (model2vec / minilm / hashing) via sift.features.embed.
"""

from __future__ import annotations

import numpy as np

from sift.data.dataset import Dataset
from sift.data import taxonomy
from sift.features.embed import get_encoder


class _EncoderMethod:
    encoder_name = "model2vec"

    def __init__(self, encoder_name: str | None = None):
        if encoder_name:
            self.encoder_name = encoder_name
        self._enc = None

    def available(self) -> bool:
        return True  # encoder layer self-degrades to hashing

    @property
    def enc(self):
        if self._enc is None:
            self._enc = get_encoder(self.encoder_name)
        return self._enc

    def _embed(self, ds: Dataset) -> np.ndarray:
        return self.enc.encode(ds.texts)


class StaticLinear(_EncoderMethod):
    name = "static_linear"
    citation = "encoder + logistic regression (embedding+linear guardrail pattern)"

    def fit(self, train: Dataset):
        from sklearn.linear_model import LogisticRegression
        X = self._embed(train)
        self.clf = LogisticRegression(max_iter=1000, class_weight="balanced").fit(X, train.y)
        return self

    def predict_proba(self, ds: Dataset) -> np.ndarray:
        return self.clf.predict_proba(self._embed(ds))[:, 1]


class StaticGBT(_EncoderMethod):
    name = "static_gbt"
    citation = ("encoder + histogram gradient boosting; cf. NemoGuard random forest & "
                "embedding+XGBoost injection detector, CEUR Vol-3920 paper15")

    def fit(self, train: Dataset):
        from sklearn.ensemble import HistGradientBoostingClassifier
        X = self._embed(train)
        self.clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08,
                                                   l2_regularization=1.0).fit(X, train.y)
        return self

    def predict_proba(self, ds: Dataset) -> np.ndarray:
        return self.clf.predict_proba(self._embed(ds))[:, 1]


class Prototypes(_EncoderMethod):
    name = "prototypes"
    citation = "nearest-centroid / Rocchio (Manning IIR ch.14); Prototypical Networks (Snell, arXiv:1703.05175)"

    def fit(self, train: Dataset):
        # zero-shot: centroids come from the taxonomy, not the training labels. We still accept
        # `train` to fit the margin→prob squashing scale on real data.
        bad_texts, _, _ = taxonomy.all_prototypes()
        self.bad_c = self._centroids(bad_texts)
        self.good_c = self._centroids(taxonomy.BENIGN_PROTOTYPES)
        margins = self._margin(self._embed(train))
        # scale so the logistic is centred on the training margin distribution
        self.mu, self.sd = float(margins.mean()), float(margins.std() + 1e-6)
        return self

    def _centroids(self, texts: list[str]) -> np.ndarray:
        V = self.enc.encode(texts)
        c = V.mean(axis=0, keepdims=True)
        return c / (np.linalg.norm(c) + 1e-9)

    def _margin(self, X: np.ndarray) -> np.ndarray:
        bad_sim = X @ self.bad_c.T  # (n,1) cosine, X already normalised
        good_sim = X @ self.good_c.T
        return (bad_sim - good_sim).ravel()

    def predict_proba(self, ds: Dataset) -> np.ndarray:
        z = (self._margin(self._embed(ds)) - self.mu) / self.sd
        return 1.0 / (1.0 + np.exp(-z))

    def explain(self, ds: Dataset):
        """Nearest bad (domain,category) per sample — the human-readable reason."""
        bad_texts, doms, cats = taxonomy.all_prototypes()
        P = self.enc.encode(bad_texts)
        X = self._embed(ds)
        idx = (X @ P.T).argmax(axis=1)
        return [(doms[i], cats[i]) for i in idx]


class Anomaly(_EncoderMethod):
    name = "anomaly"
    citation = "Mahalanobis distance to benign manifold (Lee et al., arXiv:1807.03888)"

    def fit(self, train: Dataset):
        X = self._embed(train)
        benign = X[train.y == 0]
        # shrinkage covariance (+ its own location_) for stability in high dim / few samples
        from sklearn.covariance import LedoitWolf
        self.cov = LedoitWolf().fit(benign)
        d = self._maha(X)
        self.mu, self.sd = float(d.mean()), float(d.std() + 1e-6)
        return self

    def _maha(self, X: np.ndarray) -> np.ndarray:
        return self.cov.mahalanobis(X)  # distance from the fitted benign centre

    def predict_proba(self, ds: Dataset) -> np.ndarray:
        z = (self._maha(self._embed(ds)) - self.mu) / self.sd
        return 1.0 / (1.0 + np.exp(-z))
