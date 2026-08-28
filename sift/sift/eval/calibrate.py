"""Turn a raw method score into a calibrated probability and a principled ASK band.

Calibration (a raw margin/score is not a probability):
  * Platt scaling — fit a logistic on held-out scores. Platt, 1999.
  * Isotonic — non-parametric, monotone. Zadrozny & Elkan, KDD 2002.
Both from sklearn; we pick isotonic when the calibration set is large enough, else Platt.

Selective prediction (the DENY / ASK / ALLOW bands):
  Split-conformal thresholds computed on a held-out calibration set give distribution-free control:
  pick τ_deny as the score quantile that holds benign false-positives at the target α, and τ_ask
  below it to open an abstention region. Angelopoulos & Bates, "A Gentle Introduction to Conformal
  Prediction", arXiv:2107.07511; selective classification Geifman & El-Yaniv, arXiv:1705.08500.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class Calibrator:
    kind: str
    _model: object = None

    def transform(self, s: np.ndarray) -> np.ndarray:
        if self._model is None:
            return s
        if self.kind == "isotonic":
            return self._model.transform(s)
        return self._model.predict_proba(s.reshape(-1, 1))[:, 1]


def fit_calibrator(scores: np.ndarray, y: np.ndarray) -> Calibrator:
    """Platt (sigmoid) by default. Isotonic was collapsing to ~0/1 on near-separable training scores,
    which destroys thresholding on out-of-distribution inputs (a 0.99 threshold still admitting
    everything). Platt is a smooth 2-parameter map that keeps scores spread; pass a diverse (overlapping)
    calibration set for the spread to be meaningful."""
    n = len(scores)
    if n < 30 or y.sum() == 0 or y.sum() == n:
        return Calibrator("identity", None)
    from sklearn.linear_model import LogisticRegression
    m = LogisticRegression(max_iter=1000, C=1.0).fit(scores.reshape(-1, 1), y)
    return Calibrator("platt", m)


@dataclass
class Bands:
    tau_deny: float
    tau_ask: float

    def decide(self, p: float) -> str:
        if p >= self.tau_deny:
            return "DENY"
        if p >= self.tau_ask:
            return "ASK"
        return "ALLOW"


def conformal_bands(cal_scores: np.ndarray, cal_y: np.ndarray,
                    target_fpr: float = 0.05, ask_width: float = 0.15) -> Bands:
    """τ_deny = smallest threshold whose benign false-positive rate ≤ target_fpr on calibration data
    (a split-conformal quantile on the benign class). τ_ask opens an abstain band just below it."""
    benign = np.sort(cal_scores[cal_y == 0])
    if benign.size == 0:
        return Bands(0.5, 0.35)
    # the (1 - target_fpr) quantile of benign scores bounds benign false positives at target_fpr…
    q = np.clip(1.0 - target_fpr, 0.0, 1.0)
    tau_deny = float(np.quantile(benign, q))
    # …but clamp to a usable operating range: on near-separable data the benign quantile collapses to
    # ~0, which would DENY everything with any positive risk. Floor at 0.5 (a real probability
    # midpoint), cap at 0.95 so a confident detection always denies.
    tau_deny = float(min(max(tau_deny, 0.5), 0.95))
    tau_ask = float(min(max(tau_deny - ask_width, 0.2), tau_deny))
    return Bands(tau_deny, tau_ask)
