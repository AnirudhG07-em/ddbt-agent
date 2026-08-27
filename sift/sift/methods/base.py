"""Common interface for every bake-off method, so the harness can treat them uniformly.

A Method maps a Dataset → per-sample risk in [0, 1]. Some are supervised (fit on labels), some are
zero-shot (prototypes), some train on benign only (anomaly). `available()` lets a method opt out
cleanly when its heavy dependency isn't installed, so a run degrades instead of crashing.
"""

from __future__ import annotations

from typing import Protocol

import numpy as np

from sift.data.dataset import Dataset


class Method(Protocol):
    name: str
    citation: str

    def available(self) -> bool: ...
    def fit(self, train: Dataset) -> "Method": ...
    def predict_proba(self, ds: Dataset) -> np.ndarray: ...  # (n,) risk in [0,1]


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))
