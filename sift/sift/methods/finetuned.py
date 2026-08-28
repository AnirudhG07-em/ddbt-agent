"""Method 5: methods that TRAIN the embedding itself (not just a head on a frozen one).

These need heavier deps and a model download, so both self-skip via available() when absent, letting
the bake-off run on whatever is installed.

  5. Model2VecTrained — Model2Vec's native StaticModelForClassification: a trainable head on top of
     the static token embeddings, optionally re-distilled. Keeps the ~30 MB / no-transformer profile.
     Model2Vec training (Feb 2025), MinishLab, github.com/MinishLab/model2vec.
"""

from __future__ import annotations

import importlib.util

import numpy as np

from sift.data.dataset import Dataset

MINILM_ID = "sentence-transformers/all-MiniLM-L6-v2"
MODEL2VEC_ID = "minishlab/potion-base-32M"


def _has(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None



class Model2VecTrained:
    name = "model2vec_trained"
    citation = "Model2Vec StaticModelForClassification (MinishLab 2025)"

    def __init__(self, model_id: str = MODEL2VEC_ID):
        self.model_id = model_id

    def available(self) -> bool:
        if not _has("model2vec"):
            return False
        try:
            from model2vec.train import StaticModelForClassification  # noqa: F401
            return True
        except Exception:
            return False

    def fit(self, train: Dataset):
        from model2vec.train import StaticModelForClassification
        self.model = StaticModelForClassification.from_pretrained(model_name=self.model_id)
        self.model.fit(train.texts, train.y.tolist())
        return self

    def predict_proba(self, ds: Dataset) -> np.ndarray:
        import numpy as _np
        # the classifier exposes predict_proba over its label set; take P(label==1)
        proba = _np.asarray(self.model.predict_proba(ds.texts))
        classes = list(getattr(self.model, "classes", [0, 1]))
        col = classes.index(1) if 1 in classes else -1
        return proba[:, col]
