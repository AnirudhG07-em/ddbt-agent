"""Methods 4–5: methods that TRAIN the embedding itself (not just a head on a frozen one).

These need heavier deps and a model download, so both self-skip via available() when absent, letting
the bake-off run on whatever is installed.

  4. SetFitMethod — contrastive Siamese fine-tune of a Sentence-Transformer, then a logistic head.
     Shapes the embedding space so same-badness clusters, which is what makes cosine/margins mean
     something. Competitive with full fine-tuning from ~8 examples/class. Prompt-free, no LLM.
     SetFit: Tunstall et al., "Efficient Few-Shot Learning Without Prompts", arXiv:2209.11055.
     Base encoder all-MiniLM-L6-v2 (~90 MB) — under the 100 MB budget, still not an SLM.

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


class SetFitMethod:
    """SetFit as a METHOD, implemented directly on sentence-transformers (no `setfit` package).

    The `setfit` 1.1 wheel is in a version deadlock (imports transformers.default_logdir, removed in
    4.46, yet needs the Trainer.processing_class added in 4.46), so we run the algorithm ourselves —
    which is exactly SetFit's two steps: (1) contrastive Siamese fine-tune of the ST on same/diff
    label pairs, (2) a logistic head on the resulting embeddings. Tunstall et al., arXiv:2209.11055.
    """

    name = "setfit"
    citation = "SetFit (contrastive ST fine-tune + head), Tunstall et al., arXiv:2209.11055 — impl on sentence-transformers"

    def __init__(self, model_id: str = MINILM_ID, epochs: int = 1, pairs_per_example: int = 2,
                 max_train: int = 300, max_steps: int = 40):
        # capped hard so a CPU fine-tune stays ~1 min and NEVER silently stalls: subsample train,
        # few pairs, ≤40 steps, and a visible progress bar (below).
        self.model_id, self.epochs, self.pairs_per_example = model_id, epochs, pairs_per_example
        self.max_train, self.max_steps = max_train, max_steps

    def available(self) -> bool:
        return _has("sentence_transformers") and _has("torch")

    def _pairs(self, texts, y):
        import random
        from sentence_transformers import InputExample
        rng = random.Random(0)
        by = {0: [t for t, l in zip(texts, y) if l == 0], 1: [t for t, l in zip(texts, y) if l == 1]}
        ex = []
        for t, l in zip(texts, y):
            for _ in range(self.pairs_per_example):
                if rng.random() < 0.5 and by[l]:            # positive: same label
                    ex.append(InputExample(texts=[t, rng.choice(by[l])], label=1.0))
                elif by[1 - l]:                              # negative: opposite label
                    ex.append(InputExample(texts=[t, rng.choice(by[1 - l])], label=0.0))
        return ex

    def fit(self, train: Dataset):
        import os
        os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")  # avoid a fork-deadlock on CPU
        import torch
        torch.set_num_threads(max(1, min(4, os.cpu_count() or 1)))  # thrashing all cores stalls
        from sentence_transformers import SentenceTransformer, losses
        from torch.utils.data import DataLoader
        from sklearn.linear_model import LogisticRegression

        # subsample so a CPU fine-tune stays bounded
        texts, y = train.texts, train.y.tolist()
        if len(texts) > self.max_train:
            idx = list(range(len(texts)))[:: max(1, len(texts) // self.max_train)][: self.max_train]
            texts = [texts[i] for i in idx]
            y = [y[i] for i in idx]

        self.model = SentenceTransformer(self.model_id)
        pairs = self._pairs(texts, y)[: self.max_steps * 16]
        loader = DataLoader(pairs, shuffle=True, batch_size=16, pin_memory=False)  # no accelerator
        loss = losses.ContrastiveLoss(self.model)  # Siamese contrastive — the SetFit body 1
        # show_progress_bar=True → a live tqdm bar, so a slow CPU epoch is never a silent stall.
        self.model.fit(train_objectives=[(loader, loss)], epochs=self.epochs,
                       warmup_steps=max(1, len(loader) // 10), show_progress_bar=True)
        import numpy as _np
        emb = self.model.encode(train.texts, normalize_embeddings=True, show_progress_bar=False)
        self.head = LogisticRegression(max_iter=1000, class_weight="balanced").fit(
            emb, _np.asarray(train.y))  # body 2
        return self

    def predict_proba(self, ds: Dataset) -> np.ndarray:
        emb = self.model.encode(ds.texts, normalize_embeddings=True, show_progress_bar=False)
        return self.head.predict_proba(emb)[:, 1]


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
