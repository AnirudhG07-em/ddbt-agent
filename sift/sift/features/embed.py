"""Encoders — turn a rendered action string into a dense vector. All ≤100 MB, none an SLM.

Three backends, selected by name; heavy ones lazy-import so the harness runs with zero downloads:

* "model2vec" — potion-base-32M STATIC embeddings (~30 MB, 32 M params). A distilled token→vector
  lookup + pooling, i.e. *not a transformer forward pass and provably not a language model* — this
  is the pick for the "no SLM, ≤100 MB" constraint. ~500× faster on CPU than its teacher, retains
  ~85–95 % of MTEB. Model2Vec, MinishLab 2024, https://github.com/MinishLab/model2vec.
* "minilm" — all-MiniLM-L6-v2 (~90 MB) via sentence-transformers; used as the SetFit base. A real
  (small) encoder, kept for the accuracy-ceiling comparison. Sentence-BERT, Reimers & Gurevych,
  arXiv:1908.10084.
* "hashing" — feature-hashed char n-grams, L2-normalised. NO download, NO model — a deterministic
  offline fallback so every script runs before any deps land. Feature hashing: Weinberger et al.,
  "Feature Hashing for Large Scale Multitask Learning", ICML 2009, arXiv:0902.2206.

`get_encoder(name)` falls back hashing←minilm←model2vec if a backend can't load, and reports which
it used, so a bake-off run never silently dies on a missing dependency.
"""

from __future__ import annotations

import hashlib
import os

import numpy as np

# Silence the model-load progress bars (huggingface_hub "Fetching N files", model2vec reconstruct,
# tokenizers fork warning) — they otherwise spam the terminal every time ddbt loads the encoder, and
# could corrupt the Claude Code hook's stdout. Must be set BEFORE huggingface_hub/model2vec import.
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")


def _quiet_hub():
    """Belt-and-suspenders: also call the API that disables tqdm bars, if present."""
    try:
        from huggingface_hub.utils import disable_progress_bars
        disable_progress_bars()
    except Exception:
        pass


DEFAULT = "model2vec"
MODEL2VEC_ID = "minishlab/potion-base-32M"
MINILM_ID = "sentence-transformers/all-MiniLM-L6-v2"


class Encoder:
    name: str = "base"
    dim: int = 0
    citation: str = ""

    def encode(self, texts: list[str]) -> np.ndarray:  # -> (n, dim) float32, L2-normalised
        raise NotImplementedError


class HashingEncoder(Encoder):
    """Offline, dependency-free. char 3/4/5-grams → hashed buckets → L2 norm."""

    name = "hashing"
    citation = "Weinberger et al., Feature Hashing, ICML 2009 (arXiv:0902.2206)"

    def __init__(self, dim: int = 1024, ngrams=(3, 4, 5)):
        self.dim = dim
        self.ngrams = ngrams

    def _one(self, text: str) -> np.ndarray:
        v = np.zeros(self.dim, dtype=np.float32)
        t = f" {text.lower()} "
        for n in self.ngrams:
            for i in range(len(t) - n + 1):
                g = t[i:i + n]
                h = int.from_bytes(hashlib.blake2b(g.encode(), digest_size=8).digest(), "little")
                sign = 1.0 if (h >> 63) & 1 else -1.0
                v[h % self.dim] += sign
        nrm = np.linalg.norm(v)
        return v / nrm if nrm else v

    def encode(self, texts: list[str]) -> np.ndarray:
        return np.vstack([self._one(t) for t in texts]) if texts else np.zeros((0, self.dim), np.float32)


class Model2VecEncoder(Encoder):
    name = "model2vec"
    citation = "Model2Vec potion-base-32M, MinishLab 2024 (github.com/MinishLab/model2vec)"

    def __init__(self, model_id: str = MODEL2VEC_ID):
        import contextlib
        _quiet_hub()
        # model2vec/huggingface also print reconstruct/download lines to stdout — swallow them during
        # the one-time load so nothing reaches the terminal (or the hook's stdout).
        with open(os.devnull, "w") as _dn, contextlib.redirect_stdout(_dn), contextlib.redirect_stderr(_dn):
            from model2vec import StaticModel  # lazy
            self.model = StaticModel.from_pretrained(model_id)
        self.dim = int(self.model.dim)

    def encode(self, texts: list[str]) -> np.ndarray:
        v = np.asarray(self.model.encode(texts), dtype=np.float32)
        n = np.linalg.norm(v, axis=1, keepdims=True)
        return v / np.clip(n, 1e-9, None)


class MiniLMEncoder(Encoder):
    name = "minilm"
    citation = "all-MiniLM-L6-v2 / Sentence-BERT, Reimers & Gurevych, arXiv:1908.10084"

    def __init__(self, model_id: str = MINILM_ID):
        from sentence_transformers import SentenceTransformer  # lazy
        self.model = SentenceTransformer(model_id)
        self.dim = int(self.model.get_sentence_embedding_dimension())

    def encode(self, texts: list[str]) -> np.ndarray:
        return np.asarray(
            self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False),
            dtype=np.float32,
        )


_BUILDERS = {"model2vec": Model2VecEncoder, "minilm": MiniLMEncoder, "hashing": HashingEncoder}
_CACHE: dict[str, Encoder] = {}


def get_encoder(name: str = DEFAULT, *, strict: bool = False) -> Encoder:
    """Return a cached encoder, degrading gracefully unless strict=True."""
    if name in _CACHE:
        return _CACHE[name]
    order = [name] + [n for n in ("minilm", "hashing") if n != name]
    last = None
    for cand in order:
        try:
            enc = _BUILDERS[cand]()
            if cand != name:
                print(f"[sift.embed] '{name}' unavailable → fell back to '{cand}'")
            _CACHE[name] = enc
            return enc
        except Exception as exc:  # noqa: BLE001 — any import/download failure degrades
            last = exc
            if strict:
                raise
    raise RuntimeError(f"no encoder available: {last}")
