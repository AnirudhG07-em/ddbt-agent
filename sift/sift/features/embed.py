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
MODEL2VEC_8M_ID = "minishlab/potion-base-8M"          # "sift-mini": ~4x smaller (general)
MODEL2VEC_CODE_ID = "minishlab/potion-code-16M"       # code-domain static model — matches our command/tool inputs
MODEL2VEC_RETRIEVAL_ID = "minishlab/potion-retrieval-32M"  # retrieval/similarity-tuned
MINILM_ID = "sentence-transformers/all-MiniLM-L6-v2"

# OTHER-LAB encoders (real transformers, NEED torch via sentence-transformers) — benchmark comparison
# ONLY, never the shipped default (which stays the torch-free model2vec potion-32M). These answer "could
# a small model from another lab beat our static encoder?" at the cost of a torch dependency + slower CPU
# inference. IDs are HuggingFace repos; some are gated (accept the license + set HF_TOKEN) or need
# trust_remote_code. See _ST_MODELS below.
_ST_MODELS = {
    "embeddinggemma":  ("google/embeddinggemma-300m", False),   # Google, 300M (gated — accept license)
    "qwen3-0.6b":      ("Qwen/Qwen3-Embedding-0.6B", False),    # Alibaba/Qwen, 0.6B (large, slow on CPU)
    "bge-small":       ("BAAI/bge-small-en-v1.5", False),       # BAAI, 33M
    "e5-small":        ("intfloat/e5-small-v2", False),         # Microsoft, 33M
    "gte-small":       ("Alibaba-NLP/gte-small", True),         # Alibaba, 30M (trust_remote_code)
    "nomic-1.5":       ("nomic-ai/nomic-embed-text-v1.5", True),# Nomic, 137M (trust_remote_code)
    "arctic-s":        ("Snowflake/snowflake-arctic-embed-s", False),  # Snowflake, 33M
}


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


_ST_DTYPES = {"F64": np.float64, "F32": np.float32, "F16": np.float16, "BF16": np.float16,
              "I64": np.int64, "I32": np.int32, "I16": np.int16, "I8": np.int8, "U8": np.uint8}


def _load_static_mmap(model_id: str):
    """Load a Model2Vec StaticModel with the embedding matrix MEMORY-MAPPED, from the local cache only.

    model2vec's from_pretrained (a) re-checks HuggingFace over the network and (b) COPIES the whole
    embedding matrix into RAM (~0.55 s + ~130 MB resident). This instead resolves the cached files with
    no network, and np.memmap's the matrix straight out of the safetensors blob — load is ~0 and pages
    fault in lazily on use, so a warm daemon keeps only its working set resident. Raises on anything
    unexpected so the caller falls back to from_pretrained."""
    import json
    from huggingface_hub import hf_hub_download
    from model2vec import StaticModel
    from tokenizers import Tokenizer
    st = hf_hub_download(model_id, "model.safetensors", local_files_only=True)
    tok = hf_hub_download(model_id, "tokenizer.json", local_files_only=True)
    cfg = hf_hub_download(model_id, "config.json", local_files_only=True)
    with open(st, "rb") as f:
        n = int.from_bytes(f.read(8), "little")
        hdr = json.loads(f.read(n))
    meta = hdr["embeddings"]
    start, _end = meta["data_offsets"]
    vectors = np.memmap(st, dtype=_ST_DTYPES[meta["dtype"]], mode="r",
                        offset=8 + n + start, shape=tuple(meta["shape"]))
    return StaticModel(vectors=vectors, tokenizer=Tokenizer.from_file(tok), config=json.load(open(cfg)))


class Model2VecEncoder(Encoder):
    name = "model2vec"
    citation = "Model2Vec potion-base-32M, MinishLab 2024 (github.com/MinishLab/model2vec)"

    def __init__(self, model_id: str = MODEL2VEC_ID):
        import contextlib
        # distinct name per variant so the train-time encoder guard matches the requested encoder
        self.name = {MODEL2VEC_8M_ID: "model2vec-8m", MODEL2VEC_CODE_ID: "model2vec-code",
                     MODEL2VEC_RETRIEVAL_ID: "model2vec-retrieval"}.get(model_id, "model2vec")
        _quiet_hub()
        # model2vec/huggingface also print reconstruct/download lines to stdout — swallow them during
        # the one-time load so nothing reaches the terminal (or the hook's stdout).
        with open(os.devnull, "w") as _dn, contextlib.redirect_stdout(_dn), contextlib.redirect_stderr(_dn):
            try:
                self.model = _load_static_mmap(model_id)              # fast: cache-only + mmap'd matrix
            except Exception:
                from model2vec import StaticModel  # lazy
                # fallback (e.g. first run, cache empty). force_download DEFAULTS TO TRUE in model2vec —
                # that re-fetches from HuggingFace every load — so pin it False to use the cache.
                try:
                    self.model = StaticModel.from_pretrained(model_id, force_download=False)
                except TypeError:
                    self.model = StaticModel.from_pretrained(model_id)   # older signature
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


class STEncoder(Encoder):
    """Any HuggingFace sentence-embedding model via sentence-transformers — from OTHER labs (Google
    EmbeddingGemma, Qwen3-Embedding, BGE, E5, GTE, Nomic, Arctic…). NEEDS torch, so this is a benchmark
    comparison ONLY; the shipped judge stays the torch-free model2vec. trust_remote_code covers models
    that ship custom modeling code (gte, nomic). e5 needs a task prefix or it underperforms badly."""

    def __init__(self, name: str, model_id: str, trust_remote_code: bool = False):
        from sentence_transformers import SentenceTransformer  # lazy — pulls torch
        self.name = name
        self.citation = f"{model_id} (via sentence-transformers)"
        self.model = SentenceTransformer(model_id, trust_remote_code=trust_remote_code)
        self.dim = int(self.model.get_sentence_embedding_dimension())
        self._prefix = "query: " if "e5" in model_id.lower() else ""

    def encode(self, texts: list[str]) -> np.ndarray:
        t = [self._prefix + x for x in texts] if self._prefix else texts
        return np.asarray(
            self.model.encode(t, normalize_embeddings=True, show_progress_bar=False), dtype=np.float32)


_BUILDERS = {"model2vec": Model2VecEncoder,
             "model2vec-8m": lambda: Model2VecEncoder(MODEL2VEC_8M_ID),         # sift-mini (general, 8M)
             "model2vec-code": lambda: Model2VecEncoder(MODEL2VEC_CODE_ID),     # code-domain, 16M
             "model2vec-retrieval": lambda: Model2VecEncoder(MODEL2VEC_RETRIEVAL_ID),  # retrieval-tuned, 32M
             "minilm": MiniLMEncoder, "hashing": HashingEncoder}
# other-lab torch encoders (benchmark only) — late-binding defaults so each lambda keeps its own id
_BUILDERS.update({_n: (lambda name=_n, mid=_m, trc=_t: STEncoder(name, mid, trc))
                  for _n, (_m, _t) in _ST_MODELS.items()})
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
