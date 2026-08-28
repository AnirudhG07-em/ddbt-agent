"""Shared static-embedding accessor — the ONE Model2Vec encoder, reused across ddbt.

The sift judge already loads potion-base-32M once, cached by name in sift.features.embed._CACHE. This
returns that SAME cached instance, so semantic egress scoring (net_semantic) costs no extra memory when
sift is the judge. Degrades to None when the sift package / model isn't importable — the caller then
simply skips semantic scoring (the deterministic controls still run). Loading is attempted once.
"""

from __future__ import annotations

import sys
from pathlib import Path

_TRIED = False
_ENC = None


def get_encoder():
    """The shared Model2Vec encoder (L2-normalized `.encode(texts)->(n,dim)`), or None if unavailable."""
    global _TRIED, _ENC
    if _TRIED:
        return _ENC
    _TRIED = True
    try:
        for up in Path(__file__).resolve().parents:
            if (up / "sift" / "sift" / "serve.py").is_file():
                sys.path.insert(0, str(up / "sift"))
                break
        from sift.features.embed import get_encoder as _sift_get_encoder
        _ENC = _sift_get_encoder("model2vec")  # same cached instance the judge uses
    except Exception:  # noqa: BLE001 — no model → semantic scoring is simply skipped
        _ENC = None
    return _ENC
