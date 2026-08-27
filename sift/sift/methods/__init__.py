"""Registry of every bake-off method. `build_all(encoder)` returns fresh instances."""

from __future__ import annotations

from sift.methods.embed_heads import StaticLinear, StaticGBT, Prototypes, Anomaly
from sift.methods.finetuned import SetFitMethod, Model2VecTrained
from sift.methods.fusion import Fusion


def build_all(encoder: str = "model2vec", include_slow: bool = False) -> list:
    """The methods in report order. Heavy ones self-skip via .available().

    `include_slow=False` (default) EXCLUDES SetFit: it does a full MiniLM contrastive fine-tune per
    benchmark on CPU, which is minutes-to-stall slow and redundant with model2vec_trained (which
    also fine-tunes an embedding and scores higher here). Pass --slow / include_slow=True to add it.
    """
    methods = [
        StaticLinear(encoder),
        StaticGBT(encoder),
        Prototypes(encoder),
        Anomaly(encoder),
        Model2VecTrained(),
        Fusion(encoder),
    ]
    if include_slow:
        methods.insert(4, SetFitMethod())
    return methods


__all__ = ["build_all", "StaticLinear", "StaticGBT", "Prototypes", "Anomaly",
           "SetFitMethod", "Model2VecTrained", "Fusion"]
