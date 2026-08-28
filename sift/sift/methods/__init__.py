"""Registry of every bake-off method. `build_all(encoder)` returns fresh instances.

The deployed method is `fusion`. The rest are active comparators. SetFit is non-deployed and lives in
`experimental/`; it is imported LAZILY only when `include_slow=True`, so importing this package never
depends on `experimental/` being on the path (keeps artifact loading in the ddbt env robust)."""

from __future__ import annotations

from sift.methods.embed_heads import StaticLinear, StaticGBT, Prototypes, Anomaly
from sift.methods.finetuned import Model2VecTrained
from sift.methods.fusion import Fusion


def build_all(encoder: str = "model2vec", include_slow: bool = False) -> list:
    """Deployed + comparator methods, in report order. `include_slow=True` adds the experimental
    SetFit (slow CPU fine-tune, non-deployed, lives in experimental/)."""
    methods = [
        StaticLinear(encoder),
        StaticGBT(encoder),
        Prototypes(encoder),
        Anomaly(encoder),
        Model2VecTrained(),
        Fusion(encoder),
    ]
    if include_slow:
        try:
            from experimental.setfit_method import SetFitMethod
            methods.insert(4, SetFitMethod())
        except Exception:
            pass  # experimental/ not importable → skip the comparator, never break the run
    return methods


__all__ = ["build_all", "StaticLinear", "StaticGBT", "Prototypes", "Anomaly", "Model2VecTrained", "Fusion"]
