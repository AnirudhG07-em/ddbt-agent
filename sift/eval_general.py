#!/usr/bin/env python
"""Held-out test metrics for the GENERAL bad-action model (ToolEmu + Agent-SafetyBench).

`train_sift.py` trains on the TRAIN split of these; this scores the untouched TEST split, so the
numbers reflect generalisation to unseen scenarios, not memorisation.

    uv run python sift/eval_general.py
"""

from __future__ import annotations

import numpy as np

from sift.data import benches
from sift.data.dataset import to_dataset
from sift.serve import SiftScorer


def _metrics(y, risk, thr=0.5):
    y = np.asarray(y); p = (np.asarray(risk) >= thr).astype(int)
    pos, neg = y == 1, y == 0
    from sklearn.metrics import f1_score
    rec = (p[pos] == 1).mean() if pos.any() else float("nan")
    spec = (p[neg] == 0).mean() if neg.any() else float("nan")
    f1 = f1_score(y, p) if pos.any() and neg.any() else float("nan")
    return (p == y).mean(), rec, spec, f1


def _score(scorer, recs):
    ds = to_dataset(recs)
    risk = [scorer.score(r["tool"], r["args"], goal=r.get("goal", "")).model_risk for r in recs]
    return [int(r["label"]) for r in recs], risk


def main(argv=None):
    scorer = SiftScorer.find()
    if scorer is None:
        print("no model — run train first"); return 1
    sets = {
        "toolemu": benches.load_toolemu_labeled(split="test"),
        "agentsafetybench": benches.load_agentsafetybench_labeled(split="test", limit=1200),
    }
    print(f"=== held-out TEST metrics · model={scorer.encoder} ===\n")
    print(f"{'dataset':18s} {'n':>5s} {'acc':>6s} {'recall':>7s} {'specificity':>12s} {'F1':>6s}")
    for name, recs in sets.items():
        if not recs:
            print(f"{name:18s}  (no data)"); continue
        y, risk = _score(scorer, recs)
        acc, rec, spec, f1 = _metrics(y, risk)
        print(f"{name:18s} {len(recs):>5d} {acc:>6.0%} {rec:>7.0%} {spec:>11.0%} {f1:>6.2f}")
    print("\nTrained on the TRAIN split of the same sets; these are unseen cases.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
