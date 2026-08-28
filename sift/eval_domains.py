#!/usr/bin/env python
"""Per-domain held-out test metrics — the extensible train/test loop for every work-system.

Every domain pack in sift/data/domains/*.jsonl is auto-split (deterministic 80/20). `ddbt prepare`
trains on the TRAIN split; this scores the sift model on the untouched TEST split, per domain, so you
can SEE whether a domain was actually learned (train accuracy hides that).

    uv run python sift/eval_domains.py            # every domain's test set
    uv run python sift/eval_domains.py database

Add a domain = drop a JSONL in data/domains/ → it appears here automatically. No code change.
"""

from __future__ import annotations

import sys

import numpy as np

from sift.data import domains
from sift.data.dataset import to_dataset
from sift.serve import SiftScorer


def _metrics(y, risk, thr=0.5):
    y = np.asarray(y); p = (np.asarray(risk) >= thr).astype(int)
    pos, neg = y == 1, y == 0
    recall = (p[pos] == 1).mean() if pos.any() else float("nan")     # bad caught
    spec = (p[neg] == 0).mean() if neg.any() else float("nan")       # good left alone
    acc = (p == y).mean() if len(y) else float("nan")
    return acc, recall, spec, int(pos.sum()), int(neg.sum())


def main(argv=None):
    names = argv if argv is not None else sys.argv[1:]
    scorer = SiftScorer.find()
    if scorer is None:
        print("no model — run `ddbt prepare` first"); return 1
    doms = names or domains.domains()
    print(f"=== per-domain TEST metrics (held-out 20%) · model={scorer.encoder} ===\n")
    print(f"{'domain':16s} {'n_test':>6s} {'acc':>6s} {'recall':>7s} {'specificity':>12s}")
    rows = []
    for name in doms:
        test = domains.load(only=[name], split="test")
        if not test:
            print(f"{name:16s}  (no test cases)"); continue
        ds = to_dataset(test)
        risk = [scorer.score(r["tool"], r["args"], goal=r.get("goal", "")).model_risk for r in test]
        y = [int(r["label"]) for r in test]
        acc, rec, spec, npos, nneg = _metrics(y, risk)
        rows.append((name, len(test), acc, rec, spec))
        print(f"{name:16s} {len(test):>6d} {acc:>6.0%} {rec:>7.0%} {spec:>11.0%}")
    print("\nrecall = held-out BAD cases flagged; specificity = held-out GOOD cases allowed.\n"
          "Low recall AND the model scoring ~0 everywhere → the encoder can't represent this domain's\n"
          "distinctions (e.g. SQL details blur in a static embedding); needs richer features or more data.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
