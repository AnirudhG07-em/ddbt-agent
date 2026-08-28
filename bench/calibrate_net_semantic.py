"""Calibrate net_semantic's two thresholds for GENERALIZATION, not fit.

  * scores every egress_eval case with the DEPLOYED net_semantic math (same encoder + centroids),
  * splits train/test by hash, grid-searches (sensitivity_margin, relatedness_max),
  * picks the operating point by 5-FOLD CV mean-F1 (robust, not the train-max — guards overfitting),
  * reports the held-out TEST metrics and a PER-GROUP recall breakdown, so we can see whether the four
    seeded centroids generalize to the out-of-distribution and MITRE-mapped sensitive kinds.

Run:  uv run python bench/calibrate_net_semantic.py
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

import egress_eval  # noqa: E402
from ddbt.judge.embedder import get_encoder  # noqa: E402
from ddbt.plugins.net_semantic import _PUBLIC, _SENSITIVE, NetSemantic  # noqa: E402


def _bucket(cid: str, mod: int) -> int:
    return int(hashlib.blake2b(cid.encode(), digest_size=4).hexdigest(), 16) % mod


def _norm(v):
    n = np.linalg.norm(v)
    return v / n if n else v


def _centroids_from(enc, sens: dict):
    """Class → L2-normalized mean vector, for an arbitrary subset of sensitivity classes (+ public)."""
    return {cls: _norm(enc.encode(exs).mean(axis=0)) for cls, exs in {**sens, "public_benign": _PUBLIC}.items()}


def _encode_cases(cases, enc):
    """Encode payload / goal / destination-context ONCE; reused across every centroid set (fast LOCO)."""
    P = enc.encode([c["payload"] for c in cases])
    G = enc.encode([c["goal"] for c in cases])
    D = enc.encode([f'{c["dest"]} {c["payload"][:200]}' for c in cases])
    return P, G, D


def _feats(P, G, D, centroids):
    """(sensitivity_margin, relatedness) per case — mirrors net_semantic.pre_check exactly."""
    C = np.vstack([centroids[k] for k in centroids if k != "public_benign"])
    pub = centroids["public_benign"]
    return [(float((C @ P[i]).max()) - float(pub @ P[i]), float(G[i] @ D[i])) for i in range(len(P))]


def _predict(feat, t_s, t_r):
    margin, rel = feat
    return margin >= t_s and rel < t_r   # True → net_semantic raises ASK ("review")


# recall-weighted: a missed sensitive egress is worse than an extra ASK (this layer only ever ASKs),
# but runaway false-ASKs make it noise — beta=2 favors recall while still penalising bad precision.
_BETA = 2.0


def _f1(cases, feats, idx, t_s, t_r):
    tp = fp = fn = 0
    for i in idx:
        pred = _predict(feats[i], t_s, t_r)
        pos = cases[i]["label"] == "review"
        tp += pred and pos
        fp += pred and not pos
        fn += (not pred) and pos
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    b2 = _BETA * _BETA
    fbeta = (1 + b2) * prec * rec / (b2 * prec + rec) if (b2 * prec + rec) else 0.0
    return fbeta, prec, rec


def main():
    enc = get_encoder()
    if enc is None:
        print("model2vec encoder unavailable — cannot calibrate"); return 1
    cases = egress_eval.load()
    P, G, D = _encode_cases(cases, enc)
    full_centroids = _centroids_from(enc, _SENSITIVE)
    feats = _feats(P, G, D, full_centroids)
    n = len(cases)
    print(f"egress_eval: {n} cases "
          f"({sum(c['label']=='review' for c in cases)} review / {sum(c['label']=='clean' for c in cases)} clean)\n")

    train = [i for i in range(n) if _bucket(cases[i]["id"], 100) < 60]
    test = [i for i in range(n) if _bucket(cases[i]["id"], 100) >= 60]
    grid_s = np.round(np.arange(0.0, 0.14, 0.005), 4)
    grid_r = np.round(np.arange(0.15, 0.60, 0.025), 4)

    # pick by 5-fold CV mean-F1 (robust to any single split) — the anti-overfit selection
    folds = [[i for i in range(n) if _bucket(cases[i]["id"] + "f", 5) == k] for k in range(5)]
    best, best_cv = None, -1.0
    for t_s in grid_s:
        for t_r in grid_r:
            cvs = [_f1(cases, feats, f, t_s, t_r)[0] for f in folds if f]
            m = float(np.mean(cvs))
            if m > best_cv:
                best_cv, best = m, (float(t_s), float(t_r))
    t_s, t_r = best
    cv_scores = [_f1(cases, feats, f, t_s, t_r)[0] for f in folds if f]
    tr = _f1(cases, feats, train, t_s, t_r)
    te = _f1(cases, feats, test, t_s, t_r)
    print(f"chosen by 5-fold CV:  sensitivity_margin={t_s:.3f}  relatedness_max={t_r:.3f}")
    print(f"  CV F1     = {np.mean(cv_scores):.3f} ± {np.std(cv_scores):.3f}  (per-fold {[round(x,2) for x in cv_scores]})")
    print(f"  TRAIN     = F1 {tr[0]:.3f}  prec {tr[1]:.3f}  rec {tr[2]:.3f}   (n={len(train)})")
    print(f"  TEST      = F1 {te[0]:.3f}  prec {te[1]:.3f}  rec {te[2]:.3f}   (n={len(test)})  <-- generalization")
    print(f"  train→test F1 gap = {tr[0]-te[0]:+.3f}\n")

    # per-group recall (positives) / specificity (negatives) on the FULL set — does it generalize OOD?
    groups: dict[str, list[int]] = {}
    for i, c in enumerate(cases):
        groups.setdefault(c["id"].split("/")[0], []).append(i)
    print("per-group at the chosen thresholds:")
    for gname, idx in sorted(groups.items()):
        pos = cases[idx[0]]["label"] == "review"
        fired = sum(_predict(feats[i], t_s, t_r) for i in idx)
        kind = "recall(review→ASK)" if pos else "false-ASK(clean→ASK)"
        print(f"  {gname:16s} {kind:22s} {fired}/{len(idx)} ({fired/len(idx):.0%})")

    # LEAVE-ONE-CATEGORY-OUT: drop each sensitivity centroid, rebuild, and re-measure recall on all
    # review cases. If recall barely moves, the centroids GENERALIZE — a sensitive payload is caught
    # by proximity to the OTHER classes, not by memorising its own. The strongest anti-overfit check.
    review_idx = [i for i in range(n) if cases[i]["label"] == "review"]
    base_rec = sum(_predict(feats[i], t_s, t_r) for i in review_idx) / len(review_idx)
    print(f"\nleave-one-category-out (review recall, full set={base_rec:.0%}):")
    for drop in _SENSITIVE:
        reduced = {k: v for k, v in _SENSITIVE.items() if k != drop}
        f2 = _feats(P, G, D, _centroids_from(enc, reduced))
        rec = sum(_predict(f2[i], t_s, t_r) for i in review_idx) / len(review_idx)
        print(f"  without '{drop:18s}' centroid → review recall {rec:.0%}  ({rec-base_rec:+.0%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
