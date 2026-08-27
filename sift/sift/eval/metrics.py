"""Security-shaped metrics. Accuracy lies on imbalanced safety data, so we lead with recall at a
fixed low false-positive rate and cost-weighted risk.

  * recall_at_fpr — the operating metric for a gate: how many attacks caught while holding benign
    false-positives at, say, 1%/5%. A missed exfil is catastrophic; an over-eager ASK is cheap.
  * AUPRC — area under precision-recall, the right summary under class imbalance (Davis & Goadrich,
    ICML 2006).
  * expected_cost — folds a cost matrix (FN ≫ FP) into a single number so thresholds are chosen for
    the real asymmetry, not for symmetric error.
  * coverage_risk — the selective-prediction curve: error vs fraction auto-decided (Geifman &
    El-Yaniv, "Selective Classification", arXiv:1705.08500).
"""

from __future__ import annotations

import numpy as np


def _roc_points(y: np.ndarray, s: np.ndarray):
    order = np.argsort(-s)
    y = y[order]
    P, N = int(y.sum()), int((1 - y).sum())
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    tpr = tp / max(P, 1)
    fpr = fp / max(N, 1)
    return fpr, tpr


def recall_at_fpr(y: np.ndarray, s: np.ndarray, max_fpr: float = 0.05) -> float:
    fpr, tpr = _roc_points(y, s)
    ok = tpr[fpr <= max_fpr]
    return float(ok.max()) if ok.size else 0.0


def auprc(y: np.ndarray, s: np.ndarray) -> float:
    from sklearn.metrics import average_precision_score
    if y.sum() == 0 or y.sum() == len(y):
        return float("nan")
    return float(average_precision_score(y, s))


def auroc(y: np.ndarray, s: np.ndarray) -> float:
    from sklearn.metrics import roc_auc_score
    if y.sum() == 0 or y.sum() == len(y):
        return float("nan")
    return float(roc_auc_score(y, s))


def best_f1(y: np.ndarray, s: np.ndarray):
    from sklearn.metrics import precision_recall_curve, f1_score
    p, r, thr = precision_recall_curve(y, s)
    f1s = np.divide(2 * p * r, p + r, out=np.zeros_like(p), where=(p + r) > 0)
    i = int(np.argmax(f1s[:-1])) if len(thr) else 0
    t = float(thr[i]) if len(thr) else 0.5
    return float(f1_score(y, (s >= t).astype(int))), t


def expected_cost(y: np.ndarray, s: np.ndarray, thr: float, c_fn: float = 10.0, c_fp: float = 1.0) -> float:
    pred = (s >= thr).astype(int)
    fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    return (c_fn * fn + c_fp * fp) / len(y)


def coverage_risk(y: np.ndarray, s: np.ndarray, thr: float, abstain_lo: float, abstain_hi: float):
    """With an ASK band [lo,hi], report coverage (fraction auto-decided) and the error on those."""
    decided = (s < abstain_lo) | (s >= abstain_hi)
    if decided.sum() == 0:
        return 0.0, float("nan")
    pred = (s[decided] >= thr).astype(int)
    err = float((pred != y[decided]).mean())
    return float(decided.mean()), err


def specificity_at(y: np.ndarray, s: np.ndarray, thr: float) -> float:
    """True-negative rate at a threshold — the honest FP metric for imbalanced sets (e.g. MCPTox)."""
    neg = y == 0
    if neg.sum() == 0:
        return float("nan")
    tn = int(((s < thr) & neg).sum())
    return tn / int(neg.sum())


def summary(y: np.ndarray, s: np.ndarray) -> dict:
    f1, t = best_f1(y, s)
    spec = specificity_at(y, s, t)
    return {
        "recall@1%fpr": round(recall_at_fpr(y, s, 0.01), 3),
        "recall@5%fpr": round(recall_at_fpr(y, s, 0.05), 3),
        "auprc": round(auprc(y, s), 3),
        "auroc": round(auroc(y, s), 3),
        "best_f1": round(f1, 3),
        "f1_thr": round(t, 3),
        "specificity@f1thr": round(spec, 3),   # TN rate: 1 − false-positive rate
        "n_benign": int((y == 0).sum()),        # how many negatives the FP metric rests on
        "exp_cost@f1thr": round(expected_cost(y, s, t), 3),
    }
