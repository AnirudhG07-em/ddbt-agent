"""Run the whole bake-off: fit each available method, score both test regimes, report.

The in-distribution vs shift/adversarial split is the point — a method that only wins in-dist is a
trap ("When Benchmarks Lie" / evasion literature). We print both and rank by the shift number.
"""

from __future__ import annotations

import time

import numpy as np

from sift.data import synth
from sift.data.dataset import to_dataset
from sift.eval import metrics
from sift.methods import build_all


def run(encoder: str = "model2vec", seed: int = 0, verbose: bool = True) -> dict:
    train_r, indist_r, shift_r = synth.build(seed=seed)
    train, indist, shift = to_dataset(train_r), to_dataset(indist_r), to_dataset(shift_r)
    if verbose:
        print(f"[sift] encoder={encoder}  train={len(train)}  in-dist={len(indist)}  shift={len(shift)}")

    report = {"encoder": encoder, "seed": seed, "n_train": len(train), "methods": {}}
    for m in build_all(encoder):
        if not m.available():
            if verbose:
                print(f"  · {m.name:18s} SKIPPED (dependency not installed)")
            report["methods"][m.name] = {"skipped": True, "citation": m.citation}
            continue
        t0 = time.time()
        try:
            m.fit(train)
            si = m.predict_proba(indist)
            ss = m.predict_proba(shift)
        except Exception as exc:  # noqa: BLE001 — one method failing must not sink the run
            if verbose:
                print(f"  · {m.name:18s} ERROR: {type(exc).__name__}: {exc}")
            report["methods"][m.name] = {"error": f"{type(exc).__name__}: {exc}", "citation": m.citation}
            continue
        dt = time.time() - t0
        rec = {
            "citation": m.citation,
            "fit_predict_s": round(dt, 2),
            "in_dist": metrics.summary(indist.y, si),
            "shift": metrics.summary(shift.y, ss),
        }
        report["methods"][m.name] = rec
        if verbose:
            idi, sh = rec["in_dist"], rec["shift"]
            print(f"  · {m.name:18s} indist R@5%={idi['recall@5%fpr']:.2f} F1={idi['best_f1']:.2f}"
                  f" | SHIFT R@5%={sh['recall@5%fpr']:.2f} F1={sh['best_f1']:.2f} AUPRC={sh['auprc']:.2f}"
                  f"  ({dt:.1f}s)")

    if verbose:
        _leaderboard(report)
    return report


def _leaderboard(report: dict):
    rows = [(n, r["shift"]["recall@5%fpr"], r["shift"]["best_f1"], r["shift"]["auprc"])
            for n, r in report["methods"].items() if "shift" in r]
    rows.sort(key=lambda x: (x[1], x[3]), reverse=True)
    print("\n=== leaderboard (ranked by SHIFT recall@5%fpr, then AUPRC) ===")
    print(f"{'method':20s} {'shiftR@5%':>10s} {'shiftF1':>8s} {'shiftAUPRC':>11s}")
    for n, r5, f1, ap in rows:
        print(f"{n:20s} {r5:>10.2f} {f1:>8.2f} {ap:>11.2f}")
