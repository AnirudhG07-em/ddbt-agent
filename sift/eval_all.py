#!/usr/bin/env python
"""End-to-end decision demo for one method: raw score → calibrated prob → conformal DENY/ASK/ALLOW.

Where train_all.py ranks methods on raw scores, this shows the *deployed* pipeline on the winner:
fit → calibrate (Platt/isotonic) → conformal bands → report the DENY/ASK/ALLOW split, coverage, and
how many exfil attacks the deterministic hard-rule catches before the model is even consulted.

    uv run --no-project --with numpy --with scikit-learn python eval_all.py --method fusion --encoder hashing
"""

from __future__ import annotations

import argparse

import numpy as np

from sift.data import synth
from sift.data.dataset import to_dataset
from sift.eval import calibrate, metrics
from sift.features import structural
from sift.methods import build_all


def _split(records, frac, seed=0):
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(records))
    cut = int(len(records) * frac)
    return [records[i] for i in idx[cut:]], [records[i] for i in idx[:cut]]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--method", default="fusion")
    ap.add_argument("--encoder", default="model2vec", choices=["model2vec", "minilm", "hashing"])
    ap.add_argument("--target-fpr", type=float, default=0.05)
    args = ap.parse_args(argv)

    train_r, _indist_r, shift_r = synth.build(seed=0)
    # carve a calibration set out of train (never calibrate on the fit set)
    fit_r, cal_r = _split(train_r, 0.25)
    fit, cal, shift = to_dataset(fit_r), to_dataset(cal_r), to_dataset(shift_r)

    method = next((m for m in build_all(args.encoder) if m.name == args.method), None)
    if method is None or not method.available():
        raise SystemExit(f"method {args.method} unavailable")
    method.fit(fit)

    # calibrate on held-out cal set, then set conformal bands from calibrated benign scores
    raw_cal = method.predict_proba(cal)
    cal_model = calibrate.fit_calibrator(raw_cal, cal.y)
    p_cal = cal_model.transform(raw_cal)
    bands = calibrate.conformal_bands(p_cal, cal.y, target_fpr=args.target_fpr)

    # deploy on the shift regime
    p_shift = cal_model.transform(method.predict_proba(shift))
    decisions = np.array([bands.decide(p) for p in p_shift])

    # hard exfil rule interception (deterministic, before the model)
    hard = np.array([structural.hard_exfil_rule(
        structural.extract(r["tool"],
                           r["args"] if isinstance(r["args"], str) else str(r["args"]),
                           sink_provenance=r.get("sink_provenance", "unknown"),
                           trusted_domains=("acme.com",)))
        for r in shift_r])

    print(f"=== sift deployed: method={args.method} encoder={args.encoder} "
          f"target_fpr={args.target_fpr} ===")
    print(f"calibration: {cal_model.kind}   bands: τ_deny={bands.tau_deny:.3f} τ_ask={bands.tau_ask:.3f}")
    print(metrics.summary(shift.y, p_shift))
    for d in ("DENY", "ASK", "ALLOW"):
        mask = decisions == d
        n = int(mask.sum())
        bad = int(shift.y[mask].sum())
        print(f"  {d:5s}: {n:4d}  ({bad} bad / {n - bad} benign)")
    cov, err = metrics.coverage_risk(shift.y, p_shift, bands.tau_deny, bands.tau_ask, bands.tau_deny)
    print(f"  coverage (auto-decided) = {cov:.2f}   error on decided = {err:.3f}")
    print(f"  hard exfil-rule caught {int(hard.sum())} actions "
          f"({int((hard & (shift.y == 1)).sum())} true attacks) before the model ran")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
