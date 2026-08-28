#!/usr/bin/env python
"""Train the deployable sift judge model and save it as a single artifact.

This is the model ddbt loads as its DEFAULT decider (the LLM becomes a flagged fallback). It trains
the `fusion` method (embedding ⊕ structural — the ensemble the evasion literature recommends,
arXiv:2504.11168) on the action-level data available in this checkout: the synthetic corpus always,
plus InjecAgent when its data is present. It then fits a calibrator and conformal DENY/ASK bands on a
held-out split, and joblib-dumps everything to models/sift_judge.joblib.

    uv run --no-project --with numpy --with scikit-learn --with "model2vec[train]" \
        --with sentence-transformers --with datasets python train_sift.py --encoder model2vec

HONEST NOTE: trained on synth + InjecAgent, this is a working PROTOTYPE judge. Production quality
needs distillation — running the existing LLM judge over a real action log to get multi-task labels
(see the roadmap in sift/data/synth.py). The plumbing is real; the model is only as good as its data.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np

from sift.data import benches, synth
from sift.data.dataset import to_dataset
from sift.eval import calibrate
from sift.methods.embed_heads import Prototypes
from sift.methods.fusion import Fusion


def _load_training_records():
    from sift.data import domains

    train_r, _, _ = synth.build(seed=0)
    records = list(train_r)
    used = ["synth"]
    for name in ("injecagent", "injecagent_dh"):
        try:
            records += benches.LOADERS[name]()
            used.append(name)
        except (FileNotFoundError, OSError):
            pass  # data not in this checkout → skip
    # NOTE: training on ToolEmu / Agent-SafetyBench was TESTED and DISABLED. Their safe/unsafe line is
    # too subtle for a static embedding — folding them in drives the model to flag EVERYTHING in those
    # domains (held-out recall 100% / specificity 0%; see eval_general.py). Those are agent-behaviour
    # sets scored by an LLM; a non-LLM embedding can't reproduce that judgment. The loaders remain in
    # sift.data.benches for experimentation. To try anyway (e.g. with a stronger encoder), re-enable:
    #     records += benches.load_toolemu_labeled(split="train")
    #     records += benches.load_agentsafetybench_labeled(split="train")

    # optional workspace domain packs (extensible; empty by default) — sift/data/domains/*.jsonl
    dom = domains.load(split="train")
    if dom:
        records += dom
        used += [f"domain:{d}" for d in domains.domains()]
    return records, used


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--encoder", default="model2vec", choices=["model2vec", "minilm", "hashing"])
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "models" / "sift_judge.joblib"))
    ap.add_argument("--target-fpr", type=float, default=0.05)
    args = ap.parse_args(argv)

    records, used = _load_training_records()
    rng = np.random.default_rng(0)
    idx = rng.permutation(len(records))
    cut = int(len(records) * 0.2)
    cal_r = [records[i] for i in idx[:cut]]
    fit_r = [records[i] for i in idx[cut:]]
    fit, cal = to_dataset(fit_r), to_dataset(cal_r)
    print(f"[train] {len(records)} records from {used}  (fit={len(fit)} cal={len(cal)})")

    model = Fusion(args.encoder).fit(fit)
    protos = Prototypes(args.encoder).fit(fit)   # for human-readable reasons at inference

    raw = model.predict_proba(cal)
    calib = calibrate.fit_calibrator(raw, cal.y)
    bands = calibrate.conformal_bands(calib.transform(raw), cal.y, target_fpr=args.target_fpr)
    print(f"[train] calibrator={calib.kind}  bands: tau_deny={bands.tau_deny:.3f} tau_ask={bands.tau_ask:.3f}")

    model._enc = None  # drop the (unpicklable) live encoder; it reloads by name on load
    protos._enc = None
    artifact = {
        "version": 1, "encoder": args.encoder, "method": "fusion",
        "model": model, "prototypes": protos, "calibrator": calib, "bands": bands,
        "trained_on": used,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, out)
    print(f"[train] saved → {out}  ({out.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
