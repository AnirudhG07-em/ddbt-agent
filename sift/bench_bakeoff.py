#!/usr/bin/env python
"""Run the sift bake-off on the REAL benchmarks: R-Judge, InjecAgent, MCPTox.

For each benchmark: stratified train/test split, plus a SHIFT test built by paraphrasing +
encoding the held-out attacks (same evasion classes the literature says break semantic detectors —
arXiv:2504.11168). Every method is trained + scored; a per-benchmark leaderboard is printed and the
whole thing saved to JSON. sift's numbers sit next to ddbt's LLM-judge results for the same sets
(R-Judge F1 91.5%, InjecAgent 100%, MCPTox 99.8%).

    uv run --no-project --with numpy --with scikit-learn python bench_bakeoff.py --encoder hashing
    ./run_benches.sh                      # all encoders/deps, one command
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from sift.data import benches, synth
from sift.data.dataset import to_dataset
from sift.eval import metrics
from sift.methods import build_all

INCLUDE_SLOW = False  # set by --slow; SetFit is excluded by default (slow CPU fine-tune)


def _augment_shift(records: list[dict], rng: np.random.Generator) -> list[dict]:
    """Build the adversarial regime with the stronger `harden()` augmentation: attacks get
    paraphrase + benign-framing + encoding; benign gets occasional surface noise so 'clean surface ⇒
    benign' isn't a free shortcut. Handles both pre-rendered `text` records and structured `args`."""
    import random
    r = random.Random(int(rng.integers(1 << 30)))
    out = []
    for rec in records:
        rec = dict(rec)
        is_attack = rec.get("label") == 1
        if rec.get("text") is not None:
            rec["text"] = synth.harden(str(rec["text"]), r, is_attack)
        else:
            a = rec.get("args")
            if isinstance(a, dict):
                rec["args"] = {k: (synth.harden(v, r, is_attack) if isinstance(v, str) else v)
                               for k, v in a.items()}
            elif isinstance(a, str):
                rec["args"] = synth.harden(a, r, is_attack)
        out.append(rec)
    return out


def _split(records, test_frac=0.3, seed=0):
    rng = np.random.default_rng(seed)
    y = np.array([r["label"] for r in records])
    tr, te = [], []
    for cls in (0, 1):  # stratify
        idx = np.where(y == cls)[0]
        rng.shuffle(idx)
        cut = int(len(idx) * test_frac)
        te += [records[i] for i in idx[:cut]]
        tr += [records[i] for i in idx[cut:]]
    rng.shuffle(tr)
    rng.shuffle(te)
    return tr, te


def run_benchmark(name: str, records: list[dict], encoder: str, seed: int, verbose=True) -> dict:
    y = np.array([r["label"] for r in records])
    if len(set(y.tolist())) < 2:
        return {"skipped": "only one class present"}
    train_r, test_r = _split(records, seed=seed)
    shift_r = _augment_shift(test_r, np.random.default_rng(seed + 1))
    train, test, shift = to_dataset(train_r), to_dataset(test_r), to_dataset(shift_r)
    if verbose:
        print(f"\n#### {name}: n={len(records)} (bad={int(y.sum())}/benign={int((1-y).sum())}) "
              f"train={len(train)} test={len(test)}")

    out = {"n": len(records), "n_bad": int(y.sum()), "methods": {}}
    for m in build_all(encoder, include_slow=INCLUDE_SLOW):
        if not m.available():
            out["methods"][m.name] = {"skipped": True}
            continue
        if verbose:
            print(f"    {m.name:18s} … training", flush=True)
        try:
            m.fit(train)
            st = m.predict_proba(test)
            ss = m.predict_proba(shift)
        except Exception as exc:  # noqa: BLE001
            out["methods"][m.name] = {"error": f"{type(exc).__name__}: {exc}"}
            if verbose:
                print(f"    {m.name:18s} ERROR {type(exc).__name__}: {exc}")
            continue
        rec = {"citation": m.citation, "test": metrics.summary(test.y, st), "shift": metrics.summary(shift.y, ss)}
        out["methods"][m.name] = rec
        if verbose:
            print(f"    {m.name:18s} test F1={rec['test']['best_f1']:.2f} R@5%={rec['test']['recall@5%fpr']:.2f}"
                  f" AUPRC={rec['test']['auprc']:.2f} | SHIFT F1={rec['shift']['best_f1']:.2f}"
                  f" R@5%={rec['shift']['recall@5%fpr']:.2f}", flush=True)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="sift on the real benchmarks")
    ap.add_argument("--encoder", default="model2vec", choices=["model2vec", "minilm", "hashing"])
    ap.add_argument("--benchmarks", nargs="*",
                    default=["rjudge", "injecagent", "injecagent_prov", "mcptox"])
    ap.add_argument("--limit", type=int, default=None, help="cap records per benchmark (debug)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--slow", action="store_true", help="include SetFit (slow CPU fine-tune)")
    ap.add_argument("--out", default="reports/benches.json")
    args = ap.parse_args(argv)

    global INCLUDE_SLOW
    INCLUDE_SLOW = args.slow
    try:
        sys.stdout.reconfigure(line_buffering=True)  # live output even when piped to a file
    except Exception:
        pass
    print(f"=== sift on real benchmarks · encoder={args.encoder} "
          f"{'(+setfit)' if args.slow else '(6 methods; --slow adds setfit)'} ===")
    report = {"encoder": args.encoder, "seed": args.seed, "benchmarks": {}}
    for name in args.benchmarks:
        try:
            records = benches.LOADERS[name](limit=args.limit)
        except (FileNotFoundError, OSError) as exc:
            print(f"\n#### {name}: SKIPPED — data not found ({exc}). "
                  f"Pull bench/data/{name.split('_')[0]}/ into this checkout.", flush=True)
            report["benchmarks"][name] = {"skipped": f"data not found: {exc}"}
            continue
        report["benchmarks"][name] = run_benchmark(name, records, args.encoder, args.seed)

    # cross-benchmark summary: best-F1 method per set on the SHIFT regime
    print("\n=== summary (shift F1 by method × benchmark) ===")
    methods = sorted({m for b in report["benchmarks"].values()
                      for m in b.get("methods", {}) if "shift" in b["methods"][m]})
    header = "method".ljust(20) + "".join(n[:11].rjust(13) for n in args.benchmarks)
    print(header)
    for meth in methods:
        row = meth.ljust(20)
        for n in args.benchmarks:
            r = report["benchmarks"][n].get("methods", {}).get(meth, {})
            row += (f"{r['shift']['best_f1']:.2f}".rjust(13)) if "shift" in r else "—".rjust(13)
        print(row)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"\n[sift] report → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
