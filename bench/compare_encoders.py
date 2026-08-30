"""Compare sift encoder backbones on the security benchmarks — run on a fast machine.

Trains a sift head on each candidate static encoder (if its artifact is missing), then benchmarks every
one on the same datasets the scorecard uses, and prints a side-by-side table. Purpose: pick the best
torch-free static embedder for sift (and the "sift-mini" low-footprint option).

Candidates (all Model2Vec / potion — the torch-free static class; see notes at bottom):
    32M            minishlab/potion-base-32M       (current default; general-MTEB leader)
    8M             minishlab/potion-base-8M        (mini, general)
    code-16M       minishlab/potion-code-16M       (code-domain — matches shell/tool-call inputs)
    retrieval-32M  minishlab/potion-retrieval-32M  (retrieval/similarity-tuned)

Usage:
    uv run python bench/compare_encoders.py                 # FULL datasets (default)
    uv run python bench/compare_encoders.py --limit 200     # cap 200/dataset (fast survey)
    uv run python bench/compare_encoders.py --only 32M,code-16M
    uv run python bench/compare_encoders.py --retrain       # force retrain even if artifacts exist

Notes / gotchas baked in:
  * Runs single-threaded per-predict via sift.serve (OMP pinned) — that alone is ~30x faster than the
    default 8-thread pool on single-row inference, so a "fast machine" mostly means more cores for the
    parallel dataset loops here + faster training.
  * Each model's head is trained with train_sift.py in a subprocess (clean encoder isolation + the
    fail-loud guard against a silent encoder fallback).
  * Writes bench/reports/encoder_comparison.json.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
for p in (str(HERE), str(ROOT / "src"), str(ROOT / "sift")):
    sys.path.insert(0, p)

# label -> (train_sift --encoder name, artifact filename under sift/models/)
CANDIDATES = {
    "32M": ("model2vec", "sift_judge.joblib"),
    "8M": ("model2vec-8m", "sift_judge_8m.joblib"),
    "code-16M": ("model2vec-code", "sift_judge_code16m.joblib"),
    "retrieval-32M": ("model2vec-retrieval", "sift_judge_retr32m.joblib"),
}
MODELS_DIR = ROOT / "sift" / "models"


def ensure_trained(label: str, encoder: str, artifact: pathlib.Path, retrain: bool) -> bool:
    if artifact.is_file() and not retrain:
        return True
    print(f"[train] {label}: {encoder} → {artifact.name} …", flush=True)
    t = time.time()
    rc = subprocess.call(
        [sys.executable, str(ROOT / "sift" / "train_sift.py"), "--encoder", encoder, "--out", str(artifact)],
        cwd=str(ROOT), env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "sift")},
    )
    if rc != 0:
        print(f"[train] {label} FAILED (rc={rc}) — skipping", flush=True)
        return False
    print(f"[train] {label} done ({time.time() - t:.0f}s)", flush=True)
    return True


def benchmark(artifact: pathlib.Path, limit: int) -> dict:
    import numpy as np
    import datasets
    import fetch
    import run
    from sift.serve import SiftScorer
    from sift.data import benches
    from sift.data.dataset import to_dataset
    from ddbt.judge.sift_judge import SiftJudge
    from sklearn.metrics import f1_score, roc_auc_score, precision_recall_curve

    sc = SiftScorer(str(artifact))
    judge = SiftJudge(sc)
    out: dict = {}

    # R-Judge: held-out classification (F1 / AUROC) — the LLM-comparable metric
    recs = benches.load_rjudge(split="test", limit=limit)
    ds = to_dataset(recs)
    cal = sc.calibrator.transform(sc.model.clf.predict_proba(np.hstack([sc.model.enc.encode(ds.texts), ds.struct]))[:, 1])
    y = ds.y
    p, r, thr = precision_recall_curve(y, cal)
    f1s = np.divide(2 * p * r, p + r, out=np.zeros_like(p), where=(p + r) > 0)
    t = float(thr[int(np.argmax(f1s[:-1]))]) if len(thr) else 0.5
    out["rjudge"] = {"f1": round(float(f1_score(y, (cal >= t).astype(int))), 3),
                     "auroc": round(float(roc_auc_score(y, cal)), 3), "n": int(len(y))}

    # interception / recognition replays
    for name in ("injecagent", "agenttrust", "toolemu", "agentsafetybench"):
        entry = datasets.REGISTRY.get(name)
        if not entry:
            continue
        _mode, loader, needs_fetch = entry
        if needs_fetch and not fetch.ensure(name):
            continue
        cases = loader()
        if not cases:
            continue
        m = run._replay(cases, judge, None, limit=limit, label=name)
        out[name] = {"stopped": round(m["stopped"] / m["attacks"], 3) if m["attacks"] else None,
                     "clean": round(m["clean"] / m["benign"], 3) if m["benign"] else None,
                     "attacks": m["attacks"], "benign": m["benign"]}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="cap cases per dataset; 0 = full (default)")
    ap.add_argument("--full", action="store_true", help="(default) full datasets — kept for compatibility")
    ap.add_argument("--retrain", action="store_true")
    ap.add_argument("--only", default="", help="comma list of labels, e.g. 32M,code-16M")
    args = ap.parse_args(argv)
    limit = None if args.limit in (0, None) else args.limit

    labels = [x.strip() for x in args.only.split(",") if x.strip()] or list(CANDIDATES)
    results: dict = {}
    for label in labels:
        if label not in CANDIDATES:
            print(f"unknown label {label!r} (have: {', '.join(CANDIDATES)})"); continue
        encoder, fname = CANDIDATES[label]
        artifact = MODELS_DIR / fname
        if not ensure_trained(label, encoder, artifact, args.retrain):
            continue
        print(f"[bench] {label} …", flush=True)
        t = time.time()
        results[label] = benchmark(artifact, limit)
        results[label]["_seconds"] = round(time.time() - t, 1)
        print(f"[bench] {label} done ({time.time() - t:.0f}s)", flush=True)

    def cell(d, k):
        v = d.get(k)
        if not v:
            return "   -   "
        if k == "rjudge":
            return f"F1 {v['f1']:.2f} AUROC {v['auroc']:.2f}"
        return f"{(v['stopped'] or 0):4.0%}/{(v['clean'] or 0):4.0%}"

    print("\n" + "=" * 100)
    print(f"{'encoder':16} | {'R-Judge':17} | {'InjecAgent':11} | {'AgentTrust':11} | {'ToolEmu':11} | {'ASBench':11}")
    print("-" * 100)
    for label in labels:
        d = results.get(label)
        if not d:
            continue
        print(f"{label:16} | {cell(d,'rjudge'):17} | {cell(d,'injecagent'):11} | "
              f"{cell(d,'agenttrust'):11} | {cell(d,'toolemu'):11} | {cell(d,'agentsafetybench'):11}")
    print("=" * 100)
    print("replay cells = attacks-stopped / benign-clean.  Pick the best R-Judge F1 without losing "
          "InjecAgent clean; code-16M/8M also win on size.")

    rep = HERE / "reports" / "encoder_comparison.json"
    rep.parent.mkdir(parents=True, exist_ok=True)
    rep.write_text(json.dumps(results, indent=2))
    print(f"\n[compare] → {rep}")


if __name__ == "__main__":
    main()
