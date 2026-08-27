#!/usr/bin/env python
"""Per-query inference latency for the deployed path (encode → structural → head → decision).

Measures ONE action at a time (batch size 1), which is how a live gate runs — not the batched
throughput the training harness reports. Warms up, then times N single queries; reports mean / p50 /
p95 in milliseconds for each encoder × the fusion head.

    uv run --no-project --with numpy --with scikit-learn --with "model2vec[train]" \
        --with sentence-transformers --with datasets python bench_latency.py
"""

from __future__ import annotations

import time

import numpy as np

from sift.data import synth
from sift.data.dataset import to_dataset
from sift.methods.fusion import Fusion


def _pctls(ms):
    a = np.asarray(ms)
    return a.mean(), np.percentile(a, 50), np.percentile(a, 95)


def time_encoder(name: str, n: int = 200):
    train_r, _, test_r = synth.build(seed=0)
    train = to_dataset(train_r)
    one = to_dataset(test_r[:1])          # a single action record
    m = Fusion(name)
    t0 = time.time()
    m.fit(train)
    fit_s = time.time() - t0
    # warmup (first call loads/JITs)
    for _ in range(5):
        m.predict_proba(one)
    times = []
    for _ in range(n):
        t = time.perf_counter()
        m.predict_proba(one)              # full path: encode + structural + GBT + prob
        times.append((time.perf_counter() - t) * 1000.0)
    mean, p50, p95 = _pctls(times)
    enc = m.enc.name
    print(f"{name:12s} (encoder={enc:9s})  fit={fit_s:5.1f}s  "
          f"per-query: mean={mean:6.2f}ms  p50={p50:6.2f}ms  p95={p95:6.2f}ms")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--encoders", nargs="*", default=["hashing", "model2vec", "minilm"])
    ap.add_argument("--n", type=int, default=200)
    args = ap.parse_args(argv)
    print(f"=== sift per-query latency (batch=1, {args.n} queries, full fusion path) ===")
    for e in args.encoders:
        try:
            time_encoder(e, args.n)
        except Exception as exc:  # noqa: BLE001
            print(f"{e:12s} unavailable: {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
