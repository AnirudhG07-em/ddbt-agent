#!/usr/bin/env python
"""Train + evaluate every sift method in one shot and write a JSON report.

    uv run python sift/train_all.py --encoder model2vec
    uv run python sift/train_all.py --encoder hashing        # offline, no downloads

Heavy methods (setfit, model2vec_trained) self-skip if their deps aren't installed. The encoder
self-degrades hashing←minilm←model2vec so a run never dies on a missing package.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sift.eval.harness import run


def main(argv=None):
    ap = argparse.ArgumentParser(description="sift bake-off: train + test all methods")
    ap.add_argument("--encoder", default="model2vec", choices=["model2vec", "minilm", "hashing"])
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="sift/reports/bakeoff.json")
    args = ap.parse_args(argv)

    report = run(encoder=args.encoder, seed=args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"\n[sift] report → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
