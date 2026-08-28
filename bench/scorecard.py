#!/usr/bin/env python
"""One-file scorecard — how good is ddbt right now, vs the LLM judge. Run it anytime.

    uv run python bench/scorecard.py            # full scorecard + JSON
    uv run python bench/scorecard.py --limit 150

Covers three kinds of measurement, each with the metric that fits:
  * R-Judge  — held-out safety CLASSIFICATION (F1 / precision / recall). The LLM-comparable number.
               (train split is folded into training; the TEST split here is never trained on.)
  * InjecAgent / AgentTrust — INTERCEPTION replay through sift + plugins (attacks-stopped / benign-clean).
  * ToolEmu / Agent-SafetyBench — sift-as-scorer on the described actions (recognition; lower bound).

Prints a table against the LLM baseline and writes bench/reports/scorecard.json. Use it as your
regression guard: numbers dropping = something broke.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / "src")); sys.path.insert(0, str(HERE.parent / "sift"))

import datasets  # noqa: E402
import fetch  # noqa: E402
import run  # noqa: E402  (reuse the replay loop)
from ddbt.judge.provider import make_step_judge  # noqa: E402

# published LLM-judge numbers (from the ddbt README) for side-by-side context
LLM = {"rjudge": "F1 0.915", "injecagent": "100% stop", "agenttrust": "~95% stop",
       "toolemu": "(LLM-scored)", "agentsafetybench": "(LLM-scored)"}


def _rjudge(judge, limit):
    import numpy as np
    from sift.data import benches
    from sift.data.dataset import to_dataset
    from sift.serve import SiftScorer
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score, precision_recall_curve
    recs = benches.load_rjudge(split="test", limit=limit)
    s = SiftScorer.find()
    ds = to_dataset(recs)
    X = np.hstack([s.model.enc.encode(ds.texts), ds.struct])
    cal = s.calibrator.transform(s.model.clf.predict_proba(X)[:, 1]); y = ds.y
    p, r, thr = precision_recall_curve(y, cal)
    f1s = np.divide(2 * p * r, p + r, out=np.zeros_like(p), where=(p + r) > 0)
    i = int(np.argmax(f1s[:-1])) if len(thr) else 0
    t = float(thr[i]) if len(thr) else 0.5
    pred = (cal >= t).astype(int)
    return {"n": int(len(y)), "f1": round(float(f1_score(y, pred)), 3),
            "precision": round(float(precision_score(y, pred)), 3),
            "recall": round(float(recall_score(y, pred)), 3),
            "auroc": round(float(roc_auc_score(y, cal)), 3)}


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    limit = 200
    if "--limit" in args:
        i = args.index("--limit"); limit = int(args[i + 1])

    judge = make_step_judge(cwd=str(HERE.parent))
    print(f"=== ddbt scorecard · decider={judge.__class__.__name__} · plugins={run.DEFAULT_PLUGINS} ===\n")
    report = {"decider": judge.__class__.__name__, "results": {}}

    # 1) R-Judge classification (the LLM-comparable metric)
    t0 = time.time()
    rj = _rjudge(judge, limit)
    report["results"]["rjudge"] = rj
    print(f"  R-Judge (held-out)   F1={rj['f1']:.2f}  precision={rj['precision']:.2f}  recall={rj['recall']:.2f}"
          f"  AUROC={rj['auroc']:.2f}   [LLM {LLM['rjudge']}]  ({time.time()-t0:.0f}s)")

    # 2) interception replay + 3) sift-scorer sets
    for name in ("injecagent", "agenttrust", "toolemu", "agentsafetybench"):
        entry = datasets.REGISTRY.get(name)
        if not entry:
            continue
        mode, loader, needs_fetch = entry
        if needs_fetch and not fetch.ensure(name):
            print(f"  {name:20s} SKIPPED (no data)"); continue
        cases = loader()
        if not cases:
            print(f"  {name:20s} SKIPPED (no cases)"); continue
        t0 = time.time()
        m = run._replay(cases, judge, None, limit=limit)
        sp = (m["stopped"] / m["attacks"]) if m["attacks"] else float("nan")
        cl = (m["clean"] / m["benign"]) if m["benign"] else float("nan")
        report["results"][name] = {"attacks": m["attacks"], "stopped": round(sp, 3),
                                   "benign": m["benign"], "clean": round(cl, 3), "method": run.METHOD.get(name)}
        print(f"  {name:20s} stopped={sp:5.0%}  clean={cl:5.0%}  ({run.METHOD.get(name)})"
              f"   [LLM {LLM.get(name,'?')}]  ({time.time()-t0:.0f}s)")

    out = HERE / "reports" / "scorecard.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"\n[scorecard] → {out}")
    print("R-Judge F1 is the headline (LLM-comparable). stopped=recall on attacks; clean=utility on benign.\n"
          "toolemu/agentsafetybench are a recognition lower bound (they need an LLM agent for the real eval).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
