#!/usr/bin/env python
"""Distillation (recommendation #1): teach sift the LLM judge's PROSE-HARM judgment, offline.

The static sift model is perfect on injection (AUC 1.0) but at the static-embedding ceiling on
prose-harm (ToolEmu / Agent-SafetyBench AUC ~0.5) — it cannot tell a described harmful action from a
benign one, because that needs reasoning, not lexical/embedding features. The fix that keeps the
RUNTIME LLM-free: run the LLM judge OFFLINE over a corpus of actions, take its labels, and fold them
into sift's training set. The LLM's judgment is transferred into the static model; at deploy time no
LLM runs.

    uv run python sift/distill.py --source toolemu --limit 400 --provider gemini
    # → writes sift/data/distilled/<source>.jsonl  (records: {tool,args,goal,label,source})
    # then: PYTHONPATH=sift uv run python sift/train_sift.py   (train_sift folds distilled/*.jsonl in)

HONEST NOTES
  * This costs LLM calls (one per action) and time — it is an OFFLINE job, not the runtime.
  * Hold out a TEST split (train_sift already splits R-Judge; do the same for any distilled source)
    so the reported gain is real, not train-on-test.
  * Start with the sources where sift is weakest (toolemu, agentsafetybench). Injection is already
    saturated — distilling it adds little.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sift.data import benches


def _actions(source: str, limit: int | None):
    """Yield {tool,args,goal} actions to be labelled. We DROP the benchmark's own label — the whole
    point is to relabel with the LLM (and to be able to distill unlabelled real agent logs too)."""
    if source == "toolemu":
        recs = benches.load_toolemu_labeled()
    elif source == "agentsafetybench":
        recs = benches.load_agentsafetybench_labeled(limit=limit)
    else:
        raise SystemExit(f"unknown source '{source}' (add a loader in sift/data/benches.py)")
    for r in (recs[:limit] if limit else recs):
        yield {"tool": r.get("tool", "agent_action"),
               "args": r.get("args") if "text" not in r else r["text"],
               "goal": r.get("goal", "")}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--provider", default=None)
    ap.add_argument("--model", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    # the SAME LLM judge the runtime offers as a flagged fallback — reused here purely offline.
    from ddbt.judge.provider import make_step_judge, preflight
    if args.provider:
        import os
        os.environ["DDBT_PROVIDER"] = args.provider
    if args.model:
        import os
        os.environ["DDBT_MODEL"] = args.model
    preflight("distillation")
    judge = make_step_judge()

    from ddbt.judge.step_judge import StepFacts
    out_path = Path(args.out) if args.out else (Path(__file__).resolve().parent / "data" / "distilled" / f"{args.source}.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    n = kept = 0
    with out_path.open("w") as fh:
        for a in _actions(args.source, args.limit):
            n += 1
            facts = StepFacts(goal=a["goal"], tool=a["tool"], args=a["args"],
                              input_labels=[], quarantined=[], history=[])
            v = judge.judge(facts)
            if getattr(v, "error", False):
                continue  # a rate-limit / infra failure is not a label — skip, don't poison the set
            label = 1 if (v.harmful or v.deviation) else 0
            fh.write(json.dumps({**a, "label": label, "source": f"distill:{args.source}"}) + "\n")
            kept += 1
            if n % 25 == 0:
                print(f"  labelled {kept}/{n}…", flush=True)
    print(f"[distill] wrote {kept}/{n} labelled records → {out_path}")
    print("[distill] next: PYTHONPATH=sift uv run python sift/train_sift.py  (folds distilled/*.jsonl in)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
