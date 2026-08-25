"""One-shot bench runner: pick a suite, run it, print the report.

Usage:  uv run python bench/run_all.py <rjudge|injecagent|mcptox> [limit] [workers]

  uv run python bench/run_all.py mcptox              # all 485 descriptions
  uv run python bench/run_all.py injecagent 120 8    # 120 cases per split, 8 workers
  uv run python bench/run_all.py rjudge

The decider defaults to Gemini (`gemini-2.5-flash`); set `DDBT_PROVIDER=anthropic` or
`DDBT_JUDGE_MODEL=...` to change it. Keys are read from the environment or `.env`.

Every suite calls `preflight()` first, which prints the model that will decide and ABORTS
if no key is set. That guard is not decoration: both the judge and the scanner fail CLOSED,
so a missing key does not error out — it silently returns "blocked" for every case and
reports a perfect score. This runner previously asserted on ANTHROPIC_API_KEY specifically,
which is exactly the kind of provider-shaped assumption that guard replaces.

Each suite is bounded and foreground; run them one at a time (rate-limit discipline).
"""

from __future__ import annotations

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "src"))

from ddbt.judge.provider import preflight  # noqa: E402  (after sys.path setup)

DEFAULT_WORKERS = 8


def run_rjudge(limit, workers):
    import rjudge

    recs = rjudge.load_rjudge(str(HERE / "data" / "rjudge"), limit=limit)
    if not recs:
        sys.exit(f"no R-Judge records under {HERE / 'data' / 'rjudge'}")
    print(f"### R-Judge ({len(recs)} trajectories) ###")
    # default mapping: gate also counts as "stopped" (lenient/max-recall). ddbt off to
    # isolate axis-1 operational safety (matches how the headline number was measured).
    print(rjudge.score(recs, workers=workers, ddbt=False).render())


def run_injecagent(limit, workers):
    import static_replay as sr

    for name in ("ds_base", "dh_base"):
        path = HERE / "data" / "injecagent" / f"{name}.json"
        if not path.exists():
            print(f"(skipping {name}: {path} not found)")
            continue
        cases = sr.load_injecagent(str(path))
        if limit:
            cases = cases[:limit]
        print(f"\n### InjecAgent {name} ({len(cases)} cases) ###")
        print(sr.replay(cases, source=f"injecagent:{name}", workers=workers).render())


def run_mcptox(limit, workers):
    import mcptox

    # `limit` is the number of descriptions to scan; None means the whole set.
    mcptox.run(n_sem=limit or len(mcptox.load_poisons()), workers=workers, dump_missed=True)


SUITES = {"rjudge": run_rjudge, "injecagent": run_injecagent, "mcptox": run_mcptox}

if __name__ == "__main__":
    # a named suite runs ONLY that suite; "all" (or no argument) runs every one in turn.
    requested = sys.argv[1] if len(sys.argv) > 1 else "all"
    if requested == "all":
        chosen = list(SUITES)
    elif requested in SUITES:
        chosen = [requested]
    else:
        sys.exit(f"unknown suite {requested!r} — choose one of: {', '.join(SUITES)}, or 'all'")

    limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_WORKERS

    preflight("benchmark run")  # prints the decider, aborts if no key
    for suite in chosen:
        print(f"\n{'=' * 70}\nsuite: {suite}  limit: {limit or 'all'}  workers: {workers}\n{'=' * 70}")
        SUITES[suite](limit, workers)
