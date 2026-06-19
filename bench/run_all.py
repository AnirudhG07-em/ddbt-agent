"""One-shot bench runner: loads .env, runs a named suite, prints the report.

Usage:  uv run python bench/run_all.py <rjudge|injecagent|mcptox> [limit]

Each suite is bounded and foreground; run them one at a time (rate-limit discipline).
"""

from __future__ import annotations

import pathlib
import sys

import dotenv

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
dotenv.load_dotenv(ROOT / ".env")

import os

assert os.environ.get("ANTHROPIC_API_KEY"), "ANTHROPIC_API_KEY not loaded from .env"


def run_rjudge(limit):
    import rjudge

    recs = rjudge.load_rjudge(str(HERE / "data" / "rjudge"), limit=limit)
    # default mapping: gate also counts as "stopped" (lenient/max-recall). ddbd off to
    # isolate axis-1 operational safety (matches how the headline number was measured).
    print(rjudge.score(recs, workers=4, ddbd=False).render())


def run_injecagent(limit):
    import static_replay as sr

    for name in ("ds_base", "dh_base"):
        path = HERE / "data" / "injecagent" / f"{name}.json"
        cases = sr.load_injecagent(str(path))
        if limit:
            cases = cases[:limit]
        print(f"\n### InjecAgent {name} ({len(cases)} cases) ###")
        print(sr.replay(cases, source="injecagent").render())


def run_mcptox(limit):
    import mcptox

    mcptox.main()


if __name__ == "__main__":
    suite = sys.argv[1] if len(sys.argv) > 1 else "rjudge"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
    {"rjudge": run_rjudge, "injecagent": run_injecagent, "mcptox": run_mcptox}[suite](limit)
