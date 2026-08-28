"""Bring benchmark datasets into bench/data/ if they're not already there.

Each fetcher is best-effort and idempotent: it returns True if the data is present after running,
False if it couldn't be obtained (network, moved layout, or no public URL yet) — the runner then
skips that dataset with a note rather than failing. agentdojo/agentdyn are intentionally NOT here;
they're handled separately.

Sources:
  rjudge / injecagent / mcptox — already vendored in bench/data (injecagent is gitignored/local).
  toolemu           — github.com/ryoungj/ToolEmu  (assets/all_cases.json, 144 cases)
  agentsafetybench  — github.com/thu-coai/Agent-SafetyBench (349 scenarios; also on HuggingFace)
  agenttrust        — arXiv:2605.04785; 300+630 scenarios. No verified public URL yet → documented, skipped.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"


def _download(url: str, dest: Path, timeout: int = 30) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ddbt-bench"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
        dest.write_bytes(data)
        return dest.stat().st_size > 0
    except (urllib.error.URLError, OSError, ValueError):
        return False


def have(name: str) -> bool:
    d = DATA / name
    return d.is_dir() and any(d.iterdir())


# ---- per-dataset fetchers (return True if present after) ----

def fetch_toolemu() -> bool:
    if have("toolemu"):
        return True
    base = "https://raw.githubusercontent.com/ryoungj/ToolEmu/main/assets/"
    ok = _download(base + "all_cases.json", DATA / "toolemu" / "all_cases.json")
    _download(base + "all_toolkits.json", DATA / "toolemu" / "all_toolkits.json")  # best-effort
    return ok or have("toolemu")


def fetch_agentsafetybench() -> bool:
    if have("agentsafetybench"):
        return True
    url = "https://raw.githubusercontent.com/thu-coai/Agent-SafetyBench/main/data/released_data.json"
    if _download(url, DATA / "agentsafetybench" / "released_data.json"):
        return True
    return have("agentsafetybench")


def fetch_agenttrust() -> bool:
    # No verified public download for the 300+630 corpus at time of writing (arXiv:2605.04785).
    # Drop the JSON into bench/data/agenttrust/ manually and the runner will pick it up.
    return have("agenttrust")


FETCHERS = {
    "toolemu": fetch_toolemu,
    "agentsafetybench": fetch_agentsafetybench,
    "agenttrust": fetch_agenttrust,
    # rjudge/injecagent/mcptox are vendored — presence is checked directly, no fetch.
}


def ensure(name: str) -> bool:
    """Ensure dataset `name` is present, fetching if a fetcher exists. Returns presence."""
    if have(name):
        return True
    f = FETCHERS.get(name)
    return bool(f and f())
