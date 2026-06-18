"""Bounded InjecAgent measurement with the v4 step-judge (real haiku).

Usage: uv run python bench/measure_injecagent.py <ds|dh> <n_items>
Slices to the first n items (each yields 1 benign + 1 attack case) to bound cost, then
replays through the engine's LLM judge and prints block/clean rates. Needs ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import static_replay as sr  # noqa: E402


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else "dh"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 25
    path = str(_HERE / "data" / "injecagent" / f"{kind}_base.json")

    all_cases = sr.load_injecagent(path)
    # take the first n items' worth (benign+attack are interleaved per item)
    benign = [c for c in all_cases if c.label == "benign"][:n]
    attack = [c for c in all_cases if c.label == "attack"][:n]
    cases = benign + attack
    label = "data-stealing" if kind == "ds" else "direct-harm"
    print(f"measuring {len(cases)} cases ({len(attack)} attack + {len(benign)} benign) "
          f"from InjecAgent {label} with the v4 haiku judge...")

    rep = sr.replay(cases, source=f"injecagent-{kind} (v4 judge)")
    print(rep.render())


if __name__ == "__main__":
    main()
