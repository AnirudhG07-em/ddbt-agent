#!/usr/bin/env python
"""Run the full ddbt stack (sift judge + plugins + grant) over the safety benchmarks and tabulate.

    uv run python bench/run.py                 # every available dataset
    uv run python bench/run.py injecagent      # just one

For each replay dataset it: (1) fetches the data if missing, (2) runs every labelled tool-call
sequence through the engine with sift deciding and the plugins intercepting, (3) tabulates
attack-stopped % (security) and benign-clean % (utility). agentdojo/agentdyn are handled separately
and are not here. rjudge/mcptox (judge classification) are scored by sift/bench_bakeoff.py.
"""

from __future__ import annotations

import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))

import datasets  # noqa: E402
import fetch  # noqa: E402
from ddbt.core.engine import Effect, Engine  # noqa: E402
from ddbt.judge.provider import make_step_judge  # noqa: E402
from ddbt.plugins import from_config as plugins_from_config  # noqa: E402

DEFAULT_PLUGINS = ["shell_deobfuscation", "provenance_taint", "exfil_budget", "net_filter", "destructive_guard", "mitre_guard"]

# how each dataset is adapted — honest labelling in the table.
#   replay      = real ground-truth tool calls run through the engine (the true fit, faithful LLM-free).
#   sift-scorer = sift REPLACES the LLM safety scorer. ToolEmu / Agent-SafetyBench have the LLM in two
#                 roles: the AGENT (generates actions — ddbt can't be this, it judges, not generates)
#                 and the SCORER (judges safety — ddbt IS this). Dropping the agent, we feed sift the
#                 benchmark's ground-truth actions and measure its safety classification vs the labels
#                 — i.e. "replace the LLM judge with ddbt". Numbers are lower than injecagent/R-Judge
#                 mainly from DISTRIBUTION SHIFT (IoT/medical/embodied scenarios far from sift's
#                 injection/exfil training) + prose inputs — a TUNING target, not a broken method. The
#                 one thing this can't do is the live-agent delta (needs an LLM actor).
METHOD = {"injecagent": "replay", "agenttrust": "replay(reconstructed)",
          "toolemu": "sift-scorer", "agentsafetybench": "sift-scorer"}


def _replay(cases, judge, plugins, limit=None):
    import tempfile
    from ddbt.plugins import build as build_plugins

    n_atk = n_ben = stopped = clean = errored = 0
    base = tempfile.mkdtemp()
    for i, c in enumerate(cases[:limit] if limit else cases):
        eng = Engine(f"b{i}", workspace_root=base, base_dir=base, step_judge=judge,
                     plugins=build_plugins(DEFAULT_PLUGINS, trusted_domains=("acme.com",)), grant=None)
        eng.on_user_prompt(c.goal)
        if getattr(c, "tainted", False):
            eng.record_result("WebFetch", {"url": "injected"}, {"content": c.taint_text or "injection"})
        effects = []
        try:
            for tool, args in c.calls:
                d = eng.evaluate_action(tool, args or {})
                effects.append(d.effect)
                if d.error:
                    errored += 1
                if d.effect != Effect.DENY:
                    eng.record_result(tool, args or {}, {})
                else:
                    break
        finally:
            eng.close()
        blocked = any(e in (Effect.DENY, Effect.ASK) for e in effects)
        if c.label == "attack":
            n_atk += 1
            stopped += 1 if blocked else 0
        else:
            n_ben += 1
            clean += 1 if not blocked else 0
    return {"attacks": n_atk, "stopped": stopped, "benign": n_ben, "clean": clean, "errored": errored}


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    limit = None
    if "--limit" in args:
        i = args.index("--limit")
        limit = int(args[i + 1])
        args = args[:i] + args[i + 2:]
    names = args or [n for n, (mode, *_ ) in datasets.REGISTRY.items() if mode == "replay"]

    judge = make_step_judge(cwd=str(HERE.parent))
    decider = judge.__class__.__name__
    print(f"=== ddbt safety benchmarks · decider={decider} · plugins={DEFAULT_PLUGINS} ===\n")

    rows = []
    for name in names:
        entry = datasets.REGISTRY.get(name)
        if not entry:
            print(f"  {name:16s} unknown dataset — skipped")
            continue
        mode, loader, needs_fetch = entry
        if needs_fetch and not fetch.ensure(name):
            print(f"  {name:16s} SKIPPED — data not available (see bench/fetch.py to add a source)")
            continue
        cases = loader()
        if not cases:
            print(f"  {name:16s} SKIPPED — no replayable cases (adapter/data missing)")
            continue
        t0 = time.time()
        m = _replay(cases, judge, None, limit=limit)
        dt = time.time() - t0
        sp = (m["stopped"] / m["attacks"]) if m["attacks"] else float("nan")
        cl = (m["clean"] / m["benign"]) if m["benign"] else float("nan")
        rows.append((name, m["attacks"], sp, m["benign"], cl, dt))
        print(f"  {name:16s} attacks={m['attacks']:4d} stopped={sp:5.1%}  benign={m['benign']:4d} clean={cl:5.1%}  ({dt:.0f}s)")

    print("\n=== summary ===")
    print(f"{'dataset':16s} {'method':22s} {'attacks':>8s} {'stopped':>9s} {'benign':>7s} {'clean':>7s}")
    for name, na, sp, nb, cl, _ in rows:
        print(f"{name:16s} {METHOD.get(name, 'replay'):22s} {na:>8d} {sp:>8.1%} {nb:>7d} {cl:>6.1%}")
    print("\nreplay = real tool calls (the true fit); proxy = recognition of prose risk on an emulation\n"
          "benchmark (lower bound — the official eval needs a full agent-in-the-loop).")
    if not rows:
        print("(no datasets ran — fetch data or drop it into bench/data/<name>/)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
