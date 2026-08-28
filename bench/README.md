# bench — ddbt safety benchmarks

Runs the **full ddbt stack (sift judge + plugins + grant)** over agent-safety benchmarks and tabulates.
`agentdojo`/`agentdyn` are handled **separately** (see `bench/agentdojo/`), not by this runner.

## Run
```bash
uv run python bench/run.py                # every available dataset, auto-fetch + tabulate
uv run python bench/run.py injecagent     # one dataset
```
`run.py` (1) fetches missing data, (2) replays each labelled tool-call sequence through the engine
with sift deciding and the plugins intercepting, (3) prints attack-stopped % (security) and
benign-clean % (utility).

## Datasets (`datasets.py` registry, `fetch.py` acquisition)

| dataset | mode | source | status |
|---|---|---|---|
| **injecagent** | replay | vendored (`data/injecagent`, gitignored) | ✅ runs |
| **agenttrust** | replay | arXiv:2605.04785 (300+630) | ⏳ drop JSON in `data/agenttrust/` |
| **toolemu** | replay | github.com/ryoungj/ToolEmu (144) | ⏳ auto-fetch + best-effort adapter |
| **agentsafetybench** | replay | github.com/thu-coai/Agent-SafetyBench (349) | ⏳ auto-fetch + best-effort adapter |
| **rjudge / mcptox** | classify | vendored | scored by `sift/bench_bakeoff.py` (judge classification) |

⏳ = fetch scaffolding is in place; the scenario-based sets (ToolEmu, Agent-SafetyBench) need a small
adapter to extract their ground-truth risky tool calls — the loaders skip cleanly until then. To add a
source, edit `fetch.py`; to add a schema adapter, edit `datasets.py`.

## Layout
```
bench/
  run.py          the sift+plugins runner + auto-tabulation
  datasets.py     dataset registry (load → replay Cases)
  fetch.py        auto-download into data/
  static_replay.py  Case + injecagent/agentdojo loaders (replay engine)
  rjudge.py mcptox.py measure_injecagent.py   dataset loaders / LLM classification
  run_all.py      the older LLM-classification runner (rjudge/injecagent/mcptox)
  agentdojo/      agentdojo harness — handled separately
  legacy/         one-off diagnostics (ab_*, diag_*)
  data/           the datasets
```
