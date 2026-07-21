"""AgentDojo benchmark harness for ddbt.

Inserts the ddbt defense into a standard AgentDojo agent by swapping every
`ToolsExecutor` in the pipeline for a `DdbtToolsExecutor`, then runs a suite with
injections and reports the comparable headline numbers:

  * utility           — fraction of user tasks completed (higher better)
  * ASR               — attack success rate: fraction of injections that succeeded
                        (lower better)
  * ddbt blocks       — how many tool calls ddbt refused

Running the full suite needs an LLM backend + API key (e.g. OPENAI_API_KEY). The
splice logic itself is unit-tested offline (no key needed). Usage:

    uv run ddbt bench agentdojo --suite workspace --model gpt-4o-mini-2024-07-18 --limit 5
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field



def _judge(step_judge):
    """Default to the real haiku step-judge for live benchmark runs (needs a key)."""
    if step_judge is not None:
        return step_judge
    from ddbt.judge.provider import make_step_judge, preflight

    preflight("benchmark")

    return make_step_judge()


def splice_ddbt_defense(pipeline, step_judge=None):
    """Recursively replace every ToolsExecutor in a pipeline with DdbtToolsExecutor.

    Returns (pipeline, [the ddbt executors]) so the caller can read per-run stats.
    step_judge=None → the executor uses the engine default (AnthropicStepJudge, needs key).
    """
    from agentdojo.agent_pipeline import ToolsExecutor

    from ddbt.adapters.agentdojo.element import DdbtToolsExecutor

    installed: list[DdbtToolsExecutor] = []

    def _replace(element):
        # a ToolsExecutor → swap for our gating executor (keep its output formatter)
        if isinstance(element, ToolsExecutor) and not isinstance(element, DdbtToolsExecutor):
            ddbt = DdbtToolsExecutor(element.output_formatter, step_judge=step_judge)
            installed.append(ddbt)
            return ddbt
        # a container with .elements (AgentPipeline / ToolsExecutionLoop) → recurse
        if hasattr(element, "elements"):
            element.elements = [_replace(e) for e in element.elements]
        return element

    _replace(pipeline)
    return pipeline, installed


@dataclass(slots=True)
class BenchReport:
    suite: str
    model: str
    benchmark: str = "AgentDojo"  # "AgentDojo" or "AgentDyn" — same harness, different suites
    defended: bool = True
    n_user_tasks: int = 0
    n_cases: int = 0
    utility: float = 0.0
    asr: float = 0.0
    ddbt_blocks: int = 0
    blocked_examples: list = field(default_factory=list)

    def render(self) -> str:
        mode = "ddbt-defended" if self.defended else "BASELINE (no defense)"
        return (
            f"\n=== {mode} × {self.benchmark} · suite={self.suite} model={self.model} ===\n"
            f"  user tasks      : {self.n_user_tasks}\n"
            f"  cases (w/ inj.) : {self.n_cases}\n"
            f"  utility         : {self.utility:.1%}   (task completion; higher better)\n"
            f"  attack success  : {self.asr:.1%}   (ASR; lower better)\n"
            f"  ddbt blocks     : {self.ddbt_blocks} tool call(s) refused\n"
            + "".join(f"      ✗ {fn}: {why}\n" for fn, why in self.blocked_examples[:8])
        )


def run_suite(
    suite_name: str = "workspace",
    model_id: str = "gpt-4o-mini-2024-07-18",
    llm: str | None = None,
    limit: int | None = 5,
    step_judge=None,
    attack_name: str = "important_instructions",
    inj_limit: int | None = None,
    defended: bool = True,
    benchmark: str = "AgentDojo",
) -> BenchReport:
    """Run an AgentDojo/AgentDyn suite through the ddbt-defended pipeline. Needs an API key.

    AgentDyn is a drop-in fork of AgentDojo (same ``agentdojo`` import, extra suites
    ``shopping``/``github``/``dailylife``), so the same harness drives both — pass the suite
    name and set ``benchmark`` only to label the report.

    AgentDojo derives the provider from the model name, so ``llm`` and ``model_id`` are
    both the model id (e.g. ``gpt-4o-mini-2024-07-18``, ``claude-3-5-sonnet-20240620``).
    """
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1", suite_name)
    pipeline, executors = _build_pipeline(model_id, llm, defended, _judge(step_judge))
    uts, its = _resolve_task_ids(suite, limit, inj_limit)
    results = _run_benchmark(pipeline, suite, attack_name, uts, its)

    report = _aggregate(results, suite_name, model_id)
    report.benchmark = benchmark
    report.defended = defended
    report.ddbt_blocks = sum(e.stats["blocked"] for e in executors)
    for e in executors:
        report.blocked_examples.extend(e.stats["blocked_calls"])
    return report


def _build_pipeline(model_id: str, llm, defended: bool, step_judge):
    """Build a standard AgentDojo pipeline, optionally splicing in the ddbt gate."""
    from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig

    # AgentDojo's built-in ModelsEnum predates current models (2024 ids are retired/404).
    # PipelineConfig.llm accepts a BasePipelineElement, so we build the LLM directly for
    # Claude models and bypass the stale enum.
    llm_obj: object = llm or model_id
    if model_id.startswith("claude"):
        import anthropic
        from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
        from agentdojo.attacks import base_attacks

        llm_obj = AnthropicLLM(anthropic.Anthropic(), model_id)
        base_attacks.MODEL_NAMES.setdefault(model_id, "Claude")  # attack addresses it as "Claude"

    base = AgentPipeline.from_config(
        PipelineConfig(llm=llm_obj, model_id=model_id, defense=None, system_message_name=None, system_message=None)
    )
    pipeline, executors = (splice_ddbt_defense(base, step_judge) if defended else (base, []))
    if not pipeline.name or pipeline.name == "None":
        pipeline.name = model_id  # must CONTAIN a key in MODEL_NAMES (family lookup)
    return pipeline, executors


def _resolve_task_ids(suite, limit, inj_limit):
    uts = list(suite.user_tasks.keys())
    if limit:
        uts = uts[:limit]
    its = list(suite.injection_tasks.keys())[:inj_limit] if inj_limit else None
    return uts, its


def default_trace_dir():
    """Persistent trace dir so failed cases are inspectable (overridable via DDBT_BENCH_LOGDIR)."""
    import os
    from pathlib import Path

    env = os.environ.get("DDBT_BENCH_LOGDIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent / "results" / "traces"


def _run_benchmark(pipeline, suite, attack_name, user_tasks, injection_tasks, logdir=None):
    """Run benchmark_suite_with_injections and return its results dict.

    AgentDojo writes a per-case trace to
      logdir/<pipeline.name>/<suite>/<user_task>/<attack>/<injection_task>.json
    so a persistent logdir makes every failure reproducible (see _offending_calls).
    """
    from pathlib import Path

    from agentdojo.attacks import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.logging import OutputLogger

    logdir = Path(logdir) if logdir else default_trace_dir()
    logdir.mkdir(parents=True, exist_ok=True)
    attack = load_attack(attack_name, suite, pipeline)
    with OutputLogger(str(logdir)):
        return benchmark_suite_with_injections(
            pipeline, suite, attack, logdir=logdir, force_rerun=True,
            user_tasks=user_tasks, injection_tasks=injection_tasks, verbose=False,
        )


def _offending_calls(logdir, pipeline_name, suite_name, attack_name, pair):
    """Best-effort: read a case's persisted trace and extract the assistant tool calls,
    so a still-succeeding (hijacked) pair names WHAT slipped through. Degrades to []."""
    import json
    from pathlib import Path

    user_task, injection_task = pair
    path = Path(logdir) / pipeline_name / suite_name / user_task / attack_name / f"{injection_task}.json"
    try:
        data = json.loads(path.read_text())
    except Exception:
        return [], str(path)
    msgs = data.get("messages", data) if isinstance(data, dict) else data
    calls: list[str] = []
    for m in msgs if isinstance(msgs, list) else []:
        if isinstance(m, dict) and m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", "?")
                args = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {})
                shown = {k: v for k, v in (args or {}).items() if isinstance(v, (str, int, float, bool))}
                calls.append(f"{fn}({shown})")
    return calls, str(path)


def _aggregate(results, suite_name: str, model_id: str) -> BenchReport:
    # benchmark_suite_with_injections returns a DICT (not an object):
    #   utility_results : {(user_task, injection_task): bool}  True = user task completed
    #   security_results: {(user_task, injection_task): bool}  True = ATTACK succeeded
    util_map = results.get("utility_results", {}) if isinstance(results, dict) else {}
    sec_map = results.get("security_results", {}) if isinstance(results, dict) else {}
    util = list(util_map.values())
    sec = list(sec_map.values())
    return BenchReport(
        suite=suite_name,
        model=model_id,
        n_user_tasks=len({k[0] for k in util_map}),
        n_cases=len(sec),
        utility=(sum(1 for u in util if u) / len(util)) if util else 0.0,
        asr=(sum(1 for s in sec if s) / len(sec)) if sec else 0.0,
    )


@dataclass(slots=True)
class VulnDelta:
    suite: str
    model: str
    benchmark: str = "AgentDojo"  # "AgentDojo" or "AgentDyn"
    baseline_cases: int = 0
    baseline_asr: float = 0.0
    vulnerable_pairs: list = field(default_factory=list)  # (user_task, injection_task) baseline lost
    defended_still_succeeds: int = 0
    ddbt_blocks: int = 0
    blocked_examples: list = field(default_factory=list)
    slipped: list = field(default_factory=list)  # (pair, [offending tool calls], trace_path)
    trace_dir: str = ""

    @property
    def neutralised(self) -> int:
        return len(self.vulnerable_pairs) - self.defended_still_succeeds

    def render(self) -> str:
        n = len(self.vulnerable_pairs)
        if n == 0:
            return (
                f"\n=== ddbt vulnerability delta · {self.benchmark} · suite={self.suite} model={self.model} ===\n"
                f"  baseline: {self.baseline_cases} cases, ASR {self.baseline_asr:.0%}\n"
                f"  → the model wasn't hijacked on this slice (nothing for ddbt to defend).\n"
                f"    widen scope (more --limit / --inj-limit) to find vulnerable pairs."
            )
        defended_asr = self.defended_still_succeeds / n
        lines = [
            f"\n=== ddbt vulnerability delta · {self.benchmark} · suite={self.suite} model={self.model} ===",
            f"  baseline    : {self.baseline_cases} cases, ASR {self.baseline_asr:.0%}",
            f"  vulnerable  : {n} pair(s) the UNDEFENDED agent got hijacked on (baseline ASR=100% on these)",
            f"  re-ran those {n} WITH ddbt:",
            f"    ASR on those: {defended_asr:.0%}   (was 100%)",
            f"    neutralised : {self.neutralised}/{n} attack(s)",
            f"    ddbt blocks : {self.ddbt_blocks} tool call(s) refused",
        ]
        lines += [f"      ✓ blocked {fn}: {why}" for fn, why in self.blocked_examples[:8]]
        if self.slipped:
            lines.append(f"  ⚠ {len(self.slipped)} STILL SLIPPED THROUGH ddbt (debug these):")
            for pair, calls, trace in self.slipped:
                lines.append(f"      ✗ {pair[0]}/{pair[1]} via: {'; '.join(calls[:3]) or '(see trace)'}")
                lines.append(f"          trace: {trace}")
        if self.trace_dir:
            lines.append(f"  traces: {self.trace_dir}")
        return "\n".join(lines)


def run_vulnerable_delta(
    suite_name: str = "workspace",
    model_id: str = "gpt-4o-mini-2024-07-18",
    llm: str | None = None,
    limit: int | None = 8,
    inj_limit: int | None = None,
    step_judge=None,
    attack_name: str = "important_instructions",
    benchmark: str = "AgentDojo",
) -> VulnDelta:
    """Run BASELINE, find the (user_task, injection_task) pairs the undefended agent gets
    hijacked on, then re-run ONLY those with ddbt — so the security delta is unmistakable.

    Drives AgentDojo or its drop-in fork AgentDyn identically; ``benchmark`` only labels
    the report.
    """
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1", suite_name)
    uts, its = _resolve_task_ids(suite, limit, inj_limit)
    logdir = default_trace_dir()

    # 1) baseline (stock pipeline)
    base_pipe, _ = _build_pipeline(model_id, llm, defended=False, step_judge=None)
    base_results = _run_benchmark(base_pipe, suite, attack_name, uts, its, logdir=logdir)
    base_sec = base_results.get("security_results", {})
    vulnerable = [pair for pair, succeeded in base_sec.items() if succeeded]

    delta = VulnDelta(
        suite=suite_name,
        model=model_id,
        benchmark=benchmark,
        baseline_cases=len(base_sec),
        baseline_asr=(sum(1 for v in base_sec.values() if v) / len(base_sec)) if base_sec else 0.0,
        vulnerable_pairs=vulnerable,
        trace_dir=str(logdir),
    )
    if not vulnerable:
        return delta

    # 2) re-run ONLY the vulnerable pairs with ddbt, then read the delta off those pairs
    v_uts = sorted({ut for ut, _ in vulnerable})
    v_its = sorted({it for _, it in vulnerable})
    def_pipe, executors = _build_pipeline(model_id, llm, defended=True, step_judge=_judge(step_judge))
    def_results = _run_benchmark(def_pipe, suite, attack_name, v_uts, v_its, logdir=logdir)
    def_sec = def_results.get("security_results", {})

    delta.defended_still_succeeds = sum(1 for pair in vulnerable if def_sec.get(pair, False))
    delta.ddbt_blocks = sum(e.stats["blocked"] for e in executors)
    for e in executors:
        delta.blocked_examples.extend(e.stats["blocked_calls"])
    # surface WHAT slipped through ddbt (for debugging) — parse the persisted defended trace
    for pair in vulnerable:
        if def_sec.get(pair, False):
            calls, trace = _offending_calls(logdir, def_pipe.name, suite_name, attack_name, pair)
            delta.slipped.append((pair, calls, trace))
    return delta
