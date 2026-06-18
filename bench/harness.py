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

from ddbt.policy.defaults import Policy, default_policy


def splice_ddbt_defense(pipeline, policy: Policy | None = None):
    """Recursively replace every ToolsExecutor in a pipeline with DdbtToolsExecutor.

    Returns (pipeline, [the ddbt executors]) so the caller can read per-run stats.
    """
    from agentdojo.agent_pipeline import ToolsExecutor

    from ddbt.adapters.agentdojo.element import DdbtToolsExecutor

    policy = policy or default_policy()
    installed: list[DdbtToolsExecutor] = []

    def _replace(element):
        # a ToolsExecutor → swap for our gating executor (keep its output formatter)
        if isinstance(element, ToolsExecutor) and not isinstance(element, DdbtToolsExecutor):
            ddbt = DdbtToolsExecutor(element.output_formatter, policy=policy)
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
    n_user_tasks: int = 0
    n_cases: int = 0
    utility: float = 0.0
    asr: float = 0.0
    ddbt_blocks: int = 0
    blocked_examples: list = field(default_factory=list)

    def render(self) -> str:
        return (
            f"\n=== ddbt × AgentDojo · suite={self.suite} model={self.model} ===\n"
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
    policy: Policy | None = None,
) -> BenchReport:
    """Run an AgentDojo suite through the ddbt-defended pipeline. Needs an API key.

    AgentDojo derives the provider from the model name, so ``llm`` and ``model_id`` are
    both the model id (e.g. ``gpt-4o-mini-2024-07-18``, ``claude-3-5-sonnet-20240620``).
    """
    from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.task_suite.load_suites import get_suite

    base = AgentPipeline.from_config(
        PipelineConfig(
            llm=llm or model_id,
            model_id=model_id,
            defense=None,
            system_message_name=None,
            system_message=None,
        )
    )
    pipeline, executors = splice_ddbt_defense(base, policy)
    pipeline.name = f"ddbt-{model_id}"

    suite = get_suite("v1", suite_name)
    user_tasks = list(suite.user_tasks.values())
    if limit:
        user_tasks = user_tasks[:limit]

    results = benchmark_suite_with_injections(
        pipeline, suite, user_tasks=user_tasks, injection_tasks=None, attacks=["important_instructions"]
    )
    report = _aggregate(results, suite_name, model_id)
    report.ddbt_blocks = sum(e.stats["blocked"] for e in executors)
    for e in executors:
        report.blocked_examples.extend(e.stats["blocked_calls"])
    return report


def _aggregate(results, suite_name: str, model_id: str) -> BenchReport:
    util = list(getattr(results, "utility_results", {}).values())
    sec = list(getattr(results, "security_results", {}).values())
    return BenchReport(
        suite=suite_name,
        model=model_id,
        n_user_tasks=len({k[0] for k in getattr(results, "utility_results", {})}),
        n_cases=len(sec),
        utility=(sum(1 for u in util if u) / len(util)) if util else 0.0,
        # security_results True == attack succeeded → ASR is the mean of True
        asr=(sum(1 for s in sec if s) / len(sec)) if sec else 0.0,
    )
