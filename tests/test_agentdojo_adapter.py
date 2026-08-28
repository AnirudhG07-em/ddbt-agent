"""AgentDojo adapter (v4): the DdbtToolsExecutor gates each tool call through the engine's
step-judge. Offline — uses a scripted stub judge, no LLM."""

from __future__ import annotations

import pathlib
import sys

import pytest

pytest.importorskip("agentdojo")

from ddbt.judge.stub import ScriptedStepJudge


class _FakeFn:
    def __init__(self, name):
        self.name = name


class _FakeRuntime:
    def __init__(self, names):
        self.functions = {n: _FakeFn(n) for n in names}
        self.executed = []

    def run_function(self, env, name, args):
        self.executed.append((name, dict(args)))
        return f"ran {name}", None


def _assistant(tool_calls):
    return {"role": "assistant", "content": None, "tool_calls": tool_calls}


def test_judge_blocks_one_allows_another():
    from agentdojo.functions_runtime import EmptyEnv, FunctionCall

    from ddbt.adapters.agentdojo.element import DdbtToolsExecutor

    rt = _FakeRuntime(["send_money", "read_file"])
    legit = FunctionCall(function="read_file", args={"name": "notes"}, id="1")
    attack = FunctionCall(function="send_money", args={"to": "attacker"}, id="2")
    judge = ScriptedStepJudge({"send_money": "deny"}, default="allow")
    element = DdbtToolsExecutor(step_judge=judge)
    _, _, _, msgs, _ = element.query("read my notes", rt, EmptyEnv(), [_assistant([legit, attack])])

    by_id = {r["tool_call_id"]: r for r in msgs[1:]}
    assert by_id["1"]["error"] is None  # allowed → executed
    assert "ddbt blocked" in (by_id["2"]["error"] or "")  # denied
    assert ("read_file", {"name": "notes"}) in rt.executed
    assert not any(n == "send_money" for n, _ in rt.executed)
    assert element.stats["blocked"] == 1 and element.stats["allowed"] == 1


def test_splice_replaces_all_tools_executors():
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bench" / "agentdojo"))
    from agentdojo.agent_pipeline import AgentPipeline, ToolsExecutor
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
    from harness import splice_ddbt_defense

    from ddbt.adapters.agentdojo.element import DdbtToolsExecutor

    class _Dummy:
        name = "dummy"

    pipe = AgentPipeline([ToolsExecutor(), ToolsExecutionLoop([ToolsExecutor(), _Dummy()])])
    spliced, execs = splice_ddbt_defense(pipe, step_judge=ScriptedStepJudge())
    assert len(execs) == 2
    survivors = []

    def walk(e):
        if isinstance(e, ToolsExecutor) and not isinstance(e, DdbtToolsExecutor):
            survivors.append(e)
        for x in getattr(e, "elements", []):
            walk(x)

    walk(spliced)
    assert not survivors
