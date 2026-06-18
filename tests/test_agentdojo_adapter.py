"""AgentDojo adapter: tool-call gating + classifier (offline, no LLM).

We use a fake runtime so the test isolates ddbt's enforcement from AgentDojo's typed
function-binding. The contract we verify: an out-of-envelope sink (attacker recipient)
is blocked with an error and never executed; the task-named recipient executes.
"""

from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from ddbt.adapters.agentdojo.classifier import classify_agentdojo, extract_identifiers
from ddbt.policy.classifier import ToolClass
from ddbt.policy.defaults import default_policy


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("DDBT_HOME", str(tmp_path / "ddbt-home"))


# ---- classifier ----

def test_identifier_extraction():
    ids = extract_identifiers("send to alice@corp.com and post to https://ci.example.com/x")
    assert "alice@corp.com" in ids and "ci.example.com" in ids


def test_sink_vs_read_classification():
    p = default_policy()
    assert classify_agentdojo("send_money", {"recipient": "x@y.com"}, p).is_outbound
    assert classify_agentdojo("send_email", {"to": "a@b.com"}, p).tool_class == ToolClass.ACTION
    assert classify_agentdojo("read_file", {"name": "notes"}, p).tool_class == ToolClass.TRUSTED_RETRIEVAL
    assert classify_agentdojo("get_webpage", {"url": "http://x"}, p).tool_class == ToolClass.UNTRUSTED_RETRIEVAL


# ---- element gating ----

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


def test_attacker_sink_blocked_legit_sink_allowed():
    from agentdojo.functions_runtime import EmptyEnv, FunctionCall

    from ddbt.adapters.agentdojo.element import DdbtToolsExecutor

    rt = _FakeRuntime(["send_money", "read_file"])
    legit = FunctionCall(function="send_money", args={"recipient": "alice@corp.com", "amount": 100}, id="1")
    attack = FunctionCall(function="send_money", args={"recipient": "attacker@evil.com", "amount": 100}, id="2")
    messages = [_assistant([legit, attack])]

    element = DdbtToolsExecutor()
    task = "Send 100 to alice@corp.com for the invoice"
    _, _, _, new_msgs, _ = element.query(task, rt, EmptyEnv(), messages)

    results = new_msgs[1:]  # the appended tool results
    by_id = {r["tool_call_id"]: r for r in results}
    assert by_id["1"]["error"] is None  # legit executed
    assert "ddbt blocked" in (by_id["2"]["error"] or "")  # attacker blocked
    assert ("send_money", {"recipient": "alice@corp.com", "amount": 100}) in rt.executed
    assert not any(args.get("recipient") == "attacker@evil.com" for _, args in rt.executed)
    assert element.stats["blocked"] == 1 and element.stats["allowed"] == 1


def test_splice_replaces_all_tools_executors():
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bench"))
    from agentdojo.agent_pipeline import AgentPipeline, ToolsExecutor
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
    from harness import splice_ddbt_defense

    from ddbt.adapters.agentdojo.element import DdbtToolsExecutor

    class _Dummy:
        name = "dummy"

    pipe = AgentPipeline([ToolsExecutor(), ToolsExecutionLoop([ToolsExecutor(), _Dummy()])])
    spliced, execs = splice_ddbt_defense(pipe)
    assert len(execs) == 2

    survivors = []

    def walk(e):
        if isinstance(e, ToolsExecutor) and not isinstance(e, DdbtToolsExecutor):
            survivors.append(e)
        for x in getattr(e, "elements", []):
            walk(x)

    walk(spliced)
    assert not survivors, "a stock ToolsExecutor survived the splice"


def test_read_tool_not_blocked():
    from agentdojo.functions_runtime import EmptyEnv, FunctionCall

    from ddbt.adapters.agentdojo.element import DdbtToolsExecutor

    rt = _FakeRuntime(["read_file"])
    fc = FunctionCall(function="read_file", args={"name": "notes.txt"}, id="1")
    element = DdbtToolsExecutor()
    _, _, _, new_msgs, _ = element.query("summarise notes.txt", rt, EmptyEnv(), [_assistant([fc])])
    assert new_msgs[1]["error"] is None
    assert ("read_file", {"name": "notes.txt"}) in rt.executed
