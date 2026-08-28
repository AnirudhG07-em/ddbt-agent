"""ddbt integration adapters — Claude Code hook and AgentDojo executor.

The Claude Code hook maps stdin-JSON → engine(step-judge) → permission decision / exit code; the
AgentDojo DdbtToolsExecutor gates each tool call through the engine. Both run offline with a scripted
(no-API) stub judge. The AgentDojo tests skip automatically if the `agentdojo` package isn't installed.

Run:
  uv run pytest tests/test_adapters.py -q            # hook + agentdojo
  uv run pytest tests/test_adapters.py -k hook       # Claude Code hook only
  uv run pytest tests/test_adapters.py -k agentdojo  # agentdojo (needs the package)
  uv run pytest tests/test_adapters.py -k splice     # a single case
"""

from __future__ import annotations

from ddbt.adapters.claude_code import hook
from ddbt.core.engine import Engine
from ddbt.judge.stub import ScriptedStepJudge
import json
import pathlib
import pytest
import sys


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("DDBT_HOME", str(tmp_path / "ddbt-home"))


@pytest.fixture
def stub_engine(tmp_path, monkeypatch):
    """Patch hook._engine to build engines with a scripted (no-API) judge."""
    verdicts = {}

    def _factory(payload):
        e = Engine(
            payload.get("session_id", "s"),
            workspace_root=payload.get("cwd", str(tmp_path)),
            step_judge=ScriptedStepJudge(dict(verdicts), default="allow"),
        )
        return e

    monkeypatch.setattr(hook, "_engine", _factory)
    return verdicts  # tests mutate this to set per-tool verdicts


def _pre(tmp_path, tool, tool_input, session="a"):
    payload = {"session_id": session, "cwd": str(tmp_path), "tool_name": tool, "tool_input": tool_input}
    out = hook.handle_pretooluse(payload)
    return out.get("hookSpecificOutput", {}).get("permissionDecision")  # None == allow


def test_allow_maps_to_no_objection(stub_engine, tmp_path):
    assert _pre(tmp_path, "Read", {"file_path": "a.py"}) is None  # default allow → {} → exit 0


def test_deny_maps_to_deny(stub_engine, tmp_path):
    stub_engine["send_money"] = "deny"
    assert _pre(tmp_path, "send_money", {"to": "x"}) == "deny"


def test_gate_maps_to_ask(stub_engine, tmp_path):
    stub_engine["Bash"] = "gate"
    assert _pre(tmp_path, "Bash", {"command": "rm x"}) == "ask"


def test_configchange_holds_on_dangerous_config(tmp_path):
    # Boundary 0 is still deterministic (hashes/regex) — no judge needed
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://x.tld"}}))
    out = hook.handle_configchange({"session_id": "c", "cwd": str(proj)})
    assert out.get("_exit") == 2 and "HOLD" in out.get("_stderr", "")


def test_dispatch_unknown_event_is_noop():
    assert hook.dispatch("SomethingElse", "{}") == 0





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
    pytest.importorskip("agentdojo")
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
    pytest.importorskip("agentdojo")
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
