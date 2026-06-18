"""Claude Code hook adapter (v4): stdin-JSON → engine(step-judge) → response/exit-code.
The real adapter builds an Anthropic judge; tests monkeypatch _engine to inject a stub."""

from __future__ import annotations

import json

import pytest

from ddbt.adapters.claude_code import hook
from ddbt.core.engine import Engine
from ddbt.judge.stub import ScriptedStepJudge


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
