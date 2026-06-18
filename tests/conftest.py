"""Shared fixtures. Each test gets an isolated DDBT_HOME and a deterministic stub judge
(the real step-judge needs an API key; CI uses scripted verdicts)."""

from __future__ import annotations

import os

import pytest

from ddbt.core.engine import Engine
from ddbt.judge.stub import ScriptedStepJudge
from ddbt.store.session import SessionStore


@pytest.fixture
def base_dir(tmp_path):
    return tmp_path / "sessions"


@pytest.fixture
def store(base_dir):
    s = SessionStore("test-session", base_dir=base_dir)
    yield s
    s.close()


@pytest.fixture
def make_engine(base_dir, tmp_path):
    """Factory: make_engine(judge=..., goal=...) → (Engine, workspace). Default judge allows."""

    def _make(session_id="t", workspace=None, judge=None, goal="do the task"):
        ws = workspace or str(tmp_path / f"ws-{session_id}")
        os.makedirs(ws, exist_ok=True)
        eng = Engine(session_id, workspace_root=ws, base_dir=base_dir, step_judge=judge or ScriptedStepJudge())
        eng.on_session_start("startup", ws)
        if goal:
            eng.on_user_prompt(goal)
        return eng, ws

    return _make
