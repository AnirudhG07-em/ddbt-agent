"""Shared fixtures. Every test gets an isolated DDBT_HOME under tmp_path so the
SQLite session stores never collide or touch the real ~/.ddbt."""

from __future__ import annotations

import os

import pytest

from ddbt.core.engine import Engine
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
    """Factory: make_engine() → Engine seeded at a fresh in-tmp workspace."""
    workspaces = []

    def _make(session_id="t", workspace=None):
        ws = workspace or str(tmp_path / f"ws-{session_id}")
        os.makedirs(ws, exist_ok=True)
        workspaces.append(ws)
        eng = Engine(session_id, workspace_root=ws, base_dir=base_dir)
        eng.on_session_start("startup", ws)
        return eng, ws

    return _make
