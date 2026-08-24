"""ddbt.json — per-project config loading, precedence, and hook wiring."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ddbt.core import config


@pytest.fixture(autouse=True)
def _clear_cache():
    config._load_raw.cache_clear()
    yield
    config._load_raw.cache_clear()


def _write(d: Path, obj: dict) -> Path:
    (d / "ddbt.json").write_text(json.dumps(obj))
    config._load_raw.cache_clear()
    return d


def test_write_default_creates_and_never_clobbers(tmp_path):
    path, written = config.write_default(tmp_path)
    assert written and path.exists()
    data = json.loads(path.read_text())
    assert data["grant"] == ".ddbt/grant.json" and data["ddbd"] is True
    # a second call must not overwrite unless forced
    _, again = config.write_default(tmp_path)
    assert again is False


def test_missing_file_yields_defaults(tmp_path):
    c = config.load(tmp_path)
    assert c["ddbd"] is True and c["gate_offgoal"] is True and c["provider"] is None


def test_file_provides_values(tmp_path):
    _write(tmp_path, {"provider": "anthropic", "model": "claude-x", "ddbd": False})
    assert config.provider(tmp_path) == "anthropic"
    assert config.model(tmp_path) == "claude-x"
    assert config.engine_kwargs(tmp_path)["ddbd"] is False


def test_env_overrides_file(tmp_path, monkeypatch):
    _write(tmp_path, {"provider": "anthropic", "model": "claude-x"})
    monkeypatch.setenv("DDBT_PROVIDER", "gemini")
    monkeypatch.setenv("DDBT_MODEL", "gemini-x")  # alias for DDBT_JUDGE_MODEL
    assert config.provider(tmp_path) == "gemini"
    assert config.model(tmp_path) == "gemini-x"


def test_grant_spec_path_and_inline(tmp_path):
    _write(tmp_path, {"grant": ".ddbt/grant.json"})
    assert config.grant_spec(tmp_path) == ".ddbt/grant.json"
    _write(tmp_path, {"grant": {"tools": ["Read"]}})
    assert config.grant_spec(tmp_path) == {"tools": ["Read"]}


def test_hook_loads_inline_grant_from_ddbt_json(tmp_path):
    from ddbt.adapters.claude_code import hook

    _write(tmp_path, {"grant": {"tools": ["Read"], "deny_paths": ["**/*.pem"]}})
    grant = hook._load_grant(str(tmp_path))
    assert grant is not None
    # the inline grant is enforced: Bash is not in {Read}
    assert grant.check("Bash", {"command": "ls"}, now=0.0).effect == "deny"
    assert grant.check("Read", {"file_path": "a.txt"}, now=0.0).effect == "allow"
