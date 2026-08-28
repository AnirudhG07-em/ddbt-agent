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
    # one file: the ticket is inline under "policy" (allow/deny per resource), plus "auth"
    assert data["ddbt"] is True
    assert isinstance(data["policy"]["tools"]["allow"], list)
    assert data["policy"]["files"]["deny"]  # secret floor present
    assert set(data["policy"]["email"]) == {"allow", "deny"}
    assert "auth" in data
    # a second call must not overwrite unless forced
    _, again = config.write_default(tmp_path)
    assert again is False


def test_inline_policy_is_the_grant_spec(tmp_path):
    _write(tmp_path, {"policy": {"tools": {"allow": ["Read"]}, "email": {"deny": ["evil.io"]}}})
    spec = config.grant_spec(tmp_path)
    assert spec["email"]["deny"] == ["evil.io"]


def test_policy_wins_over_legacy_grant(tmp_path):
    _write(tmp_path, {"policy": {"tools": {"allow": ["Read"]}}, "grant": ".ddbt/grant.json"})
    assert config.grant_spec(tmp_path) == {"tools": {"allow": ["Read"]}}


def test_auth_reads_oauth_legacy_alias(tmp_path):
    _write(tmp_path, {"oauth": {"github": {"app_id": "x"}}})
    assert config.auth(tmp_path)["github"]["app_id"] == "x"


def test_missing_file_yields_defaults(tmp_path):
    c = config.load(tmp_path)
    assert c["ddbt"] is True and c["gate_offgoal"] is True and c["provider"] is None


def test_file_provides_values(tmp_path):
    _write(tmp_path, {"provider": "anthropic", "model": "claude-x", "ddbt": False})
    assert config.provider(tmp_path) == "anthropic"
    assert config.model(tmp_path) == "claude-x"
    assert config.engine_kwargs(tmp_path)["ddbt"] is False


def test_env_overrides_file(tmp_path, monkeypatch):
    _write(tmp_path, {"provider": "anthropic", "model": "claude-x"})
    monkeypatch.setenv("DDBT_PROVIDER", "gemini")
    monkeypatch.setenv("DDBT_MODEL", "gemini-x")  # alias for DDBT_JUDGE_MODEL
    assert config.provider(tmp_path) == "gemini"
    assert config.model(tmp_path) == "gemini-x"


def test_grant_spec_is_inline_policy_only(tmp_path):
    # legacy "grant" key is no longer honoured; only the inline "policy" block is the ticket
    _write(tmp_path, {"grant": ".ddbt/grant.json"})
    assert config.grant_spec(tmp_path) is None
    _write(tmp_path, {"policy": {"tools": {"allow": ["Read"]}}})
    assert config.grant_spec(tmp_path) == {"tools": {"allow": ["Read"]}}


def test_behaviors_accessor(tmp_path):
    _write(tmp_path, {"behaviors": {"deny": ["push to git unasked"], "allow": ["run tests"]}})
    b = config.behaviors(tmp_path)
    assert b["deny"] == ["push to git unasked"] and b["allow"] == ["run tests"]


def test_hook_loads_inline_policy_from_ddbt_json(tmp_path):
    from ddbt.adapters.claude_code import hook

    _write(tmp_path, {"policy": {"tools": {"allow": ["Read"]}, "files": {"deny": ["**/*.pem"]}}})
    grant = hook._load_grant(str(tmp_path))
    assert grant is not None
    # the inline policy is enforced: Bash is not in {Read}
    assert grant.check("Bash", {"command": "ls"}, now=0.0).effect == "deny"
    assert grant.check("Read", {"file_path": "a.txt"}, now=0.0).effect == "allow"
