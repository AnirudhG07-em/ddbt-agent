"""Scope envelope: seed, grow-by-gate, membership, safe-direction (doc §3)."""

from __future__ import annotations

import os

from ddbt.core.envelope import seed_envelope
from ddbt.policy.defaults import default_policy


def test_seed_is_minimal(tmp_path):
    ws = str(tmp_path / "repo")
    os.makedirs(ws)
    env = seed_envelope(ws, default_policy())
    assert env.contains_read(os.path.join(ws, "a.py"))
    assert env.contains_write(os.path.join(ws, "a.py"))
    # nothing outside root, no domains
    assert not env.contains_read("/etc/passwd")
    assert not env.allows_domain("evil.com")


def test_safe_direction_outside_root_is_out(tmp_path):
    ws = str(tmp_path / "repo")
    os.makedirs(ws)
    env = seed_envelope(ws, default_policy())
    assert not env.contains_write(str(tmp_path / "other" / "x"))


def test_grant_widens_only_named(tmp_path):
    ws = str(tmp_path / "repo")
    os.makedirs(ws)
    env = seed_envelope(ws, default_policy())
    env.grant_domain("ci.example.com")
    assert env.allows_domain("ci.example.com")
    assert env.allows_domain("sub.ci.example.com")  # subdomain of granted
    assert not env.allows_domain("evil.com")

    target = str(tmp_path / "shared" / "lib")
    env.grant_write(target)
    assert env.contains_write(os.path.join(target, "f.py"))
    assert env.contains_read(os.path.join(target, "f.py"))  # write implies read


def test_serialisation_roundtrip(tmp_path):
    ws = str(tmp_path / "repo")
    os.makedirs(ws)
    env = seed_envelope(ws, default_policy())
    env.grant_domain("ci.example.com")
    from ddbt.core.envelope import Envelope

    restored = Envelope.from_json(env.to_json())
    assert restored.allows_domain("ci.example.com")
    assert restored.workspace_root == env.workspace_root
