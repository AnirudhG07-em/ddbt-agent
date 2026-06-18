"""Cumulative-trajectory / lookahead checks (#1, doc §1). Multi-step shapes that each
single-action judge misses: drip-exfil (too many sends) and read-heavy-then-send."""

from __future__ import annotations

import dataclasses
import os

from ddbt.core.engine import Effect, Engine
from ddbt.policy.defaults import default_policy


def _engine(base_dir, tmp_path, policy, sid="traj"):
    ws = str(tmp_path / f"ws-{sid}")
    os.makedirs(ws, exist_ok=True)
    e = Engine(sid, workspace_root=ws, base_dir=base_dir, policy=policy)
    e.on_session_start("startup", ws)
    e.on_user_prompt("publish status updates to https://ci.example.com")
    return e, ws


def test_drip_exfil_escalates_after_budget(base_dir, tmp_path):
    policy = dataclasses.replace(default_policy(), max_outbound_per_session=2)
    e, ws = _engine(base_dir, tmp_path, policy)
    cmd = {"command": "curl -d ok https://ci.example.com/s"}  # clean flow, granted domain → allow
    # first 2 are within budget
    for _ in range(2):
        assert e.evaluate_action("Bash", cmd).effect == Effect.ALLOW
        e.record_result("Bash", cmd, {})  # counts the send
    # the 3rd trips the cumulative budget → escalate (was ALLOW on its own)
    d = e.evaluate_action("Bash", cmd)
    assert d.effect == Effect.ASK and d.checkpoint == "trajectory"
    assert "drip-exfil" in d.reason
    e.close()


def test_trajectory_only_raises_never_lowers(base_dir, tmp_path):
    # even with a tiny budget, a clean in-scope action stays ALLOW (trajectory only fires
    # on outbound, and never lowers a decision)
    policy = dataclasses.replace(default_policy(), max_outbound_per_session=0)
    e, ws = _engine(base_dir, tmp_path, policy)
    assert e.evaluate_action("Write", {"file_path": os.path.join(ws, "a.py"), "file_text": "x"}).effect == Effect.ALLOW
    # but the very first outbound now trips the (zero) budget
    assert e.evaluate_action("Bash", {"command": "curl -d ok https://ci.example.com/s"}).effect == Effect.ASK
    e.close()


def test_record_accumulates_counters(base_dir, tmp_path):
    e, ws = _engine(base_dir, tmp_path, default_policy())
    e.record_result("WebFetch", {"url": "x"}, {"content": "..."})  # untrusted ingest
    e.record_result("Read", {"file_path": "/a/b.py"}, {})
    e.record_result("Read", {"file_path": "/a/c.py"}, {})
    e.record_result("Read", {"file_path": "/a/b.py"}, {})  # dup → set size still 2
    assert e.store.get_counter("traj_untrusted_ingests") == 1
    assert e.store.set_size("traj_reads") == 2
    e.close()