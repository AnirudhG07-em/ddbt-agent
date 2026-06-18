"""Provenance store: monotonic taint + diff-against-known declassify (doc §4)."""

from __future__ import annotations

from ddbt.core.labels import TRUSTED, UNTRUSTED, Channel, Label, Origin
from ddbt.core.provenance import ProvenanceTracker, _path_key
from ddbt.policy.defaults import default_policy


def _tracker(store):
    return ProvenanceTracker(store, default_policy())


def test_set_label_is_monotonic_down(store):
    store.set_label("path:/x", TRUSTED)
    assert store.get_label("path:/x").origin == Origin.TRUSTED_TOOL
    # writing a more-untrusted label lowers trust
    store.set_label("path:/x", UNTRUSTED)
    assert store.get_label("path:/x").origin == Origin.UNTRUSTED
    # writing a MORE-trusted label must NOT raise trust (worst-label-wins)
    store.set_label("path:/x", TRUSTED)
    assert store.get_label("path:/x").origin == Origin.UNTRUSTED


def test_sensitive_path_baseline(store):
    t = _tracker(store)
    lab = t.resource_label("/home/u/.ssh/id_rsa")
    assert lab.sensitive is True


def test_watermark_only_rises_in_taint(store):
    t = _tracker(store)
    assert not t.watermark().is_tainted
    t._bump_watermark(UNTRUSTED)
    assert t.watermark().is_untrusted
    t._bump_watermark(TRUSTED)  # cannot un-taint
    assert t.watermark().is_untrusted


def test_diff_against_known_restores_only_identical(store):
    t = _tracker(store)
    t.hold_for_roundtrip("tok", "hello world", TRUSTED)
    # identical bytes returned → trust restored, audited
    restored = t.declassify_roundtrip("tok", "hello world", "/round")
    assert restored == TRUSTED
    assert any(e["kind"] == "declassify" for e in store.read_audit())


def test_diff_against_known_quarantines_delta(store):
    t = _tracker(store)
    t.hold_for_roundtrip("tok", "hello world", TRUSTED)
    # mutated return → stays untrusted, delta recorded
    res = t.declassify_roundtrip("tok", "hello world EVIL", "/round")
    assert res.origin == Origin.UNTRUSTED
    assert store.get_label(_path_key("/round")).origin == Origin.UNTRUSTED
    assert any(e["kind"] == "declassify_denied" for e in store.read_audit())


def test_write_while_tainted_propagates_to_file(store):
    from ddbt.policy.classifier import classify

    t = _tracker(store)
    t._bump_watermark(UNTRUSTED)
    action = classify("Write", {"file_path": "/ws/out.txt"}, default_policy())
    t.label_result(action, {})
    assert store.get_label(_path_key("/ws/out.txt")).is_untrusted
