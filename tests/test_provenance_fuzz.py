"""Provenance fuzzer — the hardest-tested module (doc §12.5).

The blind judge trusts labels completely, so the one catastrophic failure is
**under-tainting**: untrusted content ending up with a trusted label. These property
tests fuzz the labeller directly and assert that never happens, across arbitrary
sequences of mixed trusted/untrusted operations, round-trips, and encoded content.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ddbt.core.labels import PRISTINE, SENSITIVE, TRUSTED, UNTRUSTED, Channel, Label, Origin
from ddbt.core.provenance import ProvenanceTracker, _path_key
from ddbt.policy.defaults import default_policy
from ddbt.store.session import SessionStore

_LABELS = [PRISTINE, TRUSTED, UNTRUSTED, SENSITIVE, TRUSTED.via_untrusted_hop(), UNTRUSTED.via_untrusted_hop()]
_label_strat = st.sampled_from(_LABELS)


@given(labels=st.lists(_label_strat, min_size=1, max_size=20))
def test_join_never_under_taints(labels):
    """worst-label-wins: if ANY input is untrusted/sensitive, the result must be too."""
    result = labels[0]
    for lab in labels[1:]:
        result = result.join(lab)
    if any(l.is_untrusted for l in labels):
        assert result.is_untrusted, "untrusted input produced a non-untrusted join"
    if any(l.sensitive for l in labels):
        assert result.sensitive, "sensitive input was lost in the join"
    # the joined origin is exactly the minimum (least trusted) of the inputs
    assert result.origin == min(l.origin for l in labels)


@given(
    ops=st.lists(_label_strat, min_size=1, max_size=15),
    tmp=st.integers(min_value=0, max_value=1_000_000),
)
@settings(max_examples=200, deadline=None)
def test_store_set_label_is_monotonic_down(ops, tmp, tmp_path_factory):
    """No sequence of set_label calls can ever raise a resource's trust."""
    base = tmp_path_factory.mktemp("fuzz")
    store = SessionStore(f"fuzz-{tmp}", base_dir=base)
    try:
        key = "path:/r"
        worst = ops[0]
        store.set_label(key, ops[0])
        for lab in ops[1:]:
            worst = worst.join(lab)
            store.set_label(key, lab)
            current = store.get_label(key)
            # stored label must never be MORE trusted than the running worst-case
            assert current.origin <= worst.origin
            assert current.channel <= worst.channel
            assert current.sensitive == worst.sensitive
    finally:
        store.close()


@given(
    original=st.text(min_size=0, max_size=80),
    returned=st.text(min_size=0, max_size=80),
    tmp=st.integers(min_value=0, max_value=1_000_000),
)
@settings(max_examples=200, deadline=None)
def test_diff_against_known_only_restores_on_exact_match(original, returned, tmp, tmp_path_factory):
    """The single trust-raising path restores trust IFF bytes are identical."""
    base = tmp_path_factory.mktemp("rt")
    store = SessionStore(f"rt-{tmp}", base_dir=base)
    try:
        t = ProvenanceTracker(store, default_policy())
        t.hold_for_roundtrip("tok", original, TRUSTED)
        result = t.declassify_roundtrip("tok", returned, "/res")
        if original == returned:
            assert result == TRUSTED
        else:
            assert result.is_untrusted, "non-identical round-trip must stay tainted"
            assert store.get_label(_path_key("/res")).is_untrusted
    finally:
        store.close()


@given(
    secret_path=st.sampled_from(["~/.ssh/id_rsa", "/home/u/.aws/credentials", "/x/.env", "/p/token.txt"]),
    tmp=st.integers(min_value=0, max_value=1_000_000),
)
@settings(max_examples=50, deadline=None)
def test_sensitive_paths_always_labelled_sensitive(secret_path, tmp, tmp_path_factory):
    base = tmp_path_factory.mktemp("sens")
    store = SessionStore(f"sens-{tmp}", base_dir=base)
    try:
        t = ProvenanceTracker(store, default_policy())
        assert t.resource_label(secret_path).sensitive is True
    finally:
        store.close()
