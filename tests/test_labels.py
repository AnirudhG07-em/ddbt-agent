"""Label algebra: worst-label-wins join + monotonicity (doc §4)."""

from __future__ import annotations

from ddbt.core.labels import (
    PRISTINE,
    SENSITIVE,
    TRUSTED,
    UNTRUSTED,
    Channel,
    Label,
    Origin,
    join_all,
)


def test_join_takes_least_trusted_origin():
    assert TRUSTED.join(UNTRUSTED).origin == Origin.UNTRUSTED
    assert PRISTINE.join(TRUSTED).origin == Origin.TRUSTED_TOOL
    assert UNTRUSTED.join(PRISTINE).origin == Origin.UNTRUSTED


def test_join_worsens_channel():
    hopped = TRUSTED.via_untrusted_hop()
    assert hopped.channel == Channel.VIA_UNTRUSTED_HOP
    assert TRUSTED.join(hopped).channel == Channel.VIA_UNTRUSTED_HOP


def test_sensitive_sticks_through_join():
    assert SENSITIVE.join(TRUSTED).sensitive is True
    assert TRUSTED.join(PRISTINE).sensitive is False


def test_join_is_commutative_on_all_axes():
    a, b = UNTRUSTED.via_untrusted_hop(), SENSITIVE
    j1, j2 = a.join(b), b.join(a)
    assert (j1.origin, j1.channel, j1.sensitive) == (j2.origin, j2.channel, j2.sensitive)


def test_join_never_raises_trust():
    # for any pair, the join is no more trusted than either input on every axis
    labels = [PRISTINE, TRUSTED, UNTRUSTED, SENSITIVE, TRUSTED.via_untrusted_hop()]
    for a in labels:
        for b in labels:
            j = a.join(b)
            assert j.origin <= min(a.origin, b.origin)
            assert j.channel <= min(a.channel, b.channel)
            assert j.sensitive == (a.sensitive or b.sensitive)


def test_predicates():
    assert UNTRUSTED.is_untrusted and UNTRUSTED.is_tainted
    assert SENSITIVE.is_tainted and not SENSITIVE.is_untrusted
    assert not TRUSTED.is_tainted


def test_join_all_empty_is_pristine():
    assert join_all([]) == PRISTINE
    assert join_all([TRUSTED, UNTRUSTED]).origin == Origin.UNTRUSTED


def test_label_is_immutable():
    lab = Label()
    try:
        lab.origin = Origin.UNTRUSTED  # type: ignore[misc]
        raised = False
    except Exception:
        raised = True
    assert raised
