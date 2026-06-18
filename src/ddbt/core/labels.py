"""Two-axis provenance labels (doc §4).

A label carries *integrity* (whose data is it, by what path) and *confidentiality*
(is it secret). These are independent axes:

  - origin    — integrity: who produced the data  (USER > TRUSTED_TOOL > UNTRUSTED)
  - channel   — what path did it travel           (DIRECT vs VIA_UNTRUSTED_HOP)
  - sensitive — confidentiality: is it a secret    (e.g. an ssh key, a token)

The combining rule everywhere is **worst-label-wins** (doc §4): an output derived
from N inputs inherits the *least* trusted origin, the *worst* channel, and is
sensitive if *any* input was. Trust therefore only ever decreases automatically —
that monotonicity is the security property the blind judge relies on. The one
permitted automatic re-trusting (diff-against-known) lives in ``provenance.py``,
never here.

Nothing in this module reads untrusted *content*; a label is metadata *about* a
value, not the value. That is what lets the policy judge reason over labels while
staying blind to bytes (doc §5.4).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Origin(enum.IntEnum):
    """Integrity axis, ordered by trust. Higher = more trusted.

    Ordering matters: ``min()`` over a set of origins yields the worst (least
    trusted) one, which is exactly worst-label-wins for this axis.
    """

    UNTRUSTED = 0  # externally influenceable: web, email, issues, 3rd-party MCP
    TRUSTED_TOOL = 1  # first-party, system-controlled: in-scope local read, owned git
    USER = 2  # pristine user input (the prompt, clarification answers)

    @property
    def label(self) -> str:
        return self.name.lower()


class Channel(enum.IntEnum):
    """Path the data travelled. DIRECT is trusted; a single untrusted hop taints it."""

    VIA_UNTRUSTED_HOP = 0  # passed through an externally-influenceable component
    DIRECT = 1  # never left a trusted path

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Label:
    """Immutable provenance label attached to a resource or tool result.

    ``sensitive`` is confidentiality (secret-ness), determined *structurally* by
    source/path (e.g. matches ``~/.ssh/*``), never by reading content.
    """

    origin: Origin = Origin.USER
    channel: Channel = Channel.DIRECT
    sensitive: bool = False

    # ---- predicates the structural judge (checkpoint2) reads ----

    @property
    def is_untrusted(self) -> bool:
        """True if integrity is compromised on either axis."""
        return self.origin == Origin.UNTRUSTED or self.channel == Channel.VIA_UNTRUSTED_HOP

    @property
    def is_tainted(self) -> bool:
        """Tainted = untrusted-integrity OR sensitive. The thing we won't let leak."""
        return self.is_untrusted or self.sensitive

    def describe(self) -> str:
        bits = [self.origin.label, self.channel.label]
        if self.sensitive:
            bits.append("sensitive")
        return "/".join(bits)

    # ---- the worst-label-wins join (doc §4) ----

    def join(self, other: "Label") -> "Label":
        """Combine two labels, keeping the most-untrusted of each axis."""
        return Label(
            origin=min(self.origin, other.origin),
            channel=min(self.channel, other.channel),
            sensitive=self.sensitive or other.sensitive,
        )

    def via_untrusted_hop(self) -> "Label":
        """Return this label after travelling through an untrusted hop.

        Monotonic: the channel can only worsen, never improve, here.
        """
        return Label(origin=self.origin, channel=Channel.VIA_UNTRUSTED_HOP, sensitive=self.sensitive)


# Canonical labels used across the codebase.
PRISTINE = Label(Origin.USER, Channel.DIRECT, sensitive=False)  # the user prompt
TRUSTED = Label(Origin.TRUSTED_TOOL, Channel.DIRECT, sensitive=False)  # in-scope local read
UNTRUSTED = Label(Origin.UNTRUSTED, Channel.DIRECT, sensitive=False)  # web/email/issue result
SENSITIVE = Label(Origin.TRUSTED_TOOL, Channel.DIRECT, sensitive=True)  # a secret, locally read


def join_all(labels: object) -> Label:
    """Worst-label-wins over an iterable of labels. Empty → PRISTINE (no taint)."""
    result = PRISTINE
    seen = False
    for lab in labels:  # type: ignore[attr-defined]
        result = result.join(lab)
        seen = True
    return result if seen else PRISTINE
