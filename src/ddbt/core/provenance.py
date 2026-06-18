"""Provenance tracker — the content inspector (doc §4, §5.4).

This is the *labelling* half of the dual-judge split. It assumes every input is
hostile and may itself be fully injected — and that's fine, because it has **no
authority to approve anything**. Its only powers are to *lower* trust (emit taint)
and, in exactly one audited case, to *restore* byte-identical trust
(diff-against-known). The worst it can do is under-flag; it can never grant
permission. All authority lives in the (blind) policy judge, ``checkpoint2``.

Resource-granularity model (the honest boundary, doc §3.3): we label *resources*
(files, tool results) and a session *watermark*, not data flowing inside the model
— the hook layer cannot see the model's hidden state. The primary protection is
therefore the envelope boundary (target path/domain membership) plus the structural
fact "this action touches a sensitive source"; taint is the secondary signal for the
``sensitive → outbound`` toxic-flow case.
"""

from __future__ import annotations

from dataclasses import dataclass

from ddbt.core.labels import PRISTINE, SENSITIVE, TRUSTED, UNTRUSTED, Label
from ddbt.policy.classifier import StructuralAction, ToolClass
from ddbt.policy.defaults import Policy
from ddbt.store.session import SessionStore

# meta key under which we persist the session taint watermark
_WATERMARK_KEY = "taint_watermark"


@dataclass(slots=True)
class ProvenanceTracker:
    store: SessionStore
    policy: Policy

    # ---- reading the trust of a resource (for checkpoint2's structural facts) ----

    def resource_label(self, path: str) -> Label:
        """The current label of a filesystem resource.

        Worst-label-wins of: any stored taint for the path (e.g. untrusted bytes were
        written into it earlier) joined with its structural baseline (sensitive secret
        vs ordinary local file). Never reads the file's contents.
        """
        baseline = SENSITIVE if self.policy.is_sensitive_path(path) else TRUSTED
        stored = self.store.get_label(_path_key(path))
        return baseline.join(stored) if stored else baseline

    def watermark(self) -> Label:
        """The worst label ingested into the session context so far."""
        raw = self.store.get_meta(_WATERMARK_KEY)
        return _decode_label(raw) if raw else PRISTINE

    def _bump_watermark(self, label: Label) -> None:
        self.store.set_meta(_WATERMARK_KEY, _encode_label(self.watermark().join(label)))

    # ---- labelling tool results (called at PostToolUse — the content inspector) ----

    def label_result(self, action: StructuralAction, tool_response: dict) -> Label:
        """Assign a provenance label to a completed tool's output and persist effects.

        Deterministic, by *source class* — not by inspecting meaning. Updates per-file
        taint and the session watermark. Returns the label assigned to the result.
        """
        if action.tool_class == ToolClass.UNTRUSTED_RETRIEVAL:
            label = UNTRUSTED
            self._bump_watermark(label)
            for d in action.domains:
                self.store.set_label(_domain_key(d), label, reason=f"fetched from {d}")
            return label

        if action.tool_class == ToolClass.TRUSTED_RETRIEVAL and action.op == "read":
            # reading a file surfaces its current label into the context watermark
            for p in action.paths:
                lab = self.resource_label(p)
                self._bump_watermark(lab)
            return self.watermark()

        if action.tool_class == ToolClass.ACTION and action.op == "write":
            # Resource-granularity propagation: a write performed while the session
            # context is tainted is conservatively assumed to carry that taint into
            # the target file. Over-tainting here is the safe direction (doc §3.2).
            wm = self.watermark()
            if wm.is_tainted:
                for p in action.paths:
                    self.store.set_label(
                        _path_key(p), wm, reason="written while context tainted"
                    )
            return wm

        return PRISTINE

    # ---- diff-against-known declassify (doc §4 #3) ----

    def hold_for_roundtrip(self, token: str, content: str, label: Label) -> None:
        """Remember a trusted value before it travels through an untrusted hop."""
        self.store.hold_original(token, content, label)

    def declassify_roundtrip(self, token: str, returned: str, resource: str) -> Label:
        """Restore trust only for the byte-identical portion of a round-tripped value.

        If the returned bytes match the held original exactly, the original (trusted)
        label is restored via an audited declassify. Any delta keeps the value tainted.
        This is the only automatic trust-raising mechanism in the system.
        """
        original = self.store.get_original(token)
        if original is not None and original == returned:
            self.store.declassify(
                _path_key(resource), TRUSTED, reason="diff-match: bytes identical to held original"
            )
            return TRUSTED
        # delta (or no original held) → stays/Becomes untrusted; record quarantine size
        delta = abs(len((returned or "")) - len((original or "")))
        self.store.set_label(
            _path_key(resource), UNTRUSTED, reason=f"diff-mismatch: {delta} bytes delta quarantined"
        )
        self.store.append_audit(
            "declassify_denied", {"resource": resource, "delta_bytes": delta}
        )
        return UNTRUSTED


# ---- resource key helpers (stable keys for the store) ----


def _path_key(path: str) -> str:
    return f"path:{path}"


def _domain_key(domain: str) -> str:
    return f"domain:{domain}"


def _encode_label(label: Label) -> str:
    return f"{int(label.origin)},{int(label.channel)},{int(label.sensitive)}"


def _decode_label(raw: str) -> Label:
    from ddbt.core.labels import Channel, Origin

    o, c, s = raw.split(",")
    return Label(Origin(int(o)), Channel(int(c)), bool(int(s)))
