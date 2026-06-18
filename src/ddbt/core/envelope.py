"""The scope envelope — the structural anchor (doc §3).

The envelope is the boundary of what is currently in-bounds for the session:
readable/writable path roots, allowed outbound domains, and explicit grants. It is
**not** an intent inferred from the prompt; it starts minimal (the workspace root)
and grows *only* by explicit gates and pristine user grants (doc §3.2). Sensitive
resources are always-out unless explicitly granted.

The two membership questions the judge asks are deterministic set checks:
``contains_read(path)`` and ``contains_write(path)`` / ``allows_domain(domain)``.
The **safe-direction rule** (doc §3.2) is baked in: anything not provably inside is
treated as outside, so errors fall toward false-block (recoverable), never
false-allow (silent and dangerous).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from ddbt.policy.defaults import Policy
from ddbt.store.session import SessionStore

_ENVELOPE_KEY = "envelope"


@dataclass(slots=True)
class Envelope:
    workspace_root: str
    readable_roots: set[str] = field(default_factory=set)
    writable_roots: set[str] = field(default_factory=set)
    allowed_domains: set[str] = field(default_factory=set)
    # explicit grants (named by the user or widened by a gate); may include otherwise
    # sensitive/out-of-root paths — a grant is the deliberate way to widen.
    granted_read: set[str] = field(default_factory=set)
    granted_write: set[str] = field(default_factory=set)

    # ---- membership (deterministic; the judge's right-hand side) ----

    def _under_any(self, path: str, roots: set[str]) -> bool:
        for root in roots:
            try:
                if os.path.commonpath([path, root]) == root:
                    return True
            except ValueError:  # different drives / relative-vs-absolute mismatch
                continue
        return False

    def contains_read(self, resolved_path: str) -> bool:
        if self._under_any(resolved_path, self.granted_read | self.granted_write):
            return True
        return self._under_any(resolved_path, self.readable_roots)

    def contains_write(self, resolved_path: str) -> bool:
        if self._under_any(resolved_path, self.granted_write):
            return True
        return self._under_any(resolved_path, self.writable_roots)

    def explicitly_grants(self, resolved_path: str) -> bool:
        """Exact-path grant check (no ancestor containment).

        Sensitive resources are always-out unless *explicitly* granted (doc §3.1): a
        broad grant of a parent directory must never implicitly authorise a sensitive
        child. This is the deliberate, narrow gate for the hard-deny tier.
        """
        p = os.path.normpath(resolved_path)
        return p in self.granted_read or p in self.granted_write

    def allows_domain(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        for allowed in self.allowed_domains:
            allowed = allowed.lower().rstrip(".")
            if domain == allowed or domain.endswith("." + allowed):
                return True
        return False

    # ---- growth (only via gates / pristine grants) ----

    def grant_read(self, path: str) -> None:
        self.granted_read.add(os.path.normpath(path))

    def grant_write(self, path: str) -> None:
        p = os.path.normpath(path)
        self.granted_write.add(p)
        self.granted_read.add(p)  # write implies read

    def grant_domain(self, domain: str) -> None:
        self.allowed_domains.add(domain.lower().rstrip("."))

    # ---- (de)serialisation for the cross-call store ----

    def to_json(self) -> str:
        return json.dumps(
            {
                "workspace_root": self.workspace_root,
                "readable_roots": sorted(self.readable_roots),
                "writable_roots": sorted(self.writable_roots),
                "allowed_domains": sorted(self.allowed_domains),
                "granted_read": sorted(self.granted_read),
                "granted_write": sorted(self.granted_write),
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> "Envelope":
        d = json.loads(raw)
        return cls(
            workspace_root=d["workspace_root"],
            readable_roots=set(d.get("readable_roots", [])),
            writable_roots=set(d.get("writable_roots", [])),
            allowed_domains=set(d.get("allowed_domains", [])),
            granted_read=set(d.get("granted_read", [])),
            granted_write=set(d.get("granted_write", [])),
        )


def seed_envelope(workspace_root: str, policy: Policy, declared_deps: list[str] | None = None) -> Envelope:
    """Seed the minimal envelope at session start (doc §3.2): the workspace root
    (read+write) plus any declared dependency roots (read-only). No secrets, no
    network, nothing outside root."""
    root = os.path.normpath(os.path.expanduser(workspace_root))
    env = Envelope(workspace_root=root, readable_roots={root}, writable_roots={root})
    for dep in declared_deps or []:
        env.readable_roots.add(os.path.normpath(os.path.expanduser(dep)))
    return env


def load_or_seed(store: SessionStore, workspace_root: str, policy: Policy) -> Envelope:
    """Load a persisted envelope (session resume) or seed a fresh minimal one."""
    raw = store.get_meta(_ENVELOPE_KEY)
    if raw:
        return Envelope.from_json(raw)
    env = seed_envelope(workspace_root, policy)
    save(store, env)
    return env


def save(store: SessionStore, env: Envelope) -> None:
    store.set_meta(_ENVELOPE_KEY, env.to_json())
