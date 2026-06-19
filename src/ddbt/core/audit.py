"""Audit log (doc §1) — every decision + every trust transition.

Persistence lives in :class:`SessionStore`; this module is the typed writer and the
human-readable renderer. A core requirement (doc §12.1): the trail must *name which
checkpoint caught* each blocked action, so a denial is explainable and post-hoc
detectability is preserved (the property the injectable-judge design destroys).
"""

from __future__ import annotations

from dataclasses import dataclass

from ddbt.store.session import SessionStore


@dataclass(slots=True)
class AuditLogger:
    store: SessionStore

    def decision(self, *, checkpoint: str, state: str, tool: str, summary: str, reason: str, **extra) -> int:
        payload = {"checkpoint": checkpoint, "state": state, "tool": tool, "summary": summary, "reason": reason}
        payload.update(extra)  # v4: relevant/harmful/stray; legacy: lane
        return self.store.append_audit("decision", payload)

    def event(self, kind: str, **payload) -> int:
        return self.store.append_audit(kind, payload)

    def trail(self) -> list[dict]:
        return self.store.read_audit()

    def render(self) -> str:
        """Render the full session trail for humans (CLI / demo output)."""
        lines: list[str] = []
        for e in self.store.read_audit():
            kind = e["kind"]
            if kind == "decision":
                tag = {"allow": "✓", "gate": "?", "ask": "?", "deny": "✗"}.get(e.get("state", ""), "·")
                flags = []
                if e.get("deviation"):
                    flags.append("DEVIATION")
                if e.get("harmful"):
                    flags.append("HARMFUL")
                if e.get("serves_goal") is False:
                    flags.append("off-goal")
                for sig in ("requests_secrecy", "side_task", "external_exfil", "injection_suspected"):
                    if e.get(sig):
                        flags.append(sig)
                if e.get("strictness"):
                    flags.append(f"strict={e['strictness']}")
                fstr = f"  ({', '.join(flags)})" if flags else ""
                lines.append(
                    f"  {tag} [{e.get('checkpoint','?')}] {e.get('state','')}{fstr}  "
                    f"{e.get('tool','')} {e.get('summary','')}\n      reason: {e.get('reason','')}"
                )
            elif kind in ("declassify", "declassify_denied"):
                lines.append(f"  ⤺ {kind}: {e.get('resource','')} ({e.get('reason', e.get('delta_bytes',''))})")
            elif kind == "labeled":
                lines.append(f"  ◦ labeled {e.get('tool','')} result → {e.get('label','')}")
            elif kind in ("staged", "released", "dropped"):
                lines.append(f"  ⧗ {kind}: id={e.get('id','')} {e.get('summary', e.get('kind',''))}")
            elif kind == "bootstrap":
                lines.append(f"  ⚑ bootstrap: {e.get('status','')} — {e.get('detail','')}")
            else:
                lines.append(f"  · {kind}: {e}")
        return "\n".join(lines) if lines else "  (empty)"
