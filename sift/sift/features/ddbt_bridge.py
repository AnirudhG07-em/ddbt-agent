"""Use DDBT from inside sift — don't re-implement what the ticket already does exactly.

sift's lexical structural features (structural.py) are a *proxy* for what ddbt computes precisely:
  * provenance — ddbt's engine already labels whether a value could have been chosen by a stranger
    (grounded field vs injection-derived free text). That's the `sink_provenance` sift needs and
    cannot derive from text.
  * the grant floor — ddbt.core.grant.Grant.check() is the deterministic DENY/ALLOW/DEFER on
    tool/path/domain/host/quota/TTL. That IS sift's hard exfil/scope floor, battle-tested.

This module bridges the two, best-effort: if the ddbt package is importable (it lives in the parent
repo's src/), sift will use the real ticket; otherwise it silently falls back to the lexical proxy so
the standalone sift venv still runs. Nothing here is required for the bake-off — it's how sift plugs
into a live ddbt deployment.
"""

from __future__ import annotations

import sys
from pathlib import Path

_DDBT_OK = False


def _try_import_ddbt():
    global _DDBT_OK
    if _DDBT_OK:
        return True
    # sift may run in its own venv; add the sibling repo's src/ to the path best-effort.
    here = Path(__file__).resolve()
    for up in here.parents:
        cand = up / "src"
        if (cand / "ddbt").is_dir():
            sys.path.insert(0, str(cand))
            break
    try:
        import ddbt.core.grant  # noqa: F401
        _DDBT_OK = True
    except Exception:
        _DDBT_OK = False
    return _DDBT_OK


def available() -> bool:
    return _try_import_ddbt()


def grant_floor(tool: str, args: dict, grant_dict: dict, now: float = 0.0) -> str | None:
    """Run ddbt's deterministic ticket check. Returns "deny" | "allow" | "defer", or None if ddbt
    isn't importable. This is the hard floor sift should honour BEFORE trusting any learned score."""
    if not _try_import_ddbt():
        return None
    from ddbt.core.grant import Grant
    g = Grant.from_dict(grant_dict, now=now)
    return g.check(tool, args, now=now).effect


def decide_with_floor(risk: float, tool: str, args: dict, grant_dict: dict | None,
                      tau_deny: float, tau_ask: float, now: float = 0.0) -> tuple[str, str]:
    """Compose ddbt's floor with sift's learned bands — the floor wins, exactly as in the ddbt
    engine (ticket is checked before the judge). Returns (decision, reason)."""
    if grant_dict is not None:
        floor = grant_floor(tool, args, grant_dict, now=now)
        if floor == "deny":
            return "DENY", "ddbt ticket floor (deterministic scope/exfil)"
        if floor == "allow":
            return "ALLOW", "ddbt ticket fast-path (read-only, in scope)"
    # in scope / no floor → sift's calibrated bands decide
    if risk >= tau_deny:
        return "DENY", f"sift risk {risk:.2f} ≥ τ_deny {tau_deny:.2f}"
    if risk >= tau_ask:
        return "ASK", f"sift risk {risk:.2f} in ASK band"
    return "ALLOW", f"sift risk {risk:.2f} < τ_ask {tau_ask:.2f}"
