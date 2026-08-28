"""Exfil budget — the low-and-slow layer: stateful accounting a per-call judge cannot do.

Content checks (provenance_taint, pii_dlp) ask "is THIS payload sensitive?". They are blind to the
attack that hides in the AGGREGATE: 10k rows leaked in small innocuous batches, a secret dribbled out
one chunk per step, a beacon posting on a fixed cadence. Each call is under every content threshold;
the danger is only visible when you sum across the trajectory. This is exactly what enterprise DLP,
C2-beacon detection, and statistical-database auditing do — deterministically, no model — and the
ledger now gives us the per-destination history to do the same over tool calls.

Signals (all keyed by external destination, evaluated at the sink):
  * volume budget   — Σ outbound bytes to one external destination over the session (NetFlow low-and-slow).
  * chunk/call count — many small egress calls to the same external destination (chunked exfil / beacon).
  * beacon cadence  — inter-call intervals with low coefficient-of-variation (RITA). Timing-gated: only
                      when the calls are actually spaced in wall-clock, so bulk replay can't false-fire.
  * db coverage     — cumulative records pulled from queries + consecutive-result overlap (enumeration);
                      a large read-volume then leaving the boundary is the aggregation attack.

Trusted destinations are exempt. Escalates ASK for suspicious, DENY only for egregious — thresholds are
configurable per workspace via ddbt.json (all have conservative defaults tuned to not fire on normal
short benign sequences).
"""

from __future__ import annotations

import json
import statistics

from ddbt.core.ledger import EGRESS as _EGRESS, MAX_SCAN_CHARS, Ledger, destinations, flatten, is_external
from ddbt.plugins.base import Plugin, PluginContext, PreVerdict

_REC_KEYS = ("rows", "records", "results", "data", "items", "documents", "hits")
_ID_KEYS = ("id", "_id", "uuid", "pk", "key", "email", "user_id", "account_id")
_ENUM_KEY = "exfil_lastids"
_REC_KEY = "exfil_records"
_ENUM_CNT = "exfil_enum"


def _cov(xs: list[float]) -> float:
    """Coefficient of variation σ/μ — scale-free regularity. Near 0 = machine-clockwork beacon;
    organic/agent traffic has high CoV. Returns a large number when μ≈0 (i.e. 'not regular data')."""
    if len(xs) < 2:
        return 99.0
    mu = statistics.fmean(xs)
    if mu <= 0:
        return 99.0
    return statistics.pstdev(xs) / mu


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _record_ids(result) -> set[str]:
    """Best-effort: pull record identifiers out of a query/read result so we can measure how much of
    a dataset the session has cumulatively touched. Only fires when the result looks like records."""
    ids: set[str] = set()
    rows = None
    if isinstance(result, list):
        rows = result
    elif isinstance(result, dict):
        for k in _REC_KEYS:
            if isinstance(result.get(k), list):
                rows = result[k]
                break
    if not isinstance(rows, list):
        return ids
    for r in rows[:5000]:
        if isinstance(r, dict):
            for k in _ID_KEYS:
                if k in r:
                    ids.add(f"{k}={str(r[k])[:64]}".lower())
                    break
            else:
                ids.add(json.dumps(r, sort_keys=True, default=str)[:96].lower())
        else:
            ids.add(str(r)[:64].lower())
    return ids


class ExfilBudget(Plugin):
    name = "exfil_budget"
    headline = "A lot of data is trickling out — this looks like slow data theft."

    def __init__(self, trusted_domains: tuple[str, ...] = (), soft_bytes: int = 200_000,
                 hard_bytes: int = 2_000_000, soft_calls: int = 5, hard_calls: int = 25,
                 beacon_min_calls: int = 4, beacon_cov: float = 0.35, beacon_min_interval: float = 1.0,
                 db_records_soft: int = 300, db_records_hard: int = 3000):
        self.trusted = tuple(d.lower() for d in trusted_domains)
        self.soft_bytes, self.hard_bytes = soft_bytes, hard_bytes
        self.soft_calls, self.hard_calls = soft_calls, hard_calls
        self.beacon_min_calls, self.beacon_cov, self.beacon_min_interval = beacon_min_calls, beacon_cov, beacon_min_interval
        self.db_records_soft, self.db_records_hard = db_records_soft, db_records_hard

    # ---- observe: accumulate how much of a dataset the session has pulled ----
    def observe(self, tool: str, args: dict, result, ctx: PluginContext) -> None:
        if ctx.store is None:
            return
        ids = _record_ids(result)
        if not ids:
            return
        ctx.store.increment_meta(_REC_KEY, len(ids))
        try:
            prev = set(json.loads(ctx.store.get_meta(_ENUM_KEY) or "[]"))
        except (ValueError, TypeError):
            prev = set()
        if _jaccard(prev, ids) >= 0.6 and len(ids) >= 3:  # near-identical successive queries = enumeration
            ctx.store.increment_meta(_ENUM_CNT, 1)
        ctx.store.set_meta(_ENUM_KEY, json.dumps(sorted(ids)[:60]))

    # ---- pre_check: score the sink against the session's accumulated egress ----
    def pre_check(self, tool: str, args: dict, ctx: PluginContext) -> PreVerdict | None:
        text = flatten(args)
        cur_bytes = len(text)                 # true outbound size, before capping the scan
        text = text[:MAX_SCAN_CHARS]
        dests = destinations(text)
        if not (_EGRESS.search(tool) or _EGRESS.search(text)):
            return None
        ext = [d for d in dests if is_external(d, self.trusted)]
        if not ext:  # no external destination to account against — nothing for this layer to add
            return self._db_only(ctx, dests)
        led = Ledger(ctx.store)
        worst: PreVerdict | None = None
        for d in ext:
            worst = self._max(worst, self._score_dest(led, d, cur_bytes))
        return self._max(worst, self._db_only(ctx, dests))

    def _score_dest(self, led: Ledger, dest: str, cur_bytes: int) -> PreVerdict | None:
        total = led.bytes_to(dest) + cur_bytes
        calls = led.calls_to(dest) + 1
        if total >= self.hard_bytes or calls >= self.hard_calls:
            return PreVerdict("deny", f"Exfiltration (T1030 · TA0010) · {calls} sends totalling "
                              f"~{total//1000}KB to {dest} this session — sustained bulk egress "
                              f"(low-and-slow exfil pattern)", self.name)
        soft = None
        if total >= self.soft_bytes:
            soft = (f"~{total//1000}KB of data has now gone to {dest} across {calls} sends this session")
        elif calls >= self.soft_calls:
            soft = (f"{calls} separate sends to {dest} this session — possible chunked exfil")
        else:
            ivals = led.intervals(dest)
            if len(ivals) + 1 >= self.beacon_min_calls and statistics.fmean(ivals) >= self.beacon_min_interval \
                    and _cov(ivals) < self.beacon_cov:
                soft = (f"regular {statistics.fmean(ivals):.0f}s cadence to {dest} (CoV={_cov(ivals):.2f}) "
                        f"— beacon-like timing")
        if soft:
            return PreVerdict("ask", f"Exfiltration (T1030 · TA0010) · {soft} — confirm it's intended", self.name)
        return None

    def _db_only(self, ctx: PluginContext, dests: list[str]) -> PreVerdict | None:
        if ctx.store is None:
            return None
        recs = int(ctx.store.get_meta(_REC_KEY, "0") or "0")
        enum = int(ctx.store.get_meta(_ENUM_CNT, "0") or "0")
        external = any(is_external(d, self.trusted) for d in dests) or not dests
        if not external:
            return None
        if recs >= self.db_records_hard:
            return PreVerdict("deny", f"Collection→Exfiltration (T1213 · TA0009) · ~{recs} records were "
                              f"read from queries this session and are now leaving the boundary — "
                              f"aggregation/bulk-export", self.name)
        if recs >= self.db_records_soft or enum >= 4:
            why = (f"~{recs} records read via queries this session" if recs >= self.db_records_soft
                   else f"{enum} near-identical enumeration queries this session")
            return PreVerdict("ask", f"Collection→Exfiltration (T1213 · TA0009) · {why}, now egressing "
                              f"— confirm it's intended", self.name)
        return None

    @staticmethod
    def _max(a: PreVerdict | None, b: PreVerdict | None) -> PreVerdict | None:
        order = {"ask": 1, "deny": 2}
        if a is None:
            return b
        if b is None:
            return a
        return b if order.get(b.effect, 0) > order.get(a.effect, 0) else a
