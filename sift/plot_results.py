#!/usr/bin/env python
"""Generate the result charts in docs/ as dependency-free SVG (no matplotlib).

    python plot_results.py

Numbers are the measured model2vec-encoder run (deployed method = fusion) vs ddbt's LLM judge.
Edit the DATA blocks and re-run to refresh. SVGs render inline in the READMEs on GitHub.
"""

from __future__ import annotations

from pathlib import Path

# --- measured results (model2vec encoder). "sift" = the deployed `fusion` method. ---
SIFT_VS_LLM = [  # (benchmark, sift F1, llm F1)
    ("R-Judge", 0.87, 0.915),
    ("InjecAgent", 1.00, 1.00),
    ("MCPTox", 1.00, 0.998),
]
# R-Judge recall@5%FPR on the SHIFT (adversarial) set — the metric a deployed gate actually runs at
# (fixed low false-positive rate), unlike F1 which uses an oracle-best threshold. This is why fusion
# is deployed even though a couple of methods edge it on F1.
LEADERBOARD = [
    ("fusion (deployed)", 0.43),
    ("static_gbt", 0.40),
    ("model2vec_trained", 0.33),
    ("static_linear", 0.30),
    ("setfit (exp.)", 0.24),
    ("anomaly", 0.16),
    ("prototypes", 0.04),
]
LLM_REF = None  # not comparable at this metric (the LLM judge runs at its own threshold)

TEAL, GRAY, INK, MUT, CARD, GRID = "#0d9488", "#94a3b8", "#0f172a", "#64748b", "#ffffff", "#e2e8f0"


def _grouped(path: Path):
    W, H = 720, 430
    x0, x1, y0, y1 = 95, 680, 300, 60   # plot area (y0 bottom=0.0, y1 top=1.0)
    def Y(v): return y0 - (y1 - y0) * (-v)  # v in [0,1] → pixel
    def Yv(v): return y0 - (y0 - y1) * v
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="Segoe UI,Helvetica,Arial,sans-serif">']
    s.append(f'<rect width="{W}" height="{H}" rx="12" fill="{CARD}"/>')
    s.append(f'<text x="40" y="34" font-size="19" font-weight="700" fill="{INK}">sift (non-LLM) vs the LLM judge — F1</text>')
    s.append(f'<text x="40" y="52" font-size="12.5" fill="{MUT}">near-parity, at $0 API cost and ~62 ms local (vs a networked LLM call)</text>')
    # gridlines 0,.25,.5,.75,1
    for g in (0, .25, .5, .75, 1):
        yy = Yv(g)
        s.append(f'<line x1="{x0}" y1="{yy:.1f}" x2="{x1}" y2="{yy:.1f}" stroke="{GRID}"/>')
        s.append(f'<text x="{x0-8}" y="{yy+4:.1f}" font-size="11" text-anchor="end" fill="{MUT}">{g:.2f}</text>')
    n = len(SIFT_VS_LLM)
    gw = (x1 - x0) / n
    bw = 46
    for i, (name, sv, lv) in enumerate(SIFT_VS_LLM):
        cx = x0 + gw * i + gw / 2
        for j, (val, col, lab) in enumerate([(sv, TEAL, "sift"), (lv, GRAY, "LLM")]):
            bx = cx - bw - 6 + j * (bw + 12)
            by = Yv(val)
            s.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw}" height="{y0-by:.1f}" rx="4" fill="{col}"/>')
            s.append(f'<text x="{bx+bw/2:.1f}" y="{by-6:.1f}" font-size="12" font-weight="700" text-anchor="middle" fill="{INK}">{val:.2f}</text>')
        s.append(f'<text x="{cx:.1f}" y="{y0+20:.1f}" font-size="13" font-weight="600" text-anchor="middle" fill="{INK}">{name}</text>')
    # legend
    lx, ly = 460, 400
    s.append(f'<rect x="{lx}" y="{ly-10}" width="13" height="13" rx="3" fill="{TEAL}"/><text x="{lx+19}" y="{ly}" font-size="12.5" fill="{INK}">sift · local, $0</text>')
    s.append(f'<rect x="{lx+130}" y="{ly-10}" width="13" height="13" rx="3" fill="{GRAY}"/><text x="{lx+149}" y="{ly}" font-size="12.5" fill="{INK}">LLM · API $, network</text>')
    s.append('</svg>')
    path.write_text("\n".join(s))


def _leaderboard(path: Path):
    W = 720
    rowh, top = 34, 92
    H = top + rowh * len(LEADERBOARD) + 30
    x0, x1, xmax = 210, 660, 0.5   # values are recall@5%FPR (≤~0.43) → scale axis to 0.5
    def X(v): return x0 + (x1 - x0) * (v / xmax)
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="Segoe UI,Helvetica,Arial,sans-serif">']
    s.append(f'<rect width="{W}" height="{H}" rx="12" fill="{CARD}"/>')
    s.append(f'<text x="40" y="36" font-size="19" font-weight="700" fill="{INK}">Why fusion — R-Judge recall @ 5% FPR (adversarial set)</text>')
    s.append(f'<text x="40" y="55" font-size="12.5" fill="{MUT}">the metric a deployed gate runs at (fixed low false-positive rate), not oracle-thresholded F1</text>')
    if LLM_REF is not None:
        ref = X(LLM_REF)
        s.append(f'<line x1="{ref:.1f}" y1="{top-8}" x2="{ref:.1f}" y2="{H-18}" stroke="{INK}" stroke-dasharray="4 4" opacity="0.55"/>')
        s.append(f'<text x="{ref:.1f}" y="{top-14}" font-size="11" text-anchor="middle" fill="{INK}">LLM {LLM_REF}</text>')
    for i, (name, val) in enumerate(LEADERBOARD):
        y = top + rowh * i
        col = TEAL if "deployed" in name else (GRAY if "exp." in name else "#38bdf8")
        s.append(f'<text x="195" y="{y+16:.1f}" font-size="12.5" text-anchor="end" fill="{INK}">{name}</text>')
        s.append(f'<rect x="{x0}" y="{y+3:.1f}" width="{X(val)-x0:.1f}" height="20" rx="4" fill="{col}"/>')
        s.append(f'<text x="{X(val)+7:.1f}" y="{y+18:.1f}" font-size="12" font-weight="700" fill="{INK}">{val:.2f}</text>')
    s.append('</svg>')
    path.write_text("\n".join(s))


def main():
    d = Path(__file__).resolve().parent / "docs"
    d.mkdir(exist_ok=True)
    _grouped(d / "sift_vs_llm.svg")
    _leaderboard(d / "methods.svg")
    print(f"wrote {d/'sift_vs_llm.svg'}\nwrote {d/'methods.svg'}")


if __name__ == "__main__":
    main()
