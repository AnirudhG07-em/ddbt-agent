#!/usr/bin/env bash
# One command: train ALL methods and evaluate them on the three REAL benchmarks
# (R-Judge, InjecAgent ds+dh, MCPTox), in-distribution + adversarial-shift, and print a
# method × benchmark comparison. Run from the sift/ directory:
#
#     ./run_benches.sh                 # real static encoder (potion-base-32M, ~30 MB download)
#     ./run_benches.sh hashing         # fully offline, zero downloads
#     ./run_benches.sh minilm          # MiniLM transformer encoder
#
# Reads bench/data/{rjudge,injecagent,mcptox} from the parent ddbt-agent repo.
set -euo pipefail

ENCODER="${1:-model2vec}"
cd "$(dirname "$0")"

DEPS=(
  --with numpy
  --with scikit-learn
  --with "model2vec[train]"
  --with sentence-transformers
  --with datasets
  --with accelerate
)

echo "════════════════════════════════════════════════════════════════════"
echo " sift on the 3 real benchmarks  ·  encoder=${ENCODER}"
echo "════════════════════════════════════════════════════════════════════"

uv run --no-project "${DEPS[@]}" python -u bench_bakeoff.py \
    --encoder "${ENCODER}" --out "reports/benches_${ENCODER}.json" "${@:2}"

echo
echo "Done. Full comparison JSON → reports/benches_${ENCODER}.json"
echo "Compare against ddbt's LLM judge: R-Judge F1 91.5% · InjecAgent 100% · MCPTox 99.8%"
