#!/usr/bin/env bash
# One command: install every dep, train ALL methods, run them on both benchmark regimes,
# compare, then show the deployed decision pipeline (calibration + conformal DENY/ASK/ALLOW)
# for the winning method. Run from the sift/ directory:
#
#     ./run_bakeoff.sh                 # real static encoder (potion-base-32M, ~30 MB download)
#     ./run_bakeoff.sh hashing         # fully offline, zero downloads
#     ./run_bakeoff.sh minilm          # MiniLM transformer encoder
#
# Nothing is installed into your project env — uv fetches deps into an ephemeral run env.
set -euo pipefail

ENCODER="${1:-model2vec}"
cd "$(dirname "$0")"

# every dependency the 7 methods can need; heavy ones self-skip if a wheel is unavailable.
DEPS=(
  --with numpy
  --with scikit-learn
  --with "model2vec[train]"     # static encoder (methods 1-3,6,7) + trained classifier (method 5)
  --with sentence-transformers  # MiniLM encoder + SetFit base
  --with datasets
  --with accelerate
)

echo "════════════════════════════════════════════════════════════════════"
echo " sift bake-off  ·  encoder=${ENCODER}"
echo "════════════════════════════════════════════════════════════════════"

echo
echo "── [1/2] train all methods + benchmark (in-distribution vs shift/adversarial) ──"
uv run --no-project "${DEPS[@]}" python train_all.py \
    --encoder "${ENCODER}" --out "reports/bakeoff_${ENCODER}.json"

echo
echo "── [2/2] deploy the winner: calibrate + conformal DENY/ASK/ALLOW bands ──"
uv run --no-project "${DEPS[@]}" python eval_all.py \
    --method fusion --encoder "${ENCODER}"

echo
echo "Done. Full comparison JSON → reports/bakeoff_${ENCODER}.json"
