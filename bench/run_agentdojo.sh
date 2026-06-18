#!/usr/bin/env bash
#
# Run the AgentDojo benchmark through ddbt. Default MODE=vuln runs the vulnerability
# DELTA per suite: baseline → find pairs the undefended agent gets hijacked on → re-run
# ONLY those with ddbt. That isolates ddbt's value to the cases that matter.
#
# Usage:
#   bash bench/run_agentdojo.sh                          # all suites, vuln-delta
#   SUITES="slack banking" bash bench/run_agentdojo.sh   # pick suites (these have higher baseline ASR)
#   LIMIT=12 bash bench/run_agentdojo.sh                 # more user tasks → more vulnerable pairs found
#   MODE=full bash bench/run_agentdojo.sh                # baseline + defended over the whole slice
#
# Cost note: vuln mode runs baseline over (LIMIT × all injections), then defended only on
# the hijacked subset, so cost scales with how often the model takes the bait.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# --- config (override via env) ---
SUITES="${SUITES:-workspace banking slack travel}"
MODEL="${MODEL:-claude-haiku-4-5}"
MODE="${MODE:-vuln}"          # "vuln" (delta) | "full" (baseline + defended)
LIMIT="${LIMIT:-8}"           # user tasks per suite (empty = all)
INJ_LIMIT="${INJ_LIMIT:-}"   # injection tasks per user task (empty = all)

# --- load the Anthropic key from .env (not printed) ---
if [[ -f .env ]]; then set -a; . ./.env; set +a; fi
if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "ERROR: ANTHROPIC_API_KEY not set (put it in .env or export it)." >&2
  exit 1
fi

export _ZO_DOCTOR=0 UV_LINK_MODE=copy
export DDBT_HOME="$REPO/.ddbt"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$REPO/bench/results/$STAMP"
mkdir -p "$OUTDIR"
echo "ddbt × AgentDojo | mode=$MODE model=$MODEL suites=[$SUITES] limit=${LIMIT:-all} inj=${INJ_LIMIT:-all}"
echo "logs → $OUTDIR"

# optional limit flags
LIMFLAGS=()
[[ -n "$LIMIT" ]]     && LIMFLAGS+=(--limit "$LIMIT")
[[ -n "$INJ_LIMIT" ]] && LIMFLAGS+=(--inj-limit "$INJ_LIMIT")

NOISE='zoxide|ajeetdsouza|Please ensure|Disable this|consider filing|^https|Building|Built|Uninstalled|Installed|warning:|reflink|UV_LINK|degraded|intentional|Not all injection'

run_ddbt() {  # extra args... → run + de-noise + tee
  uv run ddbt bench agentdojo --suite "$1" --model "$MODEL" "${LIMFLAGS[@]}" "${@:2}" 2>&1 \
    | grep -vE "$NOISE"
}

for suite in $SUITES; do
  echo "================================================================ $suite"
  if [[ "$MODE" == "vuln" ]]; then
    run_ddbt "$suite" --only-vulnerable | tee "$OUTDIR/${suite}_vuln.log" || echo "  ($suite failed)"
  else
    run_ddbt "$suite" --no-defense | tee "$OUTDIR/${suite}_baseline.log" || echo "  ($suite baseline failed)"
    run_ddbt "$suite"              | tee "$OUTDIR/${suite}_defended.log" || echo "  ($suite defended failed)"
  fi
done

# --- combined summary ---
SUMMARY="$OUTDIR/SUMMARY.txt"
{
  echo "ddbt × AgentDojo summary — $STAMP — mode=$MODE model=$MODEL"
  echo
  for f in "$OUTDIR"/*.log; do
    echo "## $(basename "$f" .log)"
    grep -E "baseline|vulnerable|ASR|neutralised|ddbt blocks|utility|cases" "$f" || echo "  (no result — see log)"
    echo
  done
} | tee "$SUMMARY"

echo "Done. Summary: $SUMMARY"
