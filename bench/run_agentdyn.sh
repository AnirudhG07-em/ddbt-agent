#!/usr/bin/env bash
#
# Run the AgentDyn benchmark through ddbt. AgentDyn is a hard fork of AgentDojo for
# dynamic, open-ended tasks (suites: shopping/github/dailylife); it drives the SAME harness.
# Default MODE=vuln runs the vulnerability DELTA per suite: baseline → find pairs the
# undefended agent gets hijacked on → re-run ONLY those with ddbt.
#
# Usage:
#   bash bench/run_agentdyn.sh                          # all suites, vuln-delta
#   SUITES="shopping github" bash bench/run_agentdyn.sh # pick suites
#   LIMIT=12 bash bench/run_agentdyn.sh                 # more user tasks → more vulnerable pairs found
#   MODE=full bash bench/run_agentdyn.sh                # baseline + defended over the whole slice
#
# Prereq: AgentDyn must be installed (it REPLACES upstream agentdojo in this env):
#   uv pip install -e ".[agentdyn]"
#
# Cost note: vuln mode runs baseline over (LIMIT × all injections), then defended only on
# the hijacked subset, so cost scales with how often the model takes the bait.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# --- config (override via env) ---
SUITES="${SUITES:-shopping github dailylife}"
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

# --- preflight: confirm the AgentDyn fork (not upstream AgentDojo) is installed ---
if ! uv run --no-sync python -c "from agentdojo.task_suite.load_suites import get_suite; get_suite('v1','shopping')" >/dev/null 2>&1; then
  echo "ERROR: AgentDyn suites not found — the installed 'agentdojo' is upstream, not the fork." >&2
  echo "       Install it (replaces upstream agentdojo in this env):  uv pip install -e \".[agentdyn]\"" >&2
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$REPO/bench/results/$STAMP"
mkdir -p "$OUTDIR"
echo "ddbt × AgentDyn | mode=$MODE model=$MODEL suites=[$SUITES] limit=${LIMIT:-all} inj=${INJ_LIMIT:-all}"
echo "logs → $OUTDIR"

# optional limit flags
LIMFLAGS=()
[[ -n "$LIMIT" ]]     && LIMFLAGS+=(--limit "$LIMIT")
[[ -n "$INJ_LIMIT" ]] && LIMFLAGS+=(--inj-limit "$INJ_LIMIT")

NOISE='zoxide|ajeetdsouza|Please ensure|Disable this|consider filing|^https|Building|Built|Uninstalled|Installed|warning:|reflink|UV_LINK|degraded|intentional|Not all injection'

run_ddbt() {  # extra args... → run + de-noise + tee
  # --no-sync: never reconcile to the lockfile mid-run (that would uninstall the AgentDyn
  # fork, since it's an opt-in extra, and silently restore upstream agentdojo).
  uv run --no-sync ddbt bench agentdyn --suite "$1" --model "$MODEL" "${LIMFLAGS[@]}" "${@:2}" 2>&1 \
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
  echo "ddbt × AgentDyn summary — $STAMP — mode=$MODE model=$MODEL"
  echo
  for f in "$OUTDIR"/*.log; do
    echo "## $(basename "$f" .log)"
    grep -E "baseline|vulnerable|ASR|neutralised|ddbt blocks|utility|cases" "$f" || echo "  (no result — see log)"
    echo
  done
} | tee "$SUMMARY"

echo "Done. Summary: $SUMMARY"
