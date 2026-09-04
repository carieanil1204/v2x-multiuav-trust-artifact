#!/usr/bin/env bash
set -euo pipefail
# Reproduces paper Table XIV (Scalability). Same driver/pattern as
# Table VIII, sweeping NCARS over the paper's 4 vehicle-count values;
# malicious-vehicle ratio is computed internally by the .cc scenario from
# nCars (fixed 70% ratio, per Section V-F of the paper), not a separate
# CLI flag. Also records wall-clock runtime per run for the paper's
# Runtime (s) column.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

VEHICLE_COUNTS="${VEHICLE_COUNTS:-10 20 30 50}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"

ATTACK_TYPE="${ATTACK_TYPE:-5}"
ATTACK_RATE="${ATTACK_RATE:-50}"
PKT_DROP_RATE="${PKT_DROP_RATE:-0}"
SIMTIME="${SIMTIME:-36}"
ATTACK_X0="${ATTACK_X0:-560}"
ATTACK_X1="${ATTACK_X1:-720}"
HTD_DISCOUNT="${HTD_DISCOUNT:-0.30}"

# Final locked proposed-system settings
CUSUM_H="${CUSUM_H:-0.8}"
CUSUM_MIN_OBS="${CUSUM_MIN_OBS:-3}"
CUSUM_EDGE_MAX="${CUSUM_EDGE_MAX:-0.50}"
VEREMI_MODE="${VEREMI_MODE:-shadow}"
VEREMI_GATE="${VEREMI_GATE:-0}"
CUSUM_INPUT_MODE="${CUSUM_INPUT_MODE:-veremi}"

MODE="ON"
DISABLE="false"
DISABLE_CUSUM="false"

for N in $VEHICLE_COUNTS; do
  OUTDIR="$PROJECT_ROOT/results/scalability_N${N}_AR50_guarded_cusum_15seed"
  mkdir -p "$OUTDIR"

  for SEED in $SEEDS; do
    LOGFILE="$OUTDIR/${MODE}_seed${SEED}_x${ATTACK_X0}_${ATTACK_X1}_t${SIMTIME}.log"
    if [[ -s "$LOGFILE" ]] && grep -q "\[PAYOFF\]" "$LOGFILE"; then
      echo "[SKIP] N=$N SEED=$SEED existing complete log: $LOGFILE"
      continue
    fi

    echo ""
    echo "===== RUN NCARS=$N SEED=$SEED ====="
    START_TS=$(date +%s.%N)

    ATTACK_TYPE="$ATTACK_TYPE" \
    NCARS="$N" \
    ATTACK_RATE="$ATTACK_RATE" \
    PKT_DROP_RATE="$PKT_DROP_RATE" \
    SEED="$SEED" \
    SIMTIME="$SIMTIME" \
    ATTACK_X0="$ATTACK_X0" \
    ATTACK_X1="$ATTACK_X1" \
    OUTDIR="$OUTDIR" \
    MODE="$MODE" \
    DISABLE="$DISABLE" \
    DISABLE_CUSUM="$DISABLE_CUSUM" \
    HTD_DISCOUNT="$HTD_DISCOUNT" \
    CUSUM_H="$CUSUM_H" \
    CUSUM_MIN_OBS="$CUSUM_MIN_OBS" \
    CUSUM_EDGE_MAX="$CUSUM_EDGE_MAX" \
    VEREMI_MODE="$VEREMI_MODE" \
    VEREMI_GATE="$VEREMI_GATE" \
    CUSUM_INPUT_MODE="$CUSUM_INPUT_MODE" \
      bash scripts/run_handover_tunable.sh

    END_TS=$(date +%s.%N)
    echo "runtime_seconds=$(python3 -c "print(round($END_TS-$START_TS,2))")" >> "$OUTDIR/${MODE}_seed${SEED}_runtime.txt"
  done
done

echo ""
echo "All scalability runs completed."
