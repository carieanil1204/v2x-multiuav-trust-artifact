#!/usr/bin/env bash
set -euo pipefail
# Reproduces paper Table XI (Beacon Falsification Probability / attack-rate
# robustness). Same driver/pattern as Table VIII, sweeping ATTACK_RATE over
# the paper's 4 values. Confirmed against
# ATTACK_RATE_ROBUSTNESS_EXTENDED_GUARDED_CUSUM_15SEED_SUMMARY.txt source
# path already recorded in results/final_locked_csv/.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

RATES="${RATES:-20 50 70 80}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"

NCARS="${NCARS:-10}"
ATTACK_TYPE="${ATTACK_TYPE:-5}"
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

for RATE in $RATES; do
  OUTDIR="$PROJECT_ROOT/results/attack_rate_robustness_AR${RATE}_guarded_cusum_15seed"
  mkdir -p "$OUTDIR"

  for SEED in $SEEDS; do
    LOGFILE="$OUTDIR/${MODE}_seed${SEED}_x${ATTACK_X0}_${ATTACK_X1}_t${SIMTIME}.log"
    if [[ -s "$LOGFILE" ]] && grep -q "\[PAYOFF\]" "$LOGFILE"; then
      echo "[SKIP] RATE=$RATE SEED=$SEED existing complete log: $LOGFILE"
      continue
    fi

    echo ""
    echo "===== RUN ATTACK_RATE=$RATE SEED=$SEED ====="

    ATTACK_TYPE="$ATTACK_TYPE" \
    NCARS="$NCARS" \
    ATTACK_RATE="$RATE" \
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
  done
done

echo ""
echo "All beacon falsification probability runs completed."
