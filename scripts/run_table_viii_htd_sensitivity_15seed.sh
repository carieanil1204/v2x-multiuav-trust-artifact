#!/usr/bin/env bash
set -euo pipefail
# Reproduces paper Table VIII (HTD Sensitivity). Thin sweep wrapper around
# scripts/run_handover_tunable.sh, varying HTD_DISCOUNT (delta) over the
# same 5 values as the printed table, holding the rest of the "final
# locked" config fixed. Same underlying driver, same fixed parameters, as
# scripts/run_attack_type_robustness_15seed.sh (which reproduces Table X)
# -- confirmed by the matching results/htd_sensitivity_guarded_cusum_HTD*
# log directories and CUSUM_H08_MINOBS3_EDGEMAX05_15SEED_SUMMARY.txt
# source path already on disk.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

DELTAS="${DELTAS:-0.10 0.30 0.50 0.70 1.00}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"

NCARS="${NCARS:-10}"
ATTACK_TYPE="${ATTACK_TYPE:-5}"
ATTACK_RATE="${ATTACK_RATE:-50}"
PKT_DROP_RATE="${PKT_DROP_RATE:-0}"
SIMTIME="${SIMTIME:-36}"
ATTACK_X0="${ATTACK_X0:-560}"
ATTACK_X1="${ATTACK_X1:-720}"

# Final locked proposed-system settings (same as Table X / Table XII / etc.)
CUSUM_H="${CUSUM_H:-0.8}"
CUSUM_MIN_OBS="${CUSUM_MIN_OBS:-3}"
CUSUM_EDGE_MAX="${CUSUM_EDGE_MAX:-0.50}"
VEREMI_MODE="${VEREMI_MODE:-shadow}"
VEREMI_GATE="${VEREMI_GATE:-0}"
CUSUM_INPUT_MODE="${CUSUM_INPUT_MODE:-veremi}"

MODE="${MODE:-ON}"
DISABLE="${DISABLE:-false}"
DISABLE_CUSUM="${DISABLE_CUSUM:-false}"

for DELTA in $DELTAS; do
  OUTDIR="$PROJECT_ROOT/results/htd_sensitivity_guarded_cusum_HTD${DELTA}_15seed"
  mkdir -p "$OUTDIR"

  for SEED in $SEEDS; do
    LOGFILE="$OUTDIR/${MODE}_seed${SEED}_x${ATTACK_X0}_${ATTACK_X1}_t${SIMTIME}.log"
    if [[ -s "$LOGFILE" ]] && grep -q "\[PAYOFF\]" "$LOGFILE"; then
      echo "[SKIP] DELTA=$DELTA SEED=$SEED existing complete log: $LOGFILE"
      continue
    fi

    echo ""
    echo "===== RUN DELTA=$DELTA SEED=$SEED ====="

    ATTACK_TYPE="$ATTACK_TYPE" \
    NCARS="$NCARS" \
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
    HTD_DISCOUNT="$DELTA" \
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
echo "All HTD sensitivity runs completed."
