#!/usr/bin/env bash
set -euo pipefail
# Reproduces paper Table IX (Guarded CUSUM Ablation). Same driver/pattern
# as Table VIII's wrapper, toggling DISABLE_CUSUM instead of sweeping a
# parameter. Both ON and OFF conditions share the same locked source path
# (CUSUM_H08_MINOBS3_EDGEMAX05_15SEED_SUMMARY.txt), confirming they were
# generated from the same sweep varying only this one flag.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

CONDITIONS="${CONDITIONS:-ON OFF}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"

NCARS="${NCARS:-10}"
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

for COND in $CONDITIONS; do
  if [ "$COND" = "ON" ]; then DISABLE_CUSUM="false"; else DISABLE_CUSUM="true"; fi
  OUTDIR="$PROJECT_ROOT/results/guarded_cusum_onoff_repro_${COND}_15seed"
  mkdir -p "$OUTDIR"

  for SEED in $SEEDS; do
    LOGFILE="$OUTDIR/${MODE}_seed${SEED}_x${ATTACK_X0}_${ATTACK_X1}_t${SIMTIME}.log"
    if [[ -s "$LOGFILE" ]] && grep -q "\[PAYOFF\]" "$LOGFILE"; then
      echo "[SKIP] COND=$COND SEED=$SEED existing complete log: $LOGFILE"
      continue
    fi

    echo ""
    echo "===== RUN CUSUM_COND=$COND SEED=$SEED ====="

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
echo "All CUSUM ablation runs completed."
