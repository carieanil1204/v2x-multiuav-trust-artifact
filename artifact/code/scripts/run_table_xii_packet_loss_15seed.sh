#!/usr/bin/env bash
set -euo pipefail
# Reproduces paper Table XII (Packet-Loss Robustness). Same driver/pattern
# as Table VIII, sweeping PKT_DROP_RATE (as a percentage, per
# run_handover_tunable.sh's own convention) over the paper's 4 values.
# Result directory names match existing on-disk
# results/packet_loss_robustness_DROP{0,5,10,20}_guarded_cusum_15seed/.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

DROPS="${DROPS:-0 5 10 20}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"

NCARS="${NCARS:-10}"
ATTACK_TYPE="${ATTACK_TYPE:-5}"
ATTACK_RATE="${ATTACK_RATE:-50}"
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

for DROP in $DROPS; do
  OUTDIR="$PROJECT_ROOT/results/packet_loss_robustness_DROP${DROP}_guarded_cusum_15seed"
  mkdir -p "$OUTDIR"

  for SEED in $SEEDS; do
    LOGFILE="$OUTDIR/${MODE}_seed${SEED}_x${ATTACK_X0}_${ATTACK_X1}_t${SIMTIME}.log"
    if [[ -s "$LOGFILE" ]] && grep -q "\[PAYOFF\]" "$LOGFILE"; then
      echo "[SKIP] DROP=$DROP SEED=$SEED existing complete log: $LOGFILE"
      continue
    fi

    echo ""
    echo "===== RUN PKT_DROP_RATE=$DROP SEED=$SEED ====="

    ATTACK_TYPE="$ATTACK_TYPE" \
    NCARS="$NCARS" \
    ATTACK_RATE="$ATTACK_RATE" \
    PKT_DROP_RATE="$DROP" \
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
echo "All packet-loss robustness runs completed."
