#!/usr/bin/env bash
set -euo pipefail
# Reproduces paper Table XV (Overlap BAN Guard). Same driver/pattern as
# Table VIII, toggling EDGE_OVERLAP_BAN_GUARD (read directly by
# pipeline/edge/edge_ai_server_v91_handover_defense_hybrid_veremi.py,
# default "1") instead of an ns-3 CLI flag. Uses AT5 (adaptive) / DROP20,
# matching the existing on-disk
# results/overlap_guard_ablation_AT5_DROP20_GUARD_{OFF,ON}_15seed naming.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

GUARD_STATES="${GUARD_STATES:-OFF ON}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"

NCARS="${NCARS:-10}"
ATTACK_TYPE="${ATTACK_TYPE:-5}"
ATTACK_RATE="${ATTACK_RATE:-50}"
PKT_DROP_RATE="${PKT_DROP_RATE:-20}"
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

for GSTATE in $GUARD_STATES; do
  if [ "$GSTATE" = "ON" ]; then export EDGE_OVERLAP_BAN_GUARD=1; else export EDGE_OVERLAP_BAN_GUARD=0; fi
  OUTDIR="$PROJECT_ROOT/results/overlap_guard_ablation_AT${ATTACK_TYPE}_DROP${PKT_DROP_RATE}_GUARD_${GSTATE}_15seed"
  mkdir -p "$OUTDIR"

  for SEED in $SEEDS; do
    LOGFILE="$OUTDIR/${MODE}_seed${SEED}_x${ATTACK_X0}_${ATTACK_X1}_t${SIMTIME}.log"
    if [[ -s "$LOGFILE" ]] && grep -q "\[PAYOFF\]" "$LOGFILE"; then
      echo "[SKIP] GUARD=$GSTATE SEED=$SEED existing complete log: $LOGFILE"
      continue
    fi

    echo ""
    echo "===== RUN OVERLAP_GUARD=$GSTATE (EDGE_OVERLAP_BAN_GUARD=$EDGE_OVERLAP_BAN_GUARD) SEED=$SEED ====="

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
    EDGE_OVERLAP_BAN_GUARD="$EDGE_OVERLAP_BAN_GUARD" \
      bash scripts/run_handover_tunable.sh
  done
done

echo ""
echo "All overlap-guard ablation runs completed."
