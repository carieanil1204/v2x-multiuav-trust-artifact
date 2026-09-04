#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$HOME/research/projects/v2x-multiuav-trust"
cd "$PROJECT_ROOT"

ATTACK_TYPES="${ATTACK_TYPES:-1 2 3 4}"
DROPS="${DROPS:-0 10 20}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"

NCARS="${NCARS:-10}"
ATTACK_RATE="${ATTACK_RATE:-50}"
SIMTIME="${SIMTIME:-36}"
ATTACK_X0="${ATTACK_X0:-560}"
ATTACK_X1="${ATTACK_X1:-720}"

# Final locked proposed-system settings
HTD_DISCOUNT="${HTD_DISCOUNT:-0.30}"
CUSUM_H="${CUSUM_H:-0.8}"
CUSUM_MIN_OBS="${CUSUM_MIN_OBS:-3}"
CUSUM_EDGE_MAX="${CUSUM_EDGE_MAX:-0.50}"

# Keep final guarded CUSUM / VeReMi settings
VEREMI_MODE="${VEREMI_MODE:-shadow}"
VEREMI_GATE="${VEREMI_GATE:-0}"
CUSUM_INPUT_MODE="${CUSUM_INPUT_MODE:-veremi}"

MODE="${MODE:-ON}"
DISABLE="${DISABLE:-0}"
DISABLE_CUSUM="${DISABLE_CUSUM:-0}"

echo "===== ATTACK TYPE ROBUSTNESS RUN ====="
echo "ATTACK_TYPES=$ATTACK_TYPES"
echo "DROPS=$DROPS"
echo "SEEDS=$SEEDS"
echo "NCARS=$NCARS ATTACK_RATE=$ATTACK_RATE SIMTIME=$SIMTIME"
echo "ATTACK_X0=$ATTACK_X0 ATTACK_X1=$ATTACK_X1"
echo "HTD_DISCOUNT=$HTD_DISCOUNT CUSUM_H=$CUSUM_H CUSUM_MIN_OBS=$CUSUM_MIN_OBS CUSUM_EDGE_MAX=$CUSUM_EDGE_MAX"
echo "======================================"

for AT in $ATTACK_TYPES; do
  for DROP in $DROPS; do
    OUTDIR="$PROJECT_ROOT/results/attack_type_robustness_AT${AT}_DROP${DROP}_guarded_cusum_15seed"
    mkdir -p "$OUTDIR"

    for SEED in $SEEDS; do
      LOGFILE="$OUTDIR/ON_seed${SEED}_x${ATTACK_X0}_${ATTACK_X1}_t${SIMTIME}.log"

      if [[ -s "$LOGFILE" ]] && grep -q "\[PAYOFF\]" "$LOGFILE"; then
        echo "[SKIP] AT=$AT DROP=$DROP SEED=$SEED existing complete log: $LOGFILE"
        continue
      fi

      echo ""
      echo "===== RUN AT=$AT DROP=$DROP SEED=$SEED ====="

      ATTACK_TYPE="$AT" \
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
done

echo ""
echo "All attack-type robustness runs completed."
