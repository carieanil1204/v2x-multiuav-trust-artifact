#!/usr/bin/env bash
set -euo pipefail

DROPS="${DROPS:-0 10 20}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"

OUTBASE="results/clean_safety_speedtol6_drops_15seed"
mkdir -p "$OUTBASE"

echo "===== CLEAN SAFETY SPEED_TOL=6 ====="
echo "DROPS=$DROPS"
echo "SEEDS=$SEEDS"
echo "===================================="

for DROP in $DROPS; do
  OUTDIR="$OUTBASE/DROP${DROP}"
  mkdir -p "$OUTDIR"

  for SEED in $SEEDS; do
    LOG="$OUTDIR/ON_seed${SEED}_clean_DROP${DROP}_speedtol6.log"

    if [[ -f "$LOG" ]] && grep -q "SIMULATION COMPLETE" "$LOG"; then
      echo "[SKIP] DROP=$DROP SEED=$SEED existing complete log"
      continue
    fi

    echo ""
    echo "===== CLEAN SPEED_TOL=6 DROP=$DROP SEED=$SEED ====="

    NCARS=10 \
    ATTACK_RATE=0 \
    ATTACK_TYPE=5 \
    ATTACK_X0=-1 \
    ATTACK_X1=-1 \
    SIMTIME=36 \
    PKT_DROP_RATE=$DROP \
    HTD_DISCOUNT=0.30 \
    CUSUM_H=0.8 \
    CUSUM_MIN_OBS=3 \
    CUSUM_EDGE_MAX=0.50 \
    VEREMI_EVIDENCE_ENABLE=1 \
    VEREMI_MODE=hard_only \
    VEREMI_GATE=0.12 \
    VEREMI_SPEED_TOL=6.0 \
    VEREMI_POS_TOL=15.0 \
    VEREMI_MAX_GAP=3.0 \
    VEREMI_MIN_VIOLATIONS=2 \
    CUSUM_INPUT_MODE=veremi \
    SEEDS="$SEED" \
    bash scripts/run_handover_tunable.sh | tee "$LOG"

    bash scripts/stop_pipeline_workstation.sh || true
    sleep 2
  done
done

echo "All clean safety speedtol6 runs completed."
