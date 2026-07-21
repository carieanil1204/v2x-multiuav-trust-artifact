#!/usr/bin/env bash
set -uo pipefail

ATTACK_TYPES="${ATTACK_TYPES:-0 3 4 5}"
DROP="${DROP:-0}"
SEED="${SEED:-1}"

echo "===== REMAINING ATTACK SMOKE AFTER OVERRIDE ====="
echo "ATTACK_TYPES=$ATTACK_TYPES DROP=$DROP SEED=$SEED"
echo "================================================="

for AT in $ATTACK_TYPES; do
  echo ""
  echo "===== SMOKE AT=$AT DROP=$DROP SEED=$SEED ====="

  rm -rf "results/attack_type_robustness_AT${AT}_DROP${DROP}_guarded_cusum_15seed"

  ATTACK_TYPES="$AT" DROPS="$DROP" SEEDS="$SEED" \
  VEREMI_EVIDENCE_ENABLE=1 \
  VEREMI_MODE=hard_only \
  VEREMI_GATE=0.12 \
  CUSUM_INPUT_MODE=veremi \
  timeout --kill-after=30s 1200s \
  bash scripts/run_attack_type_robustness_15seed.sh

  status=$?
  echo "AT=$AT exit_status=$status"

  bash scripts/stop_pipeline_workstation.sh || true
  sleep 3
done

echo "All remaining attack smoke tests attempted."
