#!/usr/bin/env bash
set -euo pipefail

cd ~/research/projects/v2x-multiuav-trust

ROOT="results/patched_sensitive_ablation_smoke"
rm -rf "$ROOT"
mkdir -p "$ROOT"

SEEDS="${SEEDS:-1 2 3 4 5}"

run_one () {
  local exp="$1"
  local mode="$2"
  local seed="$3"
  local disable_cusum="$4"
  local x0="$5"
  local x1="$6"
  local simtime="$7"

  local outdir="$ROOT/$exp"
  mkdir -p "$outdir"

  local logfile="$outdir/${mode}_seed${seed}_x${x0}_${x1}_t${simtime}_cusum${disable_cusum}.log"

  echo "===== RUN exp=$exp mode=$mode seed=$seed disable_cusum=$disable_cusum x=$x0-$x1 t=$simtime ====="

  env \
    NCARS=10 \
    ATTACK_RATE=50 \
    ATTACK_TYPE=5 \
    SEED="$seed" \
    MODE="$mode" \
    SIMTIME="$simtime" \
    ATTACK_X0="$x0" \
    ATTACK_X1="$x1" \
    PKT_DROP_RATE=0 \
    HTD_DISCOUNT=0.30 \
    DISABLE_CUSUM="$disable_cusum" \
    CUSUM_H=0.8 \
    CUSUM_MIN_OBS=3 \
    CUSUM_EDGE_MAX=0.50 \
    VEREMI_EVIDENCE_ENABLE=1 \
    VEREMI_MODE=shadow \
    VEREMI_GATE=0.12 \
    VEREMI_SPEED_TOL=8.0 \
    VEREMI_POS_TOL=15.0 \
    VEREMI_MAX_GAP=3.0 \
    VEREMI_MIN_VIOLATIONS=2 \
    EDGE_OVERLAP_BAN_GUARD=1 \
    EDGE_OVERLAP_BAN_MIN_P=0.50 \
    CUSUM_INPUT_MODE=veremi \
    timeout --kill-after=30s 1200s \
    bash scripts/run_handover_tunable.sh > "$logfile" 2>&1 || {
      echo "FAILED exp=$exp mode=$mode seed=$seed; see $logfile"
      bash scripts/stop_pipeline_workstation.sh || true
      exit 1
    }

  bash scripts/stop_pipeline_workstation.sh || true
  echo "Saved: $logfile"
}

# Handover-sensitive smoke: uses shorter attack window from dedicated handover ablation
for seed in $SEEDS; do
  run_one "handover_smoke_ON"  "ON"  "$seed" "false" "560" "640" "32"
  run_one "handover_smoke_OFF" "OFF" "$seed" "false" "560" "640" "32"
done

# CUSUM-sensitive smoke: same base attack window, CUSUM ON vs OFF
for seed in $SEEDS; do
  run_one "cusum_smoke_ON"  "ON" "$seed" "false" "560" "720" "36"
  run_one "cusum_smoke_OFF" "ON" "$seed" "true"  "560" "720" "36"
done

echo "PATCHED SENSITIVE ABLATION SMOKE COMPLETE"
