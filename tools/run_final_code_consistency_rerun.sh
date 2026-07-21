#!/usr/bin/env bash
set -euo pipefail

cd ~/research/projects/v2x-multiuav-trust

ROOT="results/final_code_consistency_rerun"
mkdir -p "$ROOT"

COMMON_ENV="
NCARS=10
ATTACK_TYPE=5
SIMTIME=36
ATTACK_X0=560
ATTACK_X1=720
HTD_DISCOUNT=0.30
CUSUM_H=0.8
CUSUM_MIN_OBS=3
CUSUM_EDGE_MAX=0.50
VEREMI_EVIDENCE_ENABLE=1
VEREMI_MODE=hard_only
VEREMI_GATE=0.12
VEREMI_SPEED_TOL=6.0
VEREMI_POS_TOL=15.0
VEREMI_MAX_GAP=3.0
VEREMI_MIN_VIOLATIONS=2
EDGE_OVERLAP_BAN_GUARD=1
EDGE_OVERLAP_BAN_MIN_P=0.50
CUSUM_INPUT_MODE=veremi
"

run_one () {
  local exp="$1"
  local mode="$2"
  local seed="$3"
  local attack_rate="$4"
  local drop="$5"
  local disable_handover="$6"
  local disable_cusum="$7"
  local x0="$8"
  local x1="$9"

  local outdir="$ROOT/$exp"
  mkdir -p "$outdir"

  local logfile="$outdir/${mode}_seed${seed}_drop${drop}_x${x0}_${x1}_t36.log"

  echo "===== RUN exp=$exp mode=$mode seed=$seed attack_rate=$attack_rate drop=$drop disable_handover=$disable_handover disable_cusum=$disable_cusum ====="

  env \
    NCARS=10 \
    ATTACK_RATE="$attack_rate" \
    ATTACK_TYPE=5 \
    SEED="$seed" \
    SIMTIME=36 \
    ATTACK_X0="$x0" \
    ATTACK_X1="$x1" \
    PKT_DROP_RATE="$drop" \
    MODE="$mode" \
    DISABLE="$disable_handover" \
    DISABLE_CUSUM="$disable_cusum" \
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
    EDGE_OVERLAP_BAN_GUARD=1 \
    EDGE_OVERLAP_BAN_MIN_P=0.50 \
    CUSUM_INPUT_MODE=veremi \
    timeout --kill-after=30s 1200s \
    bash scripts/run_handover_tunable.sh > "$logfile" 2>&1 || {
      echo "FAILED exp=$exp mode=$mode seed=$seed drop=$drop; see $logfile"
      bash scripts/stop_pipeline_workstation.sh || true
      exit 1
    }

  bash scripts/stop_pipeline_workstation.sh || true
  echo "Saved consistency log: $logfile"
}

# 1. Clean safety: no malicious vehicles
for seed in $(seq 1 15); do
  run_one "clean_safety_final_patch" "ON" "$seed" "0" "0" "0" "0" "-1" "-1"
done

# 2. Packet-loss robustness: DROP0/5/10/20
for drop in 0 5 10 20; do
  for seed in $(seq 1 15); do
    run_one "packet_loss_final_patch_DROP${drop}" "ON" "$seed" "50" "$drop" "0" "0" "560" "720"
  done
done

# 3. Handover ON/OFF
for mode in ON OFF; do
  if [[ "$mode" == "ON" ]]; then
    disable=0
  else
    disable=1
  fi

  for seed in $(seq 1 15); do
    run_one "handover_final_patch_${mode}" "$mode" "$seed" "50" "0" "$disable" "0" "560" "720"
  done
done

# 4. Guarded CUSUM ON/OFF
for cusum in ON OFF; do
  if [[ "$cusum" == "ON" ]]; then
    disable_cusum=0
  else
    disable_cusum=1
  fi

  for seed in $(seq 1 15); do
    run_one "cusum_final_patch_${cusum}" "ON" "$seed" "50" "0" "0" "$disable_cusum" "560" "720"
  done
done

echo "ALL FINAL-CODE CONSISTENCY RERUNS COMPLETE"
