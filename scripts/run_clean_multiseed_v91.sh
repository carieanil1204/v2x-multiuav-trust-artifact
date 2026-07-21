#!/usr/bin/env bash
set -euo pipefail

ROOT="$HOME/research/projects/v2x-multiuav-trust"
NS3="$ROOT/ns-allinone-3.41/ns-3.41"
OUT="$ROOT/results/clean_multiseed_v91_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUT"

for seed in 1 2 3 4 5
do
  echo "============================================================"
  echo " CLEAN RUN: RngRun=$seed"
  echo "============================================================"

  cd "$ROOT"

  bash scripts/stop_pipeline_workstation.sh || true
  rm -f logs/*.log logs/*.pid
  mkdir -p logs

  bash scripts/launch_pipeline_workstation.sh
  sleep 5

  cd "$NS3"

  ./ns3 run "unified_v91_multiuav_handover_defense \
    --nCars=30 \
    --attackRate=50 \
    --attackType=5 \
    --RngRun=$seed \
    --PktDropRate=1 \
    --EdgeAddr=127.0.0.1 \
    --EdgePort=9998 \
    --EdgePortZ2=9996 \
    --InternalCloud=0 \
    --CloudAddr=127.0.0.1 \
    --CloudPort=6666 \
    --simTime=210 \
    --nUAVs=2 \
    --ZoneLength=1800.0 \
    --ZoneOverlapM=200.0 \
    --HandoverLeadM=400.0 \
    --CoordAddr=127.0.0.1 \
    --CoordPort=9997 \
    --DisableHandover=false \
    --DisableCUSUM=false \
    --CusumMu0=0.20 \
    --CusumH=2.5 \
    --CusumWarmupK=5 \
    --PostHandoverProbationPkts=10 \
    --PostHandoverCreditFactor=0.15 \
    --PostHandoverDisableUpgrade=1" \
    2>&1 | tee "$OUT/ns3_seed_${seed}.log"

  cd "$ROOT"

  cp -f logs/cloud.log "$OUT/cloud_seed_${seed}.log" 2>/dev/null || true
  cp -f logs/edge_z1.log "$OUT/edge_z1_seed_${seed}.log" 2>/dev/null || true
  cp -f logs/edge_z2.log "$OUT/edge_z2_seed_${seed}.log" 2>/dev/null || true
  cp -f logs/bridge_z1.log "$OUT/bridge_z1_seed_${seed}.log" 2>/dev/null || true
  cp -f logs/bridge_z2.log "$OUT/bridge_z2_seed_${seed}.log" 2>/dev/null || true
  cp -f logs/coordinator.log "$OUT/coordinator_seed_${seed}.log" 2>/dev/null || true

  echo "[DONE] Seed $seed logs saved to $OUT"
done

cd "$ROOT"
bash scripts/stop_pipeline_workstation.sh || true

echo
echo "============================================================"
echo " PAYOFF SUMMARY FOR ALL CLEAN SEEDS"
echo "============================================================"
grep -Rni "\[PAYOFF\]" "$OUT"/ns3_seed_*.log | tee "$OUT/payoff_summary.txt"

echo
echo "Saved results in:"
echo "$OUT"
