#!/usr/bin/env bash

cd ~/research/projects/v2x-multiuav-trust

TS=$(date +%Y%m%d_%H%M%S)
OUT=results/full_veremi_n30_type5_$TS
mkdir -p "$OUT"

echo "Saving results to: $OUT"
echo "$OUT" > /tmp/latest_full_veremi_n30_type5_dir.txt

for SEED in 1 2 3 4 5; do
  echo "=================================================="
  echo "Running N=30 full VeReMi passive validation seed $SEED"
  echo "=================================================="

  bash scripts/stop_pipeline_workstation.sh || true
  sleep 2
  bash scripts/launch_pipeline_workstation.sh
  sleep 10

  cd ~/research/projects/v2x-multiuav-trust/ns-allinone-3.41/ns-3.41

  ./ns3 run "unified_v91_multiuav_handover_defense \
    --nCars=30 --attackRate=50 --attackType=5 --RngRun=$SEED \
    --PktDropRate=1 --EdgeAddr=127.0.0.1 --EdgePort=9998 \
    --EdgePortZ2=9996 --InternalCloud=0 --CloudAddr=127.0.0.1 \
    --CloudPort=6666 --simTime=210 --nUAVs=2 \
    --ZoneLength=1800.0 --ZoneOverlapM=200.0 --HandoverLeadM=400.0 \
    --CoordAddr=127.0.0.1 --CoordPort=9997 \
    --DisableHandover=false --DisableCUSUM=false \
    --CusumMu0=0.20 --CusumH=2.5 --CusumWarmupK=5 \
    --PostHandoverProbationPkts=10 --PostHandoverCreditFactor=0.15 \
    --PostHandoverDisableUpgrade=1" \
    2>&1 | tee ~/research/projects/v2x-multiuav-trust/$OUT/ns3_seed_${SEED}.log

  cd ~/research/projects/v2x-multiuav-trust

  echo "Completed seed $SEED" | tee -a "$OUT/progress.log"
  grep "\[PAYOFF\]" "$OUT/ns3_seed_${SEED}.log" | tee -a "$OUT/payoff_summary.log"
done

bash scripts/stop_pipeline_workstation.sh || true

echo "DONE. Saved to: $OUT"
