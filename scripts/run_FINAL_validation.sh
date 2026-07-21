#!/usr/bin/env bash
set -uo pipefail

cd ~/research/projects/v2x-multiuav-trust/ns-allinone-3.41/ns-3.41

for REP in 1 2 3 4 5; do
  bash ~/research/projects/v2x-multiuav-trust/scripts/stop_pipeline_workstation.sh || true
  sleep 2
  bash ~/research/projects/v2x-multiuav-trust/scripts/launch_pipeline_workstation.sh
  sleep 10
  ./ns3 run "unified_v91_multiuav_handover_defense \
    --nCars=30 --attackRate=50 --attackType=5 --RngRun=1 \
    --PktDropRate=1 --EdgeAddr=127.0.0.1 --EdgePort=9998 \
    --EdgePortZ2=9996 --InternalCloud=0 --CloudAddr=127.0.0.1 \
    --CloudPort=6666 --simTime=210 --nUAVs=2 \
    --ZoneLength=1800.0 --ZoneOverlapM=200.0 --HandoverLeadM=400.0 \
    --CoordAddr=127.0.0.1 --CoordPort=9997 \
    --DisableHandover=false --DisableCUSUM=false \
    --CusumMu0=0.20 --CusumH=2.5 --CusumWarmupK=5 \
    --PostHandoverProbationPkts=10 --PostHandoverCreditFactor=0.15 \
    --PostHandoverDisableUpgrade=1" \
    2>&1 | tee /tmp/FINAL_seed1_rep${REP}.log

  caught=$(grep "\[PAYOFF\]" /tmp/FINAL_seed1_rep${REP}.log | grep "malicious=YES" | grep -c "demoted=YES")
  total=$(grep "\[PAYOFF\]" /tmp/FINAL_seed1_rep${REP}.log | grep -c "malicious=YES")
  echo "REP $REP: $caught / $total caught" | tee -a /tmp/FINAL_summary.log
done

bash ~/research/projects/v2x-multiuav-trust/scripts/stop_pipeline_workstation.sh || true
echo "ALL DONE" | tee -a /tmp/FINAL_summary.log
