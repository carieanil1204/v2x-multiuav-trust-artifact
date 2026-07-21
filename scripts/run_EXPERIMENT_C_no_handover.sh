#!/usr/bin/env bash
set -uo pipefail

cd ~/research/projects/v2x-multiuav-trust/ns-allinone-3.41/ns-3.41

for REP in $(seq 1 15); do
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
    --DisableHandover=true --DisableCUSUM=false \
    --CusumMu0=0.20 --CusumH=2.5 --CusumWarmupK=5 \
    --PostHandoverProbationPkts=10 --PostHandoverCreditFactor=0.15 \
    --PostHandoverDisableUpgrade=1" \
    2>&1 | tee /tmp/EXPC_seed1_rep${REP}.log

  echo "=== REP $REP: sorted CID:demoted pairs (no-handover) ===" | tee -a /tmp/EXPC_summary.log
  grep "\[PAYOFF\]" /tmp/EXPC_seed1_rep${REP}.log | grep "malicious=YES" \
    | sed -E 's/.*CID:([0-9]+).*demoted=([A-Z]+).*/\1:\2/' | sort -n | tee -a /tmp/EXPC_summary.log
  caught=$(grep "\[PAYOFF\]" /tmp/EXPC_seed1_rep${REP}.log | grep "malicious=YES" | grep -c "demoted=YES")
  fp=$(grep "\[PAYOFF\]" /tmp/EXPC_seed1_rep${REP}.log | grep "malicious=NO" | grep -c "demoted=YES")
  echo "REP $REP: caught=$caught/19  FP=$fp/11" | tee -a /tmp/EXPC_summary.log
  echo "REP,$REP,$caught,$fp" >> /tmp/EXPC_counts.csv
done

bash ~/research/projects/v2x-multiuav-trust/scripts/stop_pipeline_workstation.sh || true
echo "ALL DONE" | tee -a /tmp/EXPC_summary.log
