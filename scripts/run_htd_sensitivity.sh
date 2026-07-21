#!/usr/bin/env bash
# HTD Sensitivity Experiment — delta = 0.1, 0.3, 0.5, 1.0 x seeds 1 and 5
# N=6, simTime=180, attackType=5 — fast runs (~10 min each, 8 total ~90 min)
# set -euo pipefail removed — pipeline commands return non-zero

ROOT=~/research/projects/v2x-multiuav-trust
NS3=$ROOT/ns-allinone-3.41/ns-3.41
OUT=$ROOT/results/htd_sensitivity_$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUT"

echo "HTD sensitivity sweep starting: $(date)" | tee "$OUT/progress.log"
echo "Output: $OUT" | tee -a "$OUT/progress.log"

COMMON="--nCars=6 --attackRate=50 --attackType=5 \
  --PktDropRate=1 --EdgeAddr=127.0.0.1 --EdgePort=9998 \
  --EdgePortZ2=9996 --InternalCloud=0 --CloudAddr=127.0.0.1 \
  --CloudPort=6666 --simTime=180 --nUAVs=2 \
  --ZoneLength=1800.0 --ZoneOverlapM=200.0 --HandoverLeadM=400.0 \
  --CoordAddr=127.0.0.1 --CoordPort=9997 \
  --CusumMu0=0.20 --CusumH=2.5 --CusumWarmupK=5 \
  --PostHandoverProbationPkts=10 --PostHandoverCreditFactor=0.15 \
  --PostHandoverDisableUpgrade=1"

for delta in 0.1 0.3 0.5 1.0; do
  for seed in 1 5; do
    # Skip already completed run
    if [[ "$delta" == "0.1" && "$seed" == "1" ]]; then echo "Skipping delta0.1_seed1 (already done)"; continue; fi
    TAG="delta${delta}_seed${seed}"
    echo "" | tee -a "$OUT/progress.log"
    echo "=== START ${TAG} $(date) ===" | tee -a "$OUT/progress.log"

    # Clean pipeline restart
    bash $ROOT/scripts/stop_pipeline_workstation.sh >> "$OUT/progress.log" 2>&1 || true
    sleep 3
    bash $ROOT/scripts/launch_pipeline_workstation.sh >> "$OUT/progress.log" 2>&1
    sleep 10

    # Run NS3
    cd "$NS3"
    ./ns3 run "unified_v91_multiuav_handover_defense \
      --RngRun=${seed} \
      --HandoverTrustDiscount=${delta} \
      ${COMMON}" \
      > "$OUT/ns3_${TAG}.log" 2>&1

    # Extract payoff
    echo "--- PAYOFF ${TAG} ---" >> "$OUT/payoff_summary.txt"
    grep "\[PAYOFF\]" "$OUT/ns3_${TAG}.log" >> "$OUT/payoff_summary.txt"

    # Quick DR/FPR inline
    mal=$(grep "\[PAYOFF\]" "$OUT/ns3_${TAG}.log" | grep "malicious=YES" | wc -l)
    caught=$(grep "\[PAYOFF\]" "$OUT/ns3_${TAG}.log" | grep "malicious=YES" | grep "demoted=YES" | wc -l)
    hon=$(grep "\[PAYOFF\]" "$OUT/ns3_${TAG}.log" | grep "malicious=NO" | wc -l)
    fp=$(grep "\[PAYOFF\]" "$OUT/ns3_${TAG}.log" | grep "malicious=NO" | grep "demoted=YES" | wc -l)
    echo "  ${TAG}: DR=${caught}/${mal} FP=${fp}/${hon}" | tee -a "$OUT/progress.log"

    cd "$ROOT"
    echo "=== DONE ${TAG} $(date) ===" | tee -a "$OUT/progress.log"
  done
done

echo "" | tee -a "$OUT/progress.log"
echo "=== ALL HTD SENSITIVITY RUNS COMPLETE $(date) ===" | tee -a "$OUT/progress.log"
echo ""
echo "Results in: $OUT"
echo "Summary:"
grep "DR=" "$OUT/progress.log"
