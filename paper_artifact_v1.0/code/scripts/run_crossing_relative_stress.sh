#!/usr/bin/env bash
set -euo pipefail

# [OPTION-C] "Handover-crossing-relative attack" test.
#
# Separate, additional test from scripts/run_handover_tunable.sh (which stays
# untouched and remains the labeled "trust-then-defect stress test" at its
# original attackType=5 / AttackStartX=560-640 config).
#
# Here, each malicious car's attack window is anchored to ITS OWN predicted
# handover-crossing time (computed in the .cc from that car's startX and a
# held-constant SpeedNormal), not a shared global X-window. This guarantees
# "car is mid-detection at the handover boundary" by construction instead of
# relying on attack-window/trigger/sim-end geometry lining up by luck.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SEED="${SEED:-1}"
NCARS="${NCARS:-10}"
ATTACK_RATE="${ATTACK_RATE:-50}"
ATTACK_TYPE="${ATTACK_TYPE:-5}"

ZONE_LENGTH="${ZONE_LENGTH:-900.0}"
HANDOVER_LEAD="${HANDOVER_LEAD:-300.0}"
SIMTIME="${SIMTIME:-40}"

HTD_DISCOUNT="${HTD_DISCOUNT:-0.30}"
PKT_DROP_RATE="${PKT_DROP_RATE:-1}"
VEREMI_MODE="${VEREMI_MODE:-guarded}"
CUSUM_INPUT_MODE="${CUSUM_INPUT_MODE:-edge}"
VEREMI_GATE="${VEREMI_GATE:-0.10}"
CUSUM_MU0="${CUSUM_MU0:-0.20}"
CUSUM_H="${CUSUM_H:-2.5}"
CUSUM_WARMUP="${CUSUM_WARMUP:-5}"
CUSUM_MIN_OBS="${CUSUM_MIN_OBS:-15}"
CUSUM_EDGE_MAX="${CUSUM_EDGE_MAX:-1.0}"
DISABLE_CUSUM="${DISABLE_CUSUM:-false}"

# [OPTION-C] crossing-relative attack window params
ATTACK_CROSSING_OFFSET_SEC="${ATTACK_CROSSING_OFFSET_SEC:--1.0}"   # start N sec before predicted crossing; -1.0 validated 2026-09-03 (1-seed checkpoint, see CLAUDE.md)
ATTACK_CROSSING_DURATION_SEC="${ATTACK_CROSSING_DURATION_SEC:-6.0}" # window length in seconds

MODE="${MODE:-ON}"
if [ "$MODE" = "ON" ]; then
  DISABLE=false
elif [ "$MODE" = "OFF" ]; then
  DISABLE=true
else
  echo "MODE must be ON or OFF"
  exit 1
fi

OUTDIR="${OUTDIR:-results/crossing_relative_stress_$(date +%Y%m%d_%H%M%S)}"
if [[ "$OUTDIR" != /* ]]; then
  OUTDIR="$PROJECT_ROOT/$OUTDIR"
fi
mkdir -p "$OUTDIR"

echo "PROJECT_ROOT=$PROJECT_ROOT"
echo "MODE=$MODE"
echo "SEED=$SEED"
echo "NCARS=$NCARS"
echo "ATTACK_RATE=$ATTACK_RATE"
echo "ATTACK_TYPE=$ATTACK_TYPE"
echo "ZONE_LENGTH=$ZONE_LENGTH"
echo "HANDOVER_LEAD=$HANDOVER_LEAD"
echo "SIMTIME=$SIMTIME"
echo "ATTACK_CROSSING_OFFSET_SEC=$ATTACK_CROSSING_OFFSET_SEC"
echo "ATTACK_CROSSING_DURATION_SEC=$ATTACK_CROSSING_DURATION_SEC"
echo "OUTDIR=$OUTDIR"

cd "$PROJECT_ROOT"
bash scripts/stop_pipeline_workstation.sh || true

VEREMI_EVIDENCE_ENABLE=${VEREMI_EVIDENCE_ENABLE:-1} VEREMI_EVIDENCE_MODE=$VEREMI_MODE VEREMI_SOFT_OLDP_GATE=$VEREMI_GATE CUSUM_INPUT_MODE=$CUSUM_INPUT_MODE \
  bash scripts/launch_pipeline_workstation_hybrid_veremi.sh

sleep 10

cd "$PROJECT_ROOT/ns-allinone-3.41/ns-3.41"

LOGFILE="$OUTDIR/${MODE}_seed${SEED}_crossrel.log"

./ns3 run "unified_v91_multiuav_handover_defense \
  --nCars=$NCARS --attackRate=$ATTACK_RATE --attackType=$ATTACK_TYPE --RngRun=$SEED \
  --AttackStartTime=999 --AttackEndTime=-1 --AttackStartX=-1 --AttackEndX=-1 \
  --AttackCrossingRelative=1 \
  --AttackCrossingOffsetSec=$ATTACK_CROSSING_OFFSET_SEC \
  --AttackCrossingDurationSec=$ATTACK_CROSSING_DURATION_SEC \
  --DisableSpeedPhases=1 \
  --PktDropRate=$PKT_DROP_RATE --EdgeAddr=127.0.0.1 --EdgePort=9998 \
  --EdgePortZ2=9996 --InternalCloud=0 --CloudAddr=127.0.0.1 \
  --CloudPort=6666 --simTime=$SIMTIME --nUAVs=2 \
  --ZoneLength=$ZONE_LENGTH --HTDZoneBoundary=$ZONE_LENGTH \
  --ZoneOverlapM=200.0 --HandoverLeadM=$HANDOVER_LEAD \
  --CoordAddr=127.0.0.1 --CoordPort=9997 \
  --DisableHandover=$DISABLE --DisableCUSUM=$DISABLE_CUSUM \
  --HandoverTrustDiscount=$HTD_DISCOUNT \
  --CusumMu0=$CUSUM_MU0 --CusumH=$CUSUM_H --CusumWarmupK=$CUSUM_WARMUP --CusumMinObsBeforeBan=$CUSUM_MIN_OBS --CusumEdgeMaxForBan=$CUSUM_EDGE_MAX \
  --PostHandoverProbationPkts=10 --PostHandoverCreditFactor=0.15 \
  --PostHandoverDisableUpgrade=1" \
  2>&1 | tee "$LOGFILE"

cd "$PROJECT_ROOT"
bash scripts/stop_pipeline_workstation.sh || true

echo "Saved log: $LOGFILE"
