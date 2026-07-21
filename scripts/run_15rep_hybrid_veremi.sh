#!/usr/bin/env bash
set -euo pipefail

ROOT="$HOME/research/projects/v2x-multiuav-trust"
NS3DIR="$ROOT/ns-allinone-3.41/ns-3.41"

MODE="${VEREMI_EVIDENCE_MODE:-replace}"
REPS="${REPS:-15}"
SUMMARY="/tmp/HYBRID15_${MODE}_summary.log"

rm -f "$SUMMARY"

echo "=== HYBRID VeReMi 15-rep study ===" | tee -a "$SUMMARY"
echo "mode=$MODE reps=$REPS date=$(date)" | tee -a "$SUMMARY"
echo | tee -a "$SUMMARY"

for REP in $(seq 1 "$REPS"); do
  LOG="/tmp/HYBRID15_${MODE}_seed1_rep${REP}.log"

  echo "================ REP $REP / $REPS ================" | tee -a "$SUMMARY"

  cd "$ROOT"
  bash scripts/stop_pipeline_workstation.sh || true

  VEREMI_EVIDENCE_ENABLE=1 VEREMI_EVIDENCE_MODE="$MODE" \
    bash scripts/launch_pipeline_workstation_hybrid_veremi.sh

  sleep 10

  cd "$NS3DIR"

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
    2>&1 | tee "$LOG"

  cd "$ROOT"
  bash scripts/stop_pipeline_workstation.sh || true

  python3 - "$LOG" "$REP" << 'PY' | tee -a "$SUMMARY"
import re, sys
from pathlib import Path

log = Path(sys.argv[1])
rep = sys.argv[2]

payoff_re = re.compile(r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)")

mal=caught=hon=fp=0
missed=[]
fps=[]
pairs=[]

for line in log.read_text(errors="ignore").splitlines():
    m = payoff_re.search(line)
    if not m:
        continue
    cid = int(m.group(1))
    demoted = m.group(2) == "YES"
    malicious = m.group(3) == "YES"
    if malicious:
        mal += 1
        caught += int(demoted)
        if not demoted:
            missed.append(cid)
        pairs.append((cid, "YES" if demoted else "NO"))
    else:
        hon += 1
        fp += int(demoted)
        if demoted:
            fps.append(cid)

print(f"REP {rep} caught: {caught}/{mal}  FP: {fp}/{hon}")
print("Missed malicious CIDs:", missed)
print("False-positive honest CIDs:", fps)
print("Sorted malicious CID:demoted pairs:")
for cid, d in sorted(pairs):
    print(f"  {cid}:{d}")
PY

  echo | tee -a "$SUMMARY"
done

python3 - "$MODE" "$REPS" << 'PY' | tee -a "$SUMMARY"
import re, sys, statistics
from pathlib import Path
from collections import defaultdict

mode = sys.argv[1]
reps = int(sys.argv[2])
payoff_re = re.compile(r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)")

caught_list=[]
fp_list=[]
percid=defaultdict(lambda: [0,0])

for rep in range(1, reps+1):
    log = Path(f"/tmp/HYBRID15_{mode}_seed1_rep{rep}.log")
    mal=caught=hon=fp=0
    for line in log.read_text(errors="ignore").splitlines():
        m = payoff_re.search(line)
        if not m:
            continue
        cid = int(m.group(1))
        demoted = m.group(2) == "YES"
        malicious = m.group(3) == "YES"
        if malicious:
            mal += 1
            caught += int(demoted)
            percid[cid][1] += 1
            if demoted:
                percid[cid][0] += 1
        else:
            hon += 1
            fp += int(demoted)
    caught_list.append(caught)
    fp_list.append(fp)

drs = [100*c/19 for c in caught_list]
fprs = [100*f/11 for f in fp_list]

print("\n================ FINAL HYBRID15 SUMMARY ================")
print("Caught counts:", caught_list)
print("FP counts:", fp_list)
print(f"DR mean ± std: {statistics.mean(drs):.2f}% ± {statistics.stdev(drs) if len(drs)>1 else 0:.2f}%")
print(f"FPR mean: {statistics.mean(fprs):.2f}%")
print("\nPer-CID malicious stability:")
for cid in sorted(percid):
    c,t = percid[cid]
    print(f"  CID {cid}: {c}/{t}")
PY

echo
echo "Summary saved to: $SUMMARY"
