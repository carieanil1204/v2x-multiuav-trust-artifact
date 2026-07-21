#!/usr/bin/env bash
set -euo pipefail

ROOT="$HOME/research/projects/v2x-multiuav-trust"
NS3DIR="$ROOT/ns-allinone-3.41/ns-3.41"
OUTDIR="$ROOT/results/handover_pilot_guarded_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

REPS="${REPS:-5}"

echo "Output dir: $OUTDIR"
echo "$OUTDIR" > /tmp/handover_pilot_guarded_outdir.txt

for MODE in on off; do
  if [ "$MODE" = "on" ]; then
    DISABLE_HO="false"
  else
    DISABLE_HO="true"
  fi

  SUMMARY="$OUTDIR/summary_${MODE}.log"
  echo "=== Handover pilot mode=$MODE DisableHandover=$DISABLE_HO reps=$REPS ===" | tee "$SUMMARY"

  for REP in $(seq 1 "$REPS"); do
    LOG="$OUTDIR/${MODE}_rep${REP}.log"

    echo "================ $MODE REP $REP / $REPS ================" | tee -a "$SUMMARY"

    cd "$ROOT"
    bash scripts/stop_pipeline_workstation.sh || true

    VEREMI_EVIDENCE_ENABLE=1 \
    VEREMI_EVIDENCE_MODE=guarded \
    VEREMI_SOFT_OLDP_GATE=0.10 \
      bash scripts/launch_pipeline_workstation_hybrid_veremi.sh

    sleep 10

    cd "$NS3DIR"

    ./ns3 run "unified_v91_multiuav_handover_defense \
      --nCars=30 --attackRate=50 --attackType=5 --RngRun=1 \
      --PktDropRate=1 --EdgeAddr=127.0.0.1 --EdgePort=9998 \
      --EdgePortZ2=9996 --InternalCloud=0 --CloudAddr=127.0.0.1 \
      --CloudPort=6666 --simTime=210 --nUAVs=2 \
      --ZoneLength=900.0 --HTDZoneBoundary=900.0 \
      --ZoneOverlapM=200.0 --HandoverLeadM=300.0 \
      --CoordAddr=127.0.0.1 --CoordPort=9997 \
      --DisableHandover=$DISABLE_HO --DisableCUSUM=false \
      --HandoverTrustDiscount=0.30 \
      --CusumMu0=0.20 --CusumH=2.5 --CusumWarmupK=5 \
      --PostHandoverProbationPkts=10 --PostHandoverCreditFactor=0.15 \
      --PostHandoverDisableUpgrade=1" \
      2>&1 | tee "$LOG"

    cd "$ROOT"

    mkdir -p "$OUTDIR/logs_${MODE}_rep${REP}"
    cp logs/*.log "$OUTDIR/logs_${MODE}_rep${REP}/" 2>/dev/null || true

    bash scripts/stop_pipeline_workstation.sh || true

    python3 - "$LOG" "$OUTDIR/logs_${MODE}_rep${REP}" "$REP" "$MODE" << 'PY' | tee -a "$SUMMARY"
import re, sys
from pathlib import Path

simlog = Path(sys.argv[1])
edgelogdir = Path(sys.argv[2])
rep = sys.argv[3]
mode = sys.argv[4]

payoff_re = re.compile(r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)")

text = simlog.read_text(errors="ignore")
payoff_lines = [x for x in text.splitlines() if "[PAYOFF]" in x]
payoff_lines = payoff_lines[-30:]

mal=caught=hon=fp=0
missed=[]
fps=[]

for line in payoff_lines:
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
    else:
        hon += 1
        fp += int(demoted)
        if demoted:
            fps.append(cid)

edge_text = ""
for p in edgelogdir.glob("*.log"):
    edge_text += "\n" + p.read_text(errors="ignore")

combined = text + "\n" + edge_text

handover_hits = combined.count("HANDOVER OK") + combined.count("TRUST_HANDOVER_LOAD")
htd_hits = combined.count("[HTD]")
cusum_hits = combined.count("CUSUM")
veremi_hits = combined.count("[VEREMI-EVIDENCE]")

print(f"{mode} REP {rep}: caught {caught}/{mal}, FP {fp}/{hon}, missed={missed}, fps={fps}")
print(f"{mode} REP {rep}: handover_hits={handover_hits}, htd_hits={htd_hits}, cusum_mentions={cusum_hits}, veremi_hits={veremi_hits}")
PY

    echo | tee -a "$SUMMARY"
  done
done

python3 - "$OUTDIR" << 'PY' | tee "$OUTDIR/final_summary.log"
import re, statistics, sys
from pathlib import Path

outdir = Path(sys.argv[1])
line_re = re.compile(r"^(on|off) REP (\d+): caught (\d+)/(\d+), FP (\d+)/(\d+), missed=(\[.*?\]), fps=(\[.*?\])")
metric_re = re.compile(r"^(on|off) REP (\d+): handover_hits=(\d+), htd_hits=(\d+), cusum_mentions=(\d+), veremi_hits=(\d+)")

data = {"on": [], "off": []}
metrics = {"on": [], "off": []}

for mode in ["on", "off"]:
    f = outdir / f"summary_{mode}.log"
    for line in f.read_text(errors="ignore").splitlines():
        m = line_re.search(line)
        if m:
            data[mode].append({
                "caught": int(m.group(3)),
                "mal": int(m.group(4)),
                "fp": int(m.group(5)),
                "hon": int(m.group(6)),
                "missed": m.group(7),
                "fps": m.group(8),
            })
        mm = metric_re.search(line)
        if mm:
            metrics[mode].append({
                "handover": int(mm.group(3)),
                "htd": int(mm.group(4)),
                "cusum": int(mm.group(5)),
                "veremi": int(mm.group(6)),
            })

print("============ HANDOVER PILOT FINAL SUMMARY ============")
for mode in ["on", "off"]:
    rows = data[mode]
    if not rows:
        print(mode, "NO ROWS")
        continue

    drs = [100*r["caught"]/r["mal"] for r in rows]
    fprs = [100*r["fp"]/r["hon"] for r in rows]
    print(f"\nMODE={mode}")
    print("Caught counts:", [r["caught"] for r in rows])
    print("FP counts:", [r["fp"] for r in rows])
    print(f"Total caught: {sum(r['caught'] for r in rows)}/{sum(r['mal'] for r in rows)}")
    print(f"Total FP: {sum(r['fp'] for r in rows)}/{sum(r['hon'] for r in rows)}")
    print(f"DR mean ± std: {statistics.mean(drs):.2f}% ± {statistics.stdev(drs) if len(drs)>1 else 0:.2f}%")
    print(f"FPR mean: {statistics.mean(fprs):.2f}%")
    print("Missed by rep:", [r["missed"] for r in rows])
    print("FPs by rep:", [r["fps"] for r in rows])

    if metrics[mode]:
        print("handover_hits:", [x["handover"] for x in metrics[mode]])
        print("htd_hits:", [x["htd"] for x in metrics[mode]])
        print("cusum_mentions:", [x["cusum"] for x in metrics[mode]])
        print("veremi_hits:", [x["veremi"] for x in metrics[mode]])

print("\nOutput dir:", outdir)
PY

echo "DONE. Results in: $OUTDIR"
