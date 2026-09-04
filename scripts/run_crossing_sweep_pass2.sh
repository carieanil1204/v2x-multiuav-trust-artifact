#!/usr/bin/env bash
set -uo pipefail

# [OPTION-C / Pass 2] Scale the Pass-1 transition-zone finding (tail=0.0/0.5/1.0
# real ON/OFF gap, tail=1.5 gap gone) to 15 seeds each, to confirm it holds
# beyond n=1. offset fixed at -1.5s (validated in Pass 1). Runs standalone
# inside tmux so it survives SSH/session disconnect.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

for TAIL in 0.0 0.5 1.0 1.5; do
  DUR=$(python3 -c "print(1.5 + $TAIL)")
  OUTDIR="results/crossing_sweep_pass2/tail_${TAIL}"
  mkdir -p "$OUTDIR"
  for MODE in ON OFF; do
    for SEED in $(seq 1 15); do
      echo "=== TAIL=$TAIL DUR=$DUR MODE=$MODE SEED=$SEED ==="
      bash scripts/stop_pipeline_workstation.sh >/dev/null 2>&1 || true
      MODE=$MODE SEED=$SEED ATTACK_CROSSING_OFFSET_SEC=-1.5 ATTACK_CROSSING_DURATION_SEC=$DUR OUTDIR=$OUTDIR \
        bash scripts/run_crossing_relative_stress.sh > "$OUTDIR/run_${MODE}_seed${SEED}.stdout" 2>&1
      RC=$?
      echo "exit=$RC for TAIL=$TAIL MODE=$MODE SEED=$SEED"
      if [ $RC -ne 0 ]; then
        echo "!!! FAILED, cleaning up before continuing !!!"
        bash scripts/stop_pipeline_workstation.sh >/dev/null 2>&1 || true
        sleep 3
      fi
    done
  done
done
echo "PASS2_COMPLETE"
