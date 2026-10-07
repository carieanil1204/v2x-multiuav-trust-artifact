#!/usr/bin/env bash
set -uo pipefail

# [OPTION-C / Bisect Step 2] Scale tails 1.1/1.2/1.3/1.4s to 15 seeds each.
# Step 1 (n=1) showed no single clean split point (OFF DR stepped
# 0->40->40->40->80 across 1.0-1.4, car-level granularity with only 5
# malicious cars/seed) so bisecting further at n=1 would be unreliable --
# going straight to the Pass-2 standard of 15 seeds to get the real
# population-level transition curve between the known endpoints
# (1.0s = 0% OFF DR, 1.5s = 97.3% OFF DR, both pooled n=75).
# offset fixed at -1.5s. Runs standalone inside tmux so it survives
# SSH/session disconnect.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# ./ns3 wrapper needs python3.10 (ns3-env); a fresh tmux server does not
# inherit an interactively-activated conda env, so activate explicitly.
source /home/srmap-jc205/miniconda3/etc/profile.d/conda.sh
conda activate ns3-env

for TAIL in 1.1 1.2 1.3 1.4; do
  DUR=$(python3 -c "print(1.5 + $TAIL)")
  OUTDIR="results/crossing_sweep_bisect2_15seed/tail_${TAIL}"
  mkdir -p "$OUTDIR"
  for MODE in ON OFF; do
    for SEED in $(seq 1 15); do
      STDOUT="$OUTDIR/run_${MODE}_seed${SEED}.stdout"
      if [ -f "$STDOUT" ] && grep -q "^Saved log:" "$STDOUT"; then
        echo "=== TAIL=$TAIL MODE=$MODE SEED=$SEED already complete, skipping (resume) ==="
        continue
      fi
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
echo "BISECT2_15SEED_COMPLETE"
