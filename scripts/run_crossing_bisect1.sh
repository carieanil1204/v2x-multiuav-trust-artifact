#!/usr/bin/env bash
set -uo pipefail

# [OPTION-C / Bisect Step 1] Single seed (RngRun=1) each ON/OFF, tails
# 1.1/1.2/1.3/1.4s, to bisect the transition point Pass 2 pinned as
# "somewhere between 1.0s (full gap) and 1.5s (full parity)".
# offset fixed at -1.5s (same as Pass 1/Pass 2). Runs standalone inside
# tmux so it survives SSH/session disconnect.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# ./ns3 wrapper needs python3.10 (ns3-env); system/base conda python3.14's
# stricter argparse validation crashes it before it even parses our flags.
# A fresh tmux server does not inherit an interactively-activated env, so
# activate explicitly rather than relying on shell state (bit us once
# already on this bisect run — see CLAUDE.md ops note).
source /home/srmap-jc205/miniconda3/etc/profile.d/conda.sh
conda activate ns3-env

for TAIL in 1.1 1.2 1.3 1.4; do
  DUR=$(python3 -c "print(1.5 + $TAIL)")
  OUTDIR="results/crossing_sweep_bisect1/tail_${TAIL}"
  mkdir -p "$OUTDIR"
  for MODE in ON OFF; do
    echo "=== TAIL=$TAIL DUR=$DUR MODE=$MODE SEED=1 ==="
    bash scripts/stop_pipeline_workstation.sh >/dev/null 2>&1 || true
    MODE=$MODE SEED=1 ATTACK_CROSSING_OFFSET_SEC=-1.5 ATTACK_CROSSING_DURATION_SEC=$DUR OUTDIR=$OUTDIR \
      bash scripts/run_crossing_relative_stress.sh > "$OUTDIR/run_${MODE}_seed1.stdout" 2>&1
    RC=$?
    echo "exit=$RC for TAIL=$TAIL MODE=$MODE SEED=1"
    if [ $RC -ne 0 ]; then
      echo "!!! FAILED, cleaning up before continuing !!!"
      bash scripts/stop_pipeline_workstation.sh >/dev/null 2>&1 || true
      sleep 3
    fi
  done
done
echo "BISECT1_COMPLETE"
