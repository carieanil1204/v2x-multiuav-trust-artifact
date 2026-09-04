#!/usr/bin/env bash
set -euo pipefail

# [OPTION-C] 15-seed sweep, ON and OFF, using the validated
# AttackCrossingOffsetSec=-1.0 default from scripts/run_crossing_relative_stress.sh.
# Separate from run_handover_tunable.sh (attackType=5 trust-then-defect stress
# test), which this does not touch or invoke.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="${OUTDIR:-$PROJECT_ROOT/results/crossing_relative_15seed}"
mkdir -p "$OUTDIR"

for MODE in ON OFF; do
  for SEED in $(seq 1 15); do
    echo "=== MODE=$MODE SEED=$SEED ==="
    MODE=$MODE SEED=$SEED OUTDIR="$OUTDIR" bash "$PROJECT_ROOT/scripts/run_crossing_relative_stress.sh" \
      > "$OUTDIR/run_${MODE}_seed${SEED}.stdout" 2>&1
  done
done

echo "All 30 runs complete. Logs in $OUTDIR"
