#!/usr/bin/env bash
set -euo pipefail
# Reproduces paper Table XIII (Comparison With Local Segment-Reset VeReMi
# Baseline). Unlike Tables VIII/IX/XI/XII/XIV/XV, this table needs NO new
# ns-3 simulation: it re-analyzes the [PASSIVE-BEACON] traces already
# produced by Table XII's packet-loss sweep, recomputing a VeReMi-style
# local segment-reset decision from the same raw beacon logs
# (scripts/baseline_a_full_veremi_style.py). Run
# run_table_xii_packet_loss_15seed.sh FIRST.
#
# Note: baseline_a_full_veremi_style.py's own --results_dir/--seeds
# convenience flags assume log filenames "ns3_seed_{N}.log", which does not
# match this pipeline's actual naming ("ON_seed{N}_x560_720_t36.log") --
# this wrapper uses --log_file per seed instead, which the script does
# support directly, to route around that mismatch.
#
# CONFIDENCE NOTE: the ns-3 sweep pattern this reuses (Table XII) is
# independently proven this session. This script's own numeric agreement
# with results/final_locked_csv/reviewer_ready_baseline_master_summary.csv
# was NOT independently re-verified end-to-end before inclusion -- treat
# it as "best-identified command," re-check its printed TOTAL RESULT
# against that CSV before trusting it for a new submission.

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

DROPS="${DROPS:-0 5 10 20}"
SEEDS="${SEEDS:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15}"
ATTACK_X0="${ATTACK_X0:-560}"
ATTACK_X1="${ATTACK_X1:-720}"
SIMTIME="${SIMTIME:-36}"
MODE="ON"

# Matches the "hard_only; speed_tol=6.0; pos_tol=15.0; max_gap=3.0;
# min_violations=2" final-locked config string recorded in
# attack_variant_patched_final_aggregate_summary.csv.
POS_TOL="${POS_TOL:-15.0}"
SPEED_TOL="${SPEED_TOL:-6.0}"
MAX_GAP="${MAX_GAP:-3.0}"
MIN_VIOLATIONS="${MIN_VIOLATIONS:-2}"

for DROP in $DROPS; do
  SRC_DIR="$PROJECT_ROOT/results/packet_loss_robustness_DROP${DROP}_guarded_cusum_15seed"
  if [ ! -d "$SRC_DIR" ]; then
    echo "[SKIP] $SRC_DIR does not exist -- run run_table_xii_packet_loss_15seed.sh first"
    continue
  fi

  OUTDIR="$PROJECT_ROOT/results/baseline_veremi_DROP${DROP}"
  mkdir -p "$OUTDIR"
  OUTFILE="$OUTDIR/baseline_veremi_result.txt"

  echo "" > "$OUTFILE"
  for SEED in $SEEDS; do
    LOGFILE="$SRC_DIR/${MODE}_seed${SEED}_x${ATTACK_X0}_${ATTACK_X1}_t${SIMTIME}.log"
    if [ ! -f "$LOGFILE" ]; then
      echo "[WARN] missing $LOGFILE, skipping" | tee -a "$OUTFILE"
      continue
    fi
    echo "===== DROP=$DROP SEED=$SEED =====" >> "$OUTFILE"
    python3 scripts/baseline_a_full_veremi_style.py \
      --log_file "$LOGFILE" \
      --pos_tolerance "$POS_TOL" \
      --speed_tolerance "$SPEED_TOL" \
      --max_gap "$MAX_GAP" \
      --min_violations "$MIN_VIOLATIONS" \
      >> "$OUTFILE"
  done
  echo "Wrote $OUTFILE"
done

echo ""
echo "All baseline-comparison analysis runs completed. Aggregate the"
echo "per-seed TOTAL RESULT blocks in each baseline_veremi_result.txt by"
echo "hand or with a short script -- this tool prints per-run, not pooled."
