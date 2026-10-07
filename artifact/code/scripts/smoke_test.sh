#!/usr/bin/env bash
set -euo pipefail
# Fast end-to-end smoke test for the reproduced environment.
# Single seed, MODE=ON, default crossing-relative config (tail=1.5s, the
# fastest/shortest of the tested runway durations). Confirms the ns-3
# build, the four pipeline microservices, and Ollama are all working
# together correctly. Takes ~60-90s on a typical workstation.
#
# MUST be run from <PROJECT_ROOT>/scripts/ after deployment -- see
# README.md "Deploying on a new machine" for the required directory
# layout (this script assumes ../pipeline, ../ns-allinone-3.41 exist
# as siblings, same as every other script in this directory).

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== Smoke test: environment checks ==="
source "$HOME/miniconda3/etc/profile.d/conda.sh" 2>/dev/null || {
  echo "[FAIL] could not source conda.sh -- is miniconda installed at ~/miniconda3?"
  exit 1
}
conda activate ns3-env || {
  echo "[FAIL] conda env 'ns3-env' not found -- see README.md Step 2 (Python environment)"
  exit 1
}
python3 --version | grep -q "3.10" || {
  echo "[WARN] ns3-env python is not 3.10.x -- ./ns3 may fail with an argparse error on newer Python"
}

command -v ollama >/dev/null 2>&1 || {
  echo "[FAIL] ollama not found on PATH -- see README.md Step 3 (Ollama)"
  exit 1
}
ollama list | grep -q "llama3:latest" || {
  echo "[FAIL] llama3:latest not pulled -- run: ollama pull llama3:latest"
  exit 1
}

[ -x "$PROJECT_ROOT/ns-allinone-3.41/ns-3.41/ns3" ] || {
  echo "[FAIL] ns-3 not found/built at ns-allinone-3.41/ns-3.41/ -- see README.md Step 4 (ns-3 build)"
  exit 1
}

echo "[OK] conda env, Ollama, and ns-3 build all present"

echo
echo "=== Smoke test: single-seed run (MODE=ON, tail=1.5s) ==="
OUTDIR="$PROJECT_ROOT/results/smoke_test_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

MODE=ON SEED=1 ATTACK_CROSSING_OFFSET_SEC=-1.5 ATTACK_CROSSING_DURATION_SEC=3.0 \
  OUTDIR="$OUTDIR" bash "$PROJECT_ROOT/scripts/run_crossing_relative_stress.sh"

LOGFILE="$OUTDIR/ON_seed1_crossrel.log"
if [ -f "$LOGFILE" ] && grep -q "\[PAYOFF\]" "$LOGFILE"; then
  N_PAYOFF=$(grep -c "\[PAYOFF\]" "$LOGFILE")
  echo
  echo "=== SMOKE TEST PASSED ==="
  echo "Pipeline ran end-to-end: ns-3 -> Edge -> Bridge -> Coordinator -> Cloud LLM."
  echo "$N_PAYOFF vehicle decisions logged in $LOGFILE"
  exit 0
else
  echo
  echo "=== SMOKE TEST FAILED ==="
  echo "No [PAYOFF] lines found in $LOGFILE -- check $OUTDIR/run_ON_seed1.stdout for the error"
  exit 1
fi
