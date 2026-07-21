#!/bin/bash
# git_organize.sh
# ===============
# Organize the V2X DRL research repo with proper git tracking.
#
# Fixes the contrib/.gitignore bug that hides all our research work,
# then commits in 4 logical chunks on a new phase2c-eval-baselines branch.
#
# DRY-RUN BY DEFAULT. Pass --execute to actually run.
#
# Usage:
#   bash git_organize.sh              # dry-run, just prints what would happen
#   bash git_organize.sh --execute    # actually run with confirmation prompts

set -e   # exit on any error
set -u   # exit on undefined variable

REPO_ROOT="/home/srmap/research/projects/ns3-5g-v2x/ns-allinone-3.41/ns-3.41"
DRY_RUN=true

if [ "${1:-}" = "--execute" ]; then
    DRY_RUN=false
fi

# Color output for clarity
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'   # no color

run_cmd() {
    # Print command, run it (or skip if dry-run)
    local cmd="$1"
    local desc="${2:-}"
    
    if [ -n "$desc" ]; then
        echo -e "${BLUE}# $desc${NC}"
    fi
    echo -e "  ${YELLOW}\$ $cmd${NC}"
    
    if [ "$DRY_RUN" = "true" ]; then
        echo -e "    ${YELLOW}(dry-run, not executed)${NC}"
    else
        eval "$cmd"
    fi
    echo ""
}

confirm() {
    local prompt="$1"
    if [ "$DRY_RUN" = "true" ]; then
        echo -e "${YELLOW}[dry-run] would prompt: $prompt${NC}"
        return 0
    fi
    read -p "$(echo -e ${GREEN}$prompt [y/N]: ${NC})" answer
    if [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
        echo "Aborted by user."
        exit 1
    fi
}

step_banner() {
    echo ""
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}=================================================================${NC}"
}

# ============================================================================
echo ""
if [ "$DRY_RUN" = "true" ]; then
    echo -e "${YELLOW}########################################${NC}"
    echo -e "${YELLOW}#  DRY-RUN MODE — NO CHANGES WILL HAPPEN${NC}"
    echo -e "${YELLOW}#  Run with --execute to actually run.${NC}"
    echo -e "${YELLOW}########################################${NC}"
else
    echo -e "${RED}########################################${NC}"
    echo -e "${RED}#  EXECUTE MODE — CHANGES WILL BE MADE${NC}"
    echo -e "${RED}########################################${NC}"
fi
echo ""

cd "$REPO_ROOT"
echo "Working directory: $REPO_ROOT"

# ============================================================================
step_banner "STEP 0: Pre-flight safety checks"

# 0a. Eval running check
echo "Checking if DRL eval is running..."
EVAL_DIR=$(cat contrib/ai/examples/v2x-urllc/.last_eval_dir 2>/dev/null || echo "")
EVAL_PID=$(cat "$EVAL_DIR/pid.txt" 2>/dev/null || echo "")

if [ -n "$EVAL_PID" ] && ps -p "$EVAL_PID" > /dev/null 2>&1; then
    EPS_DONE=$(grep -c '^Ep ' "$EVAL_DIR/eval.log" 2>/dev/null || echo 0)
    echo -e "${RED}WARNING: DRL eval is still running (PID $EVAL_PID, $EPS_DONE/20 episodes done)${NC}"
    echo -e "${RED}Git operations are SAFE (only read source files), but recommended to wait.${NC}"
    confirm "Continue anyway?"
else
    echo -e "${GREEN}OK: no eval process running${NC}"
fi

# 0b. Current git state
echo ""
echo "Current git state:"
run_cmd "git branch --show-current" "Current branch"
run_cmd "git log --oneline -3" "Last 3 commits"
run_cmd "git status --short | head -20" "Untracked/modified files (visible to git)"

# 0c. Backup before any change
BACKUP_FILE="/tmp/repo_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
echo "Will create safety backup before any changes..."
run_cmd "tar --exclude='./build' --exclude='./cmake-cache' --exclude='./.git' \
   -czf $BACKUP_FILE -C $REPO_ROOT . 2>/dev/null" \
   "Tar backup of source files (excludes build/, cmake-cache/, .git)"

confirm "Backup created at $BACKUP_FILE. Proceed to step 1?"

# ============================================================================
step_banner "STEP 1: Delete junk files (per user choice)"

echo "Files to delete:"
echo "  contrib/ai/examples/v2x-urllc/v2x-urllc--.cc       (typo file, 17K)"
echo "  contrib/ai/examples/v2x-urllc/patch_v2x_urllc_py.py (old patcher, replaced by patch_eval_mode.py)"
echo "  contrib/ai/examples/v2x-urllc/v2x-urllc.py.before_eval_patch (patcher backup, no longer needed)"
echo ""

run_cmd "ls -la contrib/ai/examples/v2x-urllc/v2x-urllc--.cc 2>/dev/null || echo '(missing - skipping)'" "Verify junk file 1 exists"
run_cmd "ls -la contrib/ai/examples/v2x-urllc/patch_v2x_urllc_py.py 2>/dev/null || echo '(missing - skipping)'" "Verify junk file 2 exists"
run_cmd "ls -la contrib/ai/examples/v2x-urllc/v2x-urllc.py.before_eval_patch 2>/dev/null || echo '(missing - skipping)'" "Verify backup exists"

confirm "Delete these 3 junk files?"

run_cmd "rm -f contrib/ai/examples/v2x-urllc/v2x-urllc--.cc" "Delete typo file"
run_cmd "rm -f contrib/ai/examples/v2x-urllc/patch_v2x_urllc_py.py" "Delete old patcher"
run_cmd "rm -f contrib/ai/examples/v2x-urllc/v2x-urllc.py.before_eval_patch" "Delete patch backup"

echo "Note: backup_before_reward_fix_*/ (13MB) and traces_*/ dirs are LEFT ALONE (gitignore handles them)."

# ============================================================================
step_banner "STEP 2: Update .gitignore files (the critical bug fix)"

echo "Two gitignore files will be updated:"
echo "  1. contrib/.gitignore   — add SELECTIVE OVERRIDES so our research files are tracked"
echo "  2. .gitignore (root)    — extend with proper exclusions for run dirs and binary blobs"
echo ""
echo "Strategy: keep upstream behavior intact, ONLY un-ignore specific files we created."
echo ""
echo "After this step, 'git status' will show all our work as UNTRACKED — that's expected."

confirm "Proceed to update gitignore files?"

# 2a. Write new contrib/.gitignore
echo ""
echo -e "${BLUE}# Writing new contrib/.gitignore${NC}"
if [ "$DRY_RUN" = "true" ]; then
    echo -e "    ${YELLOW}(dry-run: would write the following)${NC}"
fi

CONTRIB_GITIGNORE_CONTENT='# Ignore everything by default, contrib sources are coming from other places
* 

# Include specific files that should be tracked by Git
!.gitignore

# === BEGIN: srmap research overrides (Phase 2c) ===
# Allow git to descend into our research directories
!ai/
!ai/examples/
!ai/examples/v2x-urllc/
!nr/
!nr/model/

# DRL scenario + bridge (our code)
!ai/examples/v2x-urllc/v2x-urllc.cc
!ai/examples/v2x-urllc/v2x-urllc.py
!ai/examples/v2x-urllc/v2x-urllc-env.h
!ai/examples/v2x-urllc/v2x-urllc-py.cc
!ai/examples/v2x-urllc/CMakeLists.txt

# Tooling scripts (our code)
!ai/examples/v2x-urllc/run_baselines.py
!ai/examples/v2x-urllc/run_one_baseline.py
!ai/examples/v2x-urllc/patch_eval_mode.py

# Custom scheduler (our code, registered in nr/CMakeLists.txt)
!nr/model/nr-mac-scheduler-tdma-ai.cc
!nr/model/nr-mac-scheduler-tdma-ai.h
!nr/CMakeLists.txt
# === END: srmap research overrides ===
'

if [ "$DRY_RUN" = "false" ]; then
    echo "$CONTRIB_GITIGNORE_CONTENT" > contrib/.gitignore
    echo "    written contrib/.gitignore"
else
    echo -e "    ${YELLOW}--- new content preview ---${NC}"
    echo "$CONTRIB_GITIGNORE_CONTENT" | head -20
    echo -e "    ${YELLOW}--- (...)\n${NC}"
fi

# 2b. Append to root .gitignore
echo ""
echo -e "${BLUE}# Extending root .gitignore${NC}"

ROOT_GITIGNORE_ADDITIONS='
# === BEGIN: srmap research additions (Phase 2c) ===
# Run output dirs (BALANCED policy: ignore raw runs)
contrib/ai/examples/v2x-urllc/run_*/
contrib/ai/examples/v2x-urllc/traces/
contrib/ai/examples/v2x-urllc/eval_*/
contrib/ai/examples/v2x-urllc/backups/
contrib/ai/examples/v2x-urllc/backup_*/
contrib/ai/examples/v2x-urllc/paper_results_*/
contrib/ai/examples/v2x-urllc/traces_*/

# Within experiments/results, track only manifests + summaries (not raw)
experiments/results/*/traces/
experiments/results/*/*.pt
experiments/results/*/eval_results.csv
experiments/results/*/eval.log
experiments/results/*/launch.log
experiments/results/*/pid.txt
experiments/results/*/eval_input.pt

# Model checkpoints anywhere
*.pt

# Backup files from patchers
*.before_*_patch
*.bak
*.bak-*
v2x-urllc--.cc

# Editor / OS junk
.vscode/
*.swp
.idea/
nohup.out

# Skill staging (if you upload to claude.ai again)
caveman_skills.zip
# === END: srmap research additions ===
'

if [ "$DRY_RUN" = "false" ]; then
    # Only append if not already added (idempotent)
    if grep -q "srmap research additions" .gitignore 2>/dev/null; then
        echo "    .gitignore already extended, skipping"
    else
        echo "$ROOT_GITIGNORE_ADDITIONS" >> .gitignore
        echo "    appended to .gitignore"
    fi
else
    echo -e "    ${YELLOW}--- would append following to .gitignore ---${NC}"
    echo "$ROOT_GITIGNORE_ADDITIONS" | head -10
    echo -e "    ${YELLOW}--- (...) ---${NC}"
fi

echo ""
echo "Now running 'git status' to verify our work files are now visible:"
run_cmd "git status --short | head -30" "Files now visible to git"

confirm "Verify above shows our research files (v2x-urllc.cc, etc) as UNTRACKED. Proceed to step 3?"

# ============================================================================
step_banner "STEP 3: Create new branch phase2c-eval-baselines"

echo "Creating new branch off current HEAD (commit 9da56b7, tagged phase2a/2b)."
echo "All new commits land on this branch. master and phase2-action-wiring untouched."

run_cmd "git checkout -b phase2c-eval-baselines" "Create + checkout new branch"
run_cmd "git branch -v" "Verify branches"

# ============================================================================
step_banner "STEP 4: Commit 1/4 — chore(git): track research source via gitignore overrides"

echo "Adding only the .gitignore changes."
run_cmd "git add contrib/.gitignore .gitignore" "Stage gitignore changes only"
run_cmd "git status --short | head -10" "Verify staging"
run_cmd "git diff --cached --stat" "Confirm what's about to be committed"

confirm "Make commit 1/4?"

run_cmd 'git commit -m "chore(git): track research source via contrib/.gitignore overrides

The upstream contrib/.gitignore had a blanket \"*\" ignore rule meant for
clean 5G-LENA module imports. This silently hid all our research work
(custom scheduler, DRL scenario, trainer, baseline scripts) from git.

Add selective !-overrides to track only OUR research files while leaving
upstream contrib/ai/ and contrib/nr/ files ignored as designed.

Also extend root .gitignore with patterns for run output directories,
checkpoints, and editor junk (BALANCED tracking policy).

Refs phase2c"' "Commit gitignore fixes"

# ============================================================================
step_banner "STEP 5: Commit 2/4 — feat(scheduler+drl): NrMacSchedulerTdmaAi + ns3-ai V2X scenario"

echo "Adding the core research code (scheduler + DRL infrastructure)."
echo ""

CORE_FILES=(
    "contrib/nr/model/nr-mac-scheduler-tdma-ai.cc"
    "contrib/nr/model/nr-mac-scheduler-tdma-ai.h"
    "contrib/nr/CMakeLists.txt"
    "contrib/ai/examples/v2x-urllc/v2x-urllc.cc"
    "contrib/ai/examples/v2x-urllc/v2x-urllc.py"
    "contrib/ai/examples/v2x-urllc/v2x-urllc-env.h"
    "contrib/ai/examples/v2x-urllc/v2x-urllc-py.cc"
    "contrib/ai/examples/v2x-urllc/CMakeLists.txt"
)

for f in "${CORE_FILES[@]}"; do
    if [ -f "$f" ]; then
        run_cmd "git add $f" "Stage $f"
    else
        echo -e "${RED}WARNING: $f does not exist!${NC}"
    fi
done

run_cmd "git status --short" "Files now staged"
run_cmd "git diff --cached --stat" "Lines changed"

confirm "Make commit 2/4?"

run_cmd 'git commit -m "feat(scheduler+drl): NrMacSchedulerTdmaAi + ns3-ai V2X scenario

Custom 5G-NR MAC scheduler with UrllcSymbolFraction attribute [0,1] that
controls how many TDMA symbols per slot are reserved for URLLC traffic.
Validated as monotonic action surface in Phase-2a stress sweep
(R_gap = 22348 between frac=0.0 and frac=1.0 with same channel seed).

V2X-URLLC scenario (contrib/ai/examples/v2x-urllc/v2x-urllc.cc) wires the
scheduler attribute to a DQN agent via ns3-ai shared memory bridge.
Key design decisions:
- 100 ms decision window (matches URLLC beacon period 10 Hz). Smaller
  windows give 91% empty windows; larger windows cant react.
- Per-step delta delay metrics (g_prevDelaySumByFlow) instead of cumulative
  FlowMonitor.delaySum, to avoid washing out reward gradient.
- Reward bounds [-1000,+100], NaN guard on incoming action.
- 11 discrete actions (0.0 to 1.0 step 0.1).

Python trainer (v2x-urllc.py): DQN with 8-dim state, multiprocessing
per-episode child to release pybind/CUDA state cleanly.

Refs phase2c"' "Commit core research files"

# ============================================================================
step_banner "STEP 6: Commit 3/4 — feat(eval+baselines): frozen-policy eval + baseline runners"

echo "Adding evaluation tooling."
echo ""

EVAL_FILES=(
    "contrib/ai/examples/v2x-urllc/run_baselines.py"
    "contrib/ai/examples/v2x-urllc/run_one_baseline.py"
    "contrib/ai/examples/v2x-urllc/patch_eval_mode.py"
)

for f in "${EVAL_FILES[@]}"; do
    if [ -f "$f" ]; then
        run_cmd "git add $f" "Stage $f"
    else
        echo -e "${RED}WARNING: $f does not exist!${NC}"
    fi
done

run_cmd "git diff --cached --stat" "Lines being committed"

confirm "Make commit 3/4?"

run_cmd 'git commit -m "feat(eval+baselines): frozen-policy eval + baseline scheduler runners

Add tooling for fair DRL-vs-baselines comparison:

run_baselines.py: batch runner for TdmaRR/TdmaPF/TdmaQos under exact same
conditions as DRL training (same scenario binary, same nUes/speed/simTime,
same seeds). Sends fixed dummy urllcFraction=0.5 every step which non-AI
schedulers ignore. Sequential to avoid /dev/shm collisions.

run_one_baseline.py: minimal single-shot runner for sanity-testing one
(scheduler, seed) pair before full sweep.

patch_eval_mode.py: idempotent patcher that adds --eval_only flag to
v2x-urllc.py for true frozen-policy evaluation. When --eval_only is set:
qnet.eval() called, optimizer.step skipped, target net not updated,
checkpoint never saved. Verified: avg_loss=0.0 across all eval episodes.

This enables the standard literature methodology: train DRL for N
episodes, evaluate frozen policy on K seeds, compare to baselines on
matched K seeds.

Refs phase2c"' "Commit eval+baseline tooling"

# ============================================================================
step_banner "STEP 7: Tag the milestone"

echo "Tagging current state as phase2c-eval-baselines-complete."
run_cmd "git tag -a phase2c-eval-baselines-complete -m 'Phase 2c: eval-mode patch + baseline runner infrastructure complete

DRL-vs-baselines comparison framework ready:
- TdmaRR/PF/Qos baseline runner (5 seeds × 3 schedulers verified for RR)
- Frozen-policy DRL evaluation (--eval_only flag)
- All run conditions matched: nUes=20, speed=22 m/s, simTime=5s, stepInt=100ms

Awaiting completion of 20-episode DRL eval run for headline numbers.'" "Create annotated tag"

# ============================================================================
step_banner "STEP 8: Final verification"

run_cmd "git log --oneline --decorate -10" "Commit history"
run_cmd "git branch -v" "All branches"
run_cmd "git tag --sort=-creatordate | head -10" "All tags"
run_cmd "git status" "Working tree should be clean (or only have untracked run_*/eval_* dirs)"

run_cmd "du -sh .git/" "Repo size"

# ============================================================================
echo ""
echo -e "${GREEN}=================================================================${NC}"
if [ "$DRY_RUN" = "true" ]; then
    echo -e "${GREEN}  DRY-RUN COMPLETE — no changes were made${NC}"
    echo -e "${GREEN}  Re-run with --execute to actually do it:${NC}"
    echo -e "${GREEN}    bash $0 --execute${NC}"
else
    echo -e "${GREEN}  EXECUTION COMPLETE${NC}"
    echo -e "${GREEN}  Backup at: $BACKUP_FILE${NC}"
    echo -e "${GREEN}  Branch: phase2c-eval-baselines${NC}"
    echo -e "${GREEN}  Tag:    phase2c-eval-baselines-complete${NC}"
fi
echo -e "${GREEN}=================================================================${NC}"
