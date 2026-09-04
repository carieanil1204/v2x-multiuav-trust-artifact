# Reproducibility Artifact

**Mobility-Aware Multi-UAV Edge–Cloud Trust Management for Falsified Vehicular
Beacon Detection under Handover and Packet Loss**

This package contains everything needed to rebuild the simulation
environment on a fresh machine and reproduce every table and figure in the
paper: the ns-3 scenario source, the four pipeline microservices, the exact
scripts that generated each locked result, the locked CSVs themselves, and
verification/plotting tooling. Follow the steps below in order — each one
was verified working end-to-end on a real deployment while this package was
assembled.

## 1. What's in this artifact

```
paper_artifact_v1.0/
├── README.md                  <- this file
├── requirements.txt            <- pip packages for analysis/plotting (stdlib only for the sim itself)
├── VERSION.txt
├── CITATION.cff
├── EXPERIMENT_MANIFEST.csv     <- experiment -> paper table -> CSV mapping
├── artifact_verification_report.txt   <- last verify_tables.py run, all PASS
├── code/
│   ├── ns3_scenario/
│   │   └── unified_v91_multiuav_handover_defense.cc   <- the ns-3 scenario (goes in ns-3.41/scratch/)
│   ├── pipeline/
│   │   ├── cloud/       <- Cloud LLM microservice (talks to Ollama)
│   │   ├── coordinator/ <- Cross-UAV Trust-State Coordinator
│   │   ├── edge/        <- UAV Edge Zone microservice (used for both zones)
│   │   ├── bridge/       <- Edge<->Cloud passthrough bridge (used for both zones)
│   │   └── configs/
│   ├── scripts/          <- launch/stop pipeline + the exact run_*.sh that generated each locked result + smoke_test.sh
│   └── analysis/         <- verify_tables.py, parse_crossing_relative_results.py, compute_handover_fpr.py, plot_fig*.py
├── configuration/
├── logs/
├── paper_mapping/
│   └── table_csv_mapping.csv
└── results/
    ├── final_locked_csv/ mirror (aggregate + per-seed raw CSVs, one set per experiment)
    └── ...
```

## 2. Prerequisites

- Linux (Ubuntu 22.04+ or similar). Not tested on macOS/Windows directly —
  use WSL2 on Windows.
- ~10 GB free disk (ns-3 build + NR contrib module + Ollama model weights).
- A C++17 compiler (g++ 9+), CMake ≥ 3.13, ninja or make, python3.10.
- ~8 GB RAM free for the local LLM (llama3:latest, ~4.7 GB on disk).
- `git`, `curl`, `tmux` (recommended for long unattended runs — see Section 8).

## 3. Step-by-step setup

### Step 1 — Download and extract ns-3.41

```bash
mkdir -p ~/v2x-repro && cd ~/v2x-repro
curl -LO https://www.nsnam.org/releases/ns-allinone-3.41.tar.bz2
tar xjf ns-allinone-3.41.tar.bz2
```

This creates `~/v2x-repro/ns-allinone-3.41/ns-3.41/`.

### Step 2 — Add the NR (5G-LENA) contrib module

The scenario file depends on `ns3/nr-module.h` — the CTTC 5G-LENA NR
module, release **NR-v3.0** (the release compatible with ns-3.41). This is
a separate GPL-2.0 module, not part of vanilla ns-3, and is not bundled in
this artifact (kept out to keep the package small and avoid redistributing
a large third-party module) — clone it directly:

```bash
cd ~/v2x-repro/ns-allinone-3.41/ns-3.41/contrib
git clone https://gitlab.com/cttc-lena/nr.git
cd nr && git checkout NR-v3.0
```

### Step 3 — Python environment

The ns-3 wrapper script (`./ns3`) requires **Python 3.10** specifically.
Newer Python (3.13+/3.14) has a stricter `argparse` that crashes the
wrapper before it even parses flags — this was hit and confirmed during
this artifact's own preparation, so it is a real, not theoretical, gotcha.

```bash
# using Miniconda (recommended)
curl -LO https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh -b -p "$HOME/miniconda3"
source "$HOME/miniconda3/etc/profile.d/conda.sh"

conda create -n ns3-env python=3.10 -y
conda activate ns3-env
pip install -r requirements.txt
```

**Every time you open a new shell** (or a fresh `tmux`/background session)
you must reactivate this before running anything:

```bash
source "$HOME/miniconda3/etc/profile.d/conda.sh" && conda activate ns3-env
```

A background job started without this line will silently pick up the
system Python and fail with an `argparse` traceback from `./ns3`.

### Step 4 — Ollama (local Cloud LLM)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3:latest
ollama serve &          # or: systemctl enable --now ollama
```

Verify: `ollama list` should show `llama3:latest`.

### Step 5 — Deploy this artifact's code into the ns-3 project layout

The scripts in `code/scripts/` locate their own project root relative to
their own location (`dirname "$0"/..`) and expect `pipeline/` and
`ns-allinone-3.41/` as siblings — this exact layout must be reproduced:

```bash
cd ~/v2x-repro
cp code/ns3_scenario/unified_v91_multiuav_handover_defense.cc \
   ns-allinone-3.41/ns-3.41/scratch/
cp -r code/pipeline .
mkdir -p scripts && cp code/scripts/*.sh code/scripts/*.py scripts/
mkdir -p analysis && cp code/analysis/*.py analysis/
chmod +x scripts/*.sh
```

Result: `~/v2x-repro/{pipeline,scripts,ns-allinone-3.41}` all siblings, and
`~/v2x-repro/scripts/run_*.sh` computes `PROJECT_ROOT=~/v2x-repro` correctly.

### Step 6 — Build ns-3

```bash
cd ~/v2x-repro/ns-allinone-3.41/ns-3.41
conda activate ns3-env   # if not already active
./ns3 configure --build-profile=release --disable-examples --disable-tests
./ns3 build
```

This is the exact configuration the locked results were built with
(`CMAKE_BUILD_TYPE=release`, examples/tests off). Build takes 15–40 minutes
depending on CPU.

## 4. Smoke test — run this before anything else

```bash
cd ~/v2x-repro
bash scripts/smoke_test.sh
```

Single seed, ~60–90 seconds. Checks the conda env, Ollama, and the ns-3
build are all present, then runs one full end-to-end simulation (ns-3 →
Edge → Bridge → Coordinator → Cloud LLM) and confirms vehicle decisions
were logged. `=== SMOKE TEST PASSED ===` means the environment is correctly
reproduced and ready for full campaigns.

## 5. Reproducing the paper's tables

All commands below assume `conda activate ns3-env` and `cd ~/v2x-repro`
first. Each script starts/stops the pipeline itself per run — do not run
two of these concurrently on the same machine (ports 6666/9995–9999 are
fixed).

All of the tables below (except Table VII) are thin sweep wrappers around
one shared driver, `run_handover_tunable.sh`, which itself is fully
parameterized (nCars, attack rate/type, packet-loss rate, HTD discount,
CUSUM H/min-obs/edge-max, attack X-window, sim time). Each wrapper's output
directory naming was checked this session against the real, already-locked
result directories on disk and matches exactly, confirmed either by an
exact skip-detected match on an existing seed-1 log (Tables VIII, XI, XII,
XIV) or by direct provenance-path inspection (Table IX, XV) -- see each
script's own header comment for its specific evidence. The "final locked"
CUSUM/VeReMi settings baked into every wrapper below (`CUSUM_H=0.8`,
`CUSUM_MIN_OBS=3`, `CUSUM_EDGE_MAX=0.50`, `VEREMI_MODE=shadow`,
`SIMTIME=36`, `ATTACK_X0=560`, `ATTACK_X1=720`) match what actually
produced the locked CSVs, not `run_handover_tunable.sh`'s own older bare
defaults.

| Paper table | Script | Command |
|---|---|---|
| Table VII (Handover Ablation, runway curve) | `run_crossing_relative_stress.sh` | `for TAIL in 1.0 1.1 1.2 1.3 1.4 1.5; do for MODE in ON OFF; do for SEED in $(seq 1 15); do MODE=$MODE SEED=$SEED ATTACK_CROSSING_OFFSET_SEC=-1.5 ATTACK_CROSSING_DURATION_SEC=$(python3 -c "print(1.5+$TAIL)") OUTDIR=results/handover_repro/tail_$TAIL bash scripts/run_crossing_relative_stress.sh; done; done; done` |
| Table VIII (HTD Sensitivity) | `run_table_viii_htd_sensitivity_15seed.sh` | `bash scripts/run_table_viii_htd_sensitivity_15seed.sh` (sweeps `HTD_DISCOUNT` over 0.10/0.30/0.50/0.70/1.00) |
| Table IX (Guarded CUSUM Ablation) | `run_table_ix_cusum_ablation_15seed.sh` | `bash scripts/run_table_ix_cusum_ablation_15seed.sh` (toggles `DISABLE_CUSUM`; writes to a fresh `guarded_cusum_onoff_repro_{ON,OFF}_15seed` dir rather than an ambiguous historical one -- see script header) |
| Table X (Attack Variants) | `run_attack_type_robustness_15seed.sh` | `bash scripts/run_attack_type_robustness_15seed.sh` (defaults: AT1-AT4, drops 0/10/20, 15 seeds; set `ATTACK_TYPES="0 5"` for composite/adaptive) |
| Table XI (Beacon Falsification Probability) | `run_table_xi_beacon_falsification_15seed.sh` | `bash scripts/run_table_xi_beacon_falsification_15seed.sh` (sweeps `ATTACK_RATE` over 20/50/70/80) |
| Table XII (Packet-Loss Robustness) | `run_table_xii_packet_loss_15seed.sh` | `bash scripts/run_table_xii_packet_loss_15seed.sh` (sweeps `PKT_DROP_RATE` over 0/5/10/20) |
| Table XIII (Baseline Comparison) | `run_table_xiii_baseline_comparison.sh` | Run Table XII first, then `bash scripts/run_table_xiii_baseline_comparison.sh` -- re-analyzes Table XII's raw beacon logs with a VeReMi-style local segment-reset baseline; see script header for a confidence caveat (this one's numeric agreement with the locked CSV was not independently re-run) |
| Table XIV (Scalability) | `run_table_xiv_scalability_15seed.sh` | `bash scripts/run_table_xiv_scalability_15seed.sh` (sweeps `NCARS` over 10/20/30/50, also records per-run wall-clock runtime) |
| Table XV (Overlap BAN Guard) | `run_table_xv_overlap_guard_15seed.sh` | `bash scripts/run_table_xv_overlap_guard_15seed.sh` (toggles `EDGE_OVERLAP_BAN_GUARD`, AT5/DROP20) |
| Clean Safety (Section VI-B) | `run_clean_safety_after_override_drops_15seed.sh` / `run_clean_safety_speedtol6_drops_15seed.sh` | `bash scripts/run_clean_safety_after_override_drops_15seed.sh` |

Every wrapper above is resumable (skips a seed whose log already contains
`[PAYOFF]`) and safe to re-run against an existing partial results tree.

## 6. Verifying results against the locked CSVs

```bash
cd ~/v2x-repro   # or wherever this artifact's paper_artifact_v1.0/ lives
python3 analysis/verify_tables.py
```

Prints PASS/✓ for every checked table cell and writes
`artifact_verification_report.txt`. Requires `pandas` (see
`requirements.txt`).

## 7. Regenerating figures

```bash
cd paper_draft   # or wherever bare_jrnl.tex + figures/ live
python3 ../paper_artifact_v1.0/code/analysis/plot_handover_curve.py       # fig4
python3 ../paper_artifact_v1.0/code/analysis/plot_fig5_cusum_schematic.py # fig5
python3 ../paper_artifact_v1.0/code/analysis/plot_fig6_fig7_fig8.py       # fig6/7/8
python3 ../paper_artifact_v1.0/code/analysis/plot_fig3_validation_matrix.py  # fig3
python3 ../paper_artifact_v1.0/code/analysis/plot_fig1_architecture.py    # fig1
```

Each script writes directly into `figures/` (relative to wherever it is
run from — run from the directory containing `figures/`).

## 8. Running long/multi-hour campaigns unattended

Two gotchas discovered while assembling this artifact, both worth
following even on a machine you trust:

- **Log outside `/tmp`, not into it.** A background campaign lost its log
  to a host crash that wiped `/tmp` mid-run. Redirect to a path under your
  project/results directory instead.
- **Make sweep loops resumable.** Skip a `(mode, seed)` combination if its
  output already contains the run script's completion marker
  (`Saved log:` for `run_crossing_relative_stress.sh`). A multi-hour sweep
  that isn't resumable re-does everything from zero after any interruption.

Use `tmux new-session -d -s <name> '<your sweep command> > results/<name>/run.log 2>&1'`
so the run survives an SSH disconnect, and always
`source ~/miniconda3/etc/profile.d/conda.sh && conda activate ns3-env`
explicitly inside the script itself — a fresh `tmux`/background session
does not inherit an env activated interactively in a different shell.
