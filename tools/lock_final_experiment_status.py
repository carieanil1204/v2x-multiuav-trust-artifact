import csv
from pathlib import Path
from datetime import datetime

OUTDIR = Path("results/final_locked_csv")
STATUS_CSV = OUTDIR / "FINAL_EXPERIMENT_STATUS_LOCKED.csv"
STATUS_MD  = OUTDIR / "FINAL_EXPERIMENT_STATUS_LOCKED.md"

records = [
    {
        "section": "Core",
        "experiment": "Handover ON/OFF",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/handover_onoff_aggregate_summary.csv",
        "notes": "Handover ON improves DR over OFF while keeping FPR 0."
    },
    {
        "section": "Core",
        "experiment": "Guarded CUSUM ON/OFF",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/guarded_cusum_onoff_aggregate_summary.csv",
        "notes": "Guarded CUSUM improves detection with zero false positives."
    },
    {
        "section": "Safety",
        "experiment": "Clean CUSUM safety",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/clean_cusum_safety_aggregate_summary.csv",
        "notes": "Clean honest runs: 0/150 false positives."
    },
    {
        "section": "Sensitivity",
        "experiment": "HTD sensitivity",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/htd_sensitivity_aggregate_summary.csv",
        "notes": "HTD 0.10–0.70 robust with zero false positives; HTD=0.30 used as final moderate setting."
    },
    {
        "section": "Robustness",
        "experiment": "Attack-rate robustness",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/attack_rate_robustness_aggregate_summary.csv",
        "notes": "AR20/AR50/AR70 evaluated; AR80 excluded from main due no honest vehicles."
    },
    {
        "section": "Robustness",
        "experiment": "Packet-loss robustness",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/packet_loss_robustness_aggregate_summary.csv",
        "notes": "DROP0/5/10/20 evaluated; zero false positives."
    },
    {
        "section": "Scalability",
        "experiment": "Scalability",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/scalability_aggregate_summary.csv",
        "notes": "N=10/20/30/50; safety remains FPR 0 but detection weakens at high density."
    },
    {
        "section": "Scalability",
        "experiment": "Runtime overhead",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/scalability_runtime_overhead.csv",
        "notes": "Runtime grows super-linearly with vehicle count."
    },
    {
        "section": "Gate audit",
        "experiment": "Bayesian/Nash gate audit",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/bayesian_nash_gate_audit_final_v2.csv",
        "notes": "Audit shows honest BAN proposals were prevented from becoming confirmed honest BANs."
    },
    {
        "section": "Baseline",
        "experiment": "Fair local segment-reset VeReMi packet-loss comparison",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/baseline_veremi/proposed_vs_best_clean_safe_segment_reset_veremi_packet_loss.csv",
        "notes": "Main fair baseline comparison; excludes unsafe K1 and uses clean-safe K2."
    },
    {
        "section": "Baseline",
        "experiment": "Baseline statistical tests",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/baseline_veremi/proposed_vs_best_clean_safe_segment_reset_statistical_tests.csv",
        "notes": "Includes CIs, McNemar tests, and sign tests."
    },
    {
        "section": "Baseline",
        "experiment": "Fragmented evidence case study",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/baseline_veremi/fragmented_evidence_case_study_12_cases.csv",
        "notes": "Shows cases where segment-reset local detector misses but handover-aware proposed system detects."
    },
    {
        "section": "Baseline",
        "experiment": "Reviewer-ready baseline master summary",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/baseline_veremi/reviewer_ready_baseline_master_summary.csv",
        "notes": "Use this for reviewer-facing baseline explanation."
    },
    {
        "section": "Attack variants",
        "experiment": "Final patched attack-variant robustness",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_aggregate_summary.csv",
        "notes": "AT0–AT5, DROP0/10/20, 15 seeds each, same patched config, fallback 0, FPR 0 in all 18 conditions."
    },
    {
        "section": "Attack variants",
        "experiment": "Final patched attack-variant per-seed raw",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_per_seed_raw.csv",
        "notes": "270 seed-level rows plus header."
    },
    {
        "section": "Attack variants",
        "experiment": "Final patched attack-variant source paths",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_source_paths.csv",
        "notes": "Source log path for every AT/drop/seed run."
    },
    {
        "section": "Attack variants",
        "experiment": "Final patched attack-variant config",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_config.txt",
        "notes": "Final config: hard_only, speed_tol=6.0, overlap_ban_guard=1, min_p=0.50."
    },
    {
        "section": "Ablation",
        "experiment": "Overlap BAN guard ablation",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/overlap_guard_ablation/overlap_guard_ablation_AT5_DROP20_summary.csv",
        "notes": "Guard OFF: 101/105, FP 1/45. Guard ON: 101/105, FP 0/45."
    },
    {
        "section": "Ablation",
        "experiment": "Overlap BAN guard ablation per-seed raw",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/overlap_guard_ablation/overlap_guard_ablation_AT5_DROP20_per_seed_raw.csv",
        "notes": "Per-seed data for Guard OFF vs Guard ON."
    },
    {
        "section": "Archive",
        "experiment": "Final attack-variant archive",
        "status": "LOCKED",
        "primary_csv": "results/final_locked_csv/attack_variants_patched_final/archive/SHA256SUMS_attack_variant_csvs.txt",
        "notes": "Checksums for final attack-variant CSVs; raw logs also archived."
    },
]

for r in records:
    p = Path(r["primary_csv"])
    r["exists"] = "YES" if p.exists() else "NO"
    r["size_bytes"] = p.stat().st_size if p.exists() else 0
    if p.exists() and p.is_file():
        try:
            r["line_count"] = sum(1 for _ in p.open(errors="ignore"))
        except Exception:
            r["line_count"] = ""
    else:
        r["line_count"] = ""

with STATUS_CSV.open("w", newline="") as f:
    fieldnames = ["section", "experiment", "status", "exists", "size_bytes", "line_count", "primary_csv", "notes"]
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(records)

with STATUS_MD.open("w") as f:
    f.write("# Final Locked Experiment Status\n\n")
    f.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n\n")
    f.write("## Summary\n\n")
    f.write("- Core experiments: locked\n")
    f.write("- Baseline comparison: locked\n")
    f.write("- Final patched attack variants: locked\n")
    f.write("- Overlap BAN guard ablation: locked\n\n")
    f.write("## Locked files\n\n")
    f.write("| Section | Experiment | Status | Exists | Lines | Primary file | Notes |\n")
    f.write("|---|---|---|---|---:|---|---|\n")
    for r in records:
        f.write(
            f"| {r['section']} | {r['experiment']} | {r['status']} | {r['exists']} | "
            f"{r['line_count']} | `{r['primary_csv']}` | {r['notes']} |\n"
        )

print("Wrote:")
print(" ", STATUS_CSV)
print(" ", STATUS_MD)

missing = [r for r in records if r["exists"] != "YES"]
if missing:
    print("\nWARNING: missing files:")
    for r in missing:
        print(" -", r["experiment"], "=>", r["primary_csv"])
else:
    print("\nAll listed locked files exist.")
