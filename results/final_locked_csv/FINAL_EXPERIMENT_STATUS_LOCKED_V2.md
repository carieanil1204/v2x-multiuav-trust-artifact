# Final Locked Experiment Status V2

Generated: 2026-07-20T13:45:53

## Final decision

No further experiments are required before writing the Results section.

Use dedicated locked Handover and CUSUM ablations as the main component ablations. Use the final-code consistency rerun and patched sensitive ablation smoke only as implementation-consistency and diagnostic evidence.

| Section | Experiment | Status | Exists | Lines | Primary file | Notes |
|---|---|---|---|---:|---|---|
| Core | Handover ON/OFF | LOCKED | YES | 3 | `results/final_locked_csv/handover_onoff_aggregate_summary.csv` | Handover ON improves DR over OFF while keeping FPR 0. |
| Core | Guarded CUSUM ON/OFF | LOCKED | YES | 3 | `results/final_locked_csv/guarded_cusum_onoff_aggregate_summary.csv` | Guarded CUSUM improves detection with zero false positives. |
| Safety | Clean CUSUM safety | LOCKED | YES | 2 | `results/final_locked_csv/clean_cusum_safety_aggregate_summary.csv` | Clean honest runs: 0/150 false positives. |
| Sensitivity | HTD sensitivity | LOCKED | YES | 6 | `results/final_locked_csv/htd_sensitivity_aggregate_summary.csv` | HTD 0.10–0.70 robust with zero false positives; HTD=0.30 used as final moderate setting. |
| Robustness | Attack-rate robustness | LOCKED | YES | 4 | `results/final_locked_csv/attack_rate_robustness_aggregate_summary.csv` | AR20/AR50/AR70 evaluated; AR80 excluded from main due no honest vehicles. |
| Robustness | Packet-loss robustness | LOCKED | YES | 5 | `results/final_locked_csv/packet_loss_robustness_aggregate_summary.csv` | DROP0/5/10/20 evaluated; zero false positives. |
| Scalability | Scalability | LOCKED | YES | 5 | `results/final_locked_csv/scalability_aggregate_summary.csv` | N=10/20/30/50; safety remains FPR 0 but detection weakens at high density. |
| Scalability | Runtime overhead | LOCKED | YES | 5 | `results/final_locked_csv/scalability_runtime_overhead.csv` | Runtime grows super-linearly with vehicle count. |
| Gate audit | Bayesian/Nash gate audit | LOCKED | YES | 185 | `results/final_locked_csv/bayesian_nash_gate_audit_final_v2.csv` | Audit shows honest BAN proposals were prevented from becoming confirmed honest BANs. |
| Baseline | Fair local segment-reset VeReMi packet-loss comparison | LOCKED | YES | 9 | `results/final_locked_csv/baseline_veremi/proposed_vs_best_clean_safe_segment_reset_veremi_packet_loss.csv` | Main fair baseline comparison; excludes unsafe K1 and uses clean-safe K2. |
| Baseline | Baseline statistical tests | LOCKED | YES | 5 | `results/final_locked_csv/baseline_veremi/proposed_vs_best_clean_safe_segment_reset_statistical_tests.csv` | Includes CIs, McNemar tests, and sign tests. |
| Baseline | Fragmented evidence case study | LOCKED | YES | 13 | `results/final_locked_csv/baseline_veremi/fragmented_evidence_case_study_12_cases.csv` | Shows cases where segment-reset local detector misses but handover-aware proposed system detects. |
| Baseline | Reviewer-ready baseline master summary | LOCKED | YES | 9 | `results/final_locked_csv/baseline_veremi/reviewer_ready_baseline_master_summary.csv` | Use this for reviewer-facing baseline explanation. |
| Attack variants | Final patched attack-variant robustness | LOCKED | YES | 19 | `results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_aggregate_summary.csv` | AT0–AT5, DROP0/10/20, 15 seeds each, same patched config, fallback 0, FPR 0 in all 18 conditions. |
| Attack variants | Final patched attack-variant per-seed raw | LOCKED | YES | 271 | `results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_per_seed_raw.csv` | 270 seed-level rows plus header. |
| Attack variants | Final patched attack-variant source paths | LOCKED | YES | 271 | `results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_source_paths.csv` | Source log path for every AT/drop/seed run. |
| Attack variants | Final patched attack-variant config | LOCKED | YES | 12 | `results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_config.txt` | Final config: hard_only, speed_tol=6.0, overlap_ban_guard=1, min_p=0.50. |
| Ablation | Overlap BAN guard ablation | LOCKED | YES | 3 | `results/final_locked_csv/overlap_guard_ablation/overlap_guard_ablation_AT5_DROP20_summary.csv` | Guard OFF: 101/105, FP 1/45. Guard ON: 101/105, FP 0/45. |
| Ablation | Overlap BAN guard ablation per-seed raw | LOCKED | YES | 31 | `results/final_locked_csv/overlap_guard_ablation/overlap_guard_ablation_AT5_DROP20_per_seed_raw.csv` | Per-seed data for Guard OFF vs Guard ON. |
| Archive | Final attack-variant archive | LOCKED | YES | 3 | `results/final_locked_csv/attack_variants_patched_final/archive/SHA256SUMS_attack_variant_csvs.txt` | Checksums for final attack-variant CSVs; raw logs also archived. |
| Smoke test | Final-code consistency rerun | LOCKED_SMOKE_TEST | YES | 10 | `results/final_locked_csv/final_code_consistency_rerun/final_code_consistency_aggregate_summary.csv` | 135/135 final patched-code runs completed; fallback 0; clean safety preserved. Not used as main Handover/CUSUM ablation due ceiling effect. |
| Diagnostic | Patched sensitive ablation smoke | LOCKED_DIAGNOSTIC | YES | 5 | `results/final_locked_csv/patched_sensitive_ablation_smoke/patched_sensitive_ablation_smoke_summary.csv` | Confirms patched-code ablation controls remain active: handover ON 13/35 vs OFF 0/35; CUSUM ON 30/35 vs OFF 26/35; FP 0; fallback 0. |
Handover cold-start verification: 145 Z1->Z2 cold-start events recorded
