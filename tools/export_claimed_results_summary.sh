#!/bin/bash

OUT="results/final_locked_csv/CLAIMED_RESULTS_SUMMARY_FOR_REVIEWER.txt"

echo "====================================================" > $OUT
echo "FINAL CLAIMED RESULTS SUMMARY - PAPER EVIDENCE AUDIT" >> $OUT
echo "Generated: $(date)" >> $OUT
echo "====================================================" >> $OUT

echo "" >> $OUT
echo "1. FINAL LOCKED EXPERIMENT STATUS" >> $OUT
echo "----------------------------------------------------" >> $OUT
cat results/final_locked_csv/FINAL_EXPERIMENT_STATUS_LOCKED_V2.md >> $OUT 2>/dev/null


echo "" >> $OUT
echo "====================================================" >> $OUT
echo "2. ATTACK VARIANT ROBUSTNESS (MAIN CLAIM)" >> $OUT
echo "====================================================" >> $OUT

cat results/final_locked_csv/attack_variants_patched_final/attack_variant_patched_final_aggregate_summary.csv >> $OUT 2>/dev/null


echo "" >> $OUT
echo "====================================================" >> $OUT
echo "3. PACKET LOSS ROBUSTNESS" >> $OUT
echo "====================================================" >> $OUT

cat results/final_locked_csv/packet_loss_robustness_aggregate_summary.csv >> $OUT 2>/dev/null


echo "" >> $OUT
echo "====================================================" >> $OUT
echo "4. CLEAN SAFETY / FALSE POSITIVE VALIDATION" >> $OUT
echo "====================================================" >> $OUT

cat results/final_locked_csv/clean_cusum_safety_aggregate_summary.csv >> $OUT 2>/dev/null


echo "" >> $OUT
echo "====================================================" >> $OUT
echo "5. OVERLAP BAN GUARD ABLATION" >> $OUT
echo "====================================================" >> $OUT

cat results/final_locked_csv/overlap_guard_ablation/overlap_guard_ablation_AT5_DROP20_summary.csv >> $OUT 2>/dev/null


echo "" >> $OUT
echo "====================================================" >> $OUT
echo "6. FINAL CODE CONSISTENCY RERUN" >> $OUT
echo "====================================================" >> $OUT

cat results/final_locked_csv/final_code_consistency_rerun/final_code_consistency_aggregate_summary.csv >> $OUT 2>/dev/null


echo "" >> $OUT
echo "====================================================" >> $OUT
echo "7. SENSITIVE HANDOVER/CUSUM DIAGNOSTIC ABLATION" >> $OUT
echo "====================================================" >> $OUT

cat results/final_locked_csv/patched_sensitive_ablation_smoke/patched_sensitive_ablation_smoke_summary.csv >> $OUT 2>/dev/null


echo "" >> $OUT
echo "====================================================" >> $OUT
echo "8. ARCHIVED RAW DATA INFORMATION" >> $OUT
echo "====================================================" >> $OUT

echo "Attack variant raw logs:" >> $OUT
find results/attack_type_robustness_AT*_DROP*_guarded_cusum_15seed \
-name "ON_seed*_x560_720_t36.log" | wc -l >> $OUT

echo "Final code consistency logs:" >> $OUT
find results/final_code_consistency_rerun \
-name "*.log" | wc -l >> $OUT


echo "" >> $OUT
echo "====================================================" >> $OUT
echo "END OF CLAIM AUDIT" >> $OUT


echo "Created:"
echo $OUT
