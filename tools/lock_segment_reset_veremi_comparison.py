import csv
from pathlib import Path

BASE = Path("results/final_locked_csv/baseline_veremi")
SUMMARY = BASE / "fragmentation_audit_n10_ar50_drop0_summary.csv"
OUT = BASE / "proposed_vs_veremi_segment_reset_handover_comparison.csv"

rows = list(csv.DictReader(SUMMARY.open()))
mal = next(r for r in rows if r["group"] == "MALICIOUS")
hon = next(r for r in rows if r["group"] == "HONEST")

total_mal = int(mal["vehicles"])
total_hon = int(hon["vehicles"])

def pct(x, y):
    return round(100.0 * x / y, 2) if y else 0.0

out_rows = [
    {
        "method": "Proposed_UAV_Edge_Trust_Framework",
        "state_model": "trust_state_transferred_across_handover_with_HTD",
        "caught": f'{mal["proposed_detected"]}/{total_mal}',
        "DR_percent": pct(int(mal["proposed_detected"]), total_mal),
        "false_positive": f'{hon["proposed_detected"]}/{total_hon}',
        "FPR_percent": pct(int(hon["proposed_detected"]), total_hon),
        "interpretation": "proposed handover-aware trust continuity",
    },
    {
        "method": "Centralized_Full_VeReMi_OBS_K3_W5",
        "state_model": "global_CID_history_oracle",
        "caught": f'{mal["central_detected"]}/{total_mal}',
        "DR_percent": pct(int(mal["central_detected"]), total_mal),
        "false_positive": f'{hon["central_detected"]}/{total_hon}',
        "FPR_percent": pct(int(hon["central_detected"]), total_hon),
        "interpretation": "upper-bound physical-consistency detector",
    },
    {
        "method": "Local_Full_VeReMi_RXUAV_memory_OBS_K3_W5",
        "state_model": "per_CID_per_RXUAV_memory",
        "caught": f'{mal["rxuav_memory_detected"]}/{total_mal}',
        "DR_percent": pct(int(mal["rxuav_memory_detected"]), total_mal),
        "false_positive": f'{hon["rxuav_memory_detected"]}/{total_hon}',
        "FPR_percent": pct(int(hon["rxuav_memory_detected"]), total_hon),
        "interpretation": "local detector retaining prior vehicle state within same UAV identity",
    },
    {
        "method": "Local_Full_VeReMi_RXUAV_segment_reset_OBS_K3_W5",
        "state_model": "memory_resets_at_each_contiguous_RXUAV_segment",
        "caught": f'{mal["rxuav_segment_detected"]}/{total_mal}',
        "DR_percent": pct(int(mal["rxuav_segment_detected"]), total_mal),
        "false_positive": f'{hon["rxuav_segment_detected"]}/{total_hon}',
        "FPR_percent": pct(int(hon["rxuav_segment_detected"]), total_hon),
        "interpretation": "handover-fragmented local physical detector",
    },
    {
        "method": "Local_Full_VeReMi_ZONE_segment_reset_OBS_K3_W5",
        "state_model": "memory_resets_at_each_contiguous_zone_segment",
        "caught": f'{mal["zone_segment_detected"]}/{total_mal}',
        "DR_percent": pct(int(mal["zone_segment_detected"]), total_mal),
        "false_positive": f'{hon["zone_segment_detected"]}/{total_hon}',
        "FPR_percent": pct(int(hon["zone_segment_detected"]), total_hon),
        "interpretation": "zone-fragmented local physical detector",
    },
]

with OUT.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
    writer.writeheader()
    writer.writerows(out_rows)

print("Saved:", OUT)
print()
for r in out_rows:
    print(r)
