import csv
import re
import math
from pathlib import Path

BASE = Path("results/final_locked_csv")
B = BASE / "baseline_veremi"

PROPOSED_RAW = BASE / "packet_loss_robustness_per_seed_raw.csv"
SEG_RAW = B / "veremi_segment_reset_packet_loss_k123_per_seed_raw.csv"
FAIR_COMPARE = B / "proposed_vs_best_clean_safe_segment_reset_veremi_packet_loss.csv"
FRAG_CID = B / "fragmentation_audit_n10_ar50_drop0_per_cid.csv"
THRESHOLD = B / "segment_reset_veremi_threshold_selection_summary.csv"

OUT_STATS = B / "proposed_vs_best_clean_safe_segment_reset_statistical_tests.csv"
OUT_CASES = B / "fragmented_evidence_case_study_12_cases.csv"
OUT_MASTER = B / "reviewer_ready_baseline_master_summary.csv"

def pct(a, b):
    return round(100.0 * a / b, 2) if b else 0.0

def parse_ids(s):
    if s is None:
        return set()
    s = str(s).strip()
    if s == "" or s.lower() in {"none", "nan", "na", "n/a", "-"}:
        return set()
    return set(int(x) for x in re.findall(r"\d+", s))

def wilson_ci(success, total, z=1.96):
    if total == 0:
        return "", ""
    phat = success / total
    denom = 1 + z*z/total
    center = (phat + z*z/(2*total)) / denom
    half = z * math.sqrt((phat*(1-phat) + z*z/(4*total)) / total) / denom
    return round(100*(center-half), 2), round(100*(center+half), 2)

def exact_binomial_two_sided(a, b):
    # exact sign/McNemar test using discordant counts a,b
    n = a + b
    if n == 0:
        return 1.0
    k = min(a, b)
    p = 2 * sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return round(min(1.0, p), 6)

def condition_sort_key(c):
    m = re.search(r"\d+", c)
    return int(m.group()) if m else 999

# Read selected K per condition from fair comparison
fair_rows = list(csv.DictReader(FAIR_COMPARE.open()))
selected_k = {}
for r in fair_rows:
    if r["method"] == "Best_Clean_Safe_Local_Segment_Reset_VeReMi":
        m = re.search(r"K=(\d+)", r["threshold_policy"])
        if m:
            selected_k[r["condition"]] = int(m.group(1))

# Maps
prop_rows = list(csv.DictReader(PROPOSED_RAW.open()))
seg_rows = list(csv.DictReader(SEG_RAW.open()))

prop_map = {(r["condition"], int(r["seed"])): r for r in prop_rows}
seg_map = {}
for r in seg_rows:
    seg_map[(r["condition"], int(r["seed"]), int(r["K"]))] = r

stats_rows = []

for condition in sorted(selected_k.keys(), key=condition_sort_key):
    K = selected_k[condition]

    seed_pairs = []
    all_mal_total = 0
    all_hon_total = 0

    prop_total_det = 0
    prop_total_fp = 0
    seg_total_det = 0
    seg_total_fp = 0

    mcnemar_prop_only = 0
    mcnemar_seg_only = 0
    both_detect = 0
    both_miss = 0

    fp_prop_only = 0
    fp_seg_only = 0
    fp_both = 0
    fp_neither = 0

    per_seed_prop_better = 0
    per_seed_seg_better = 0
    per_seed_ties = 0

    for (cond, seed), p in sorted(prop_map.items()):
        if cond != condition:
            continue

        s = seg_map.get((condition, seed, K))
        if not s:
            continue

        # Malicious ID universe from segment-reset baseline raw
        mal_ids = parse_ids(s.get("detected_ids")) | parse_ids(s.get("missed_ids"))
        prop_missed = parse_ids(p.get("missed_ids"))
        seg_detected = parse_ids(s.get("detected_ids"))
        seg_missed = parse_ids(s.get("missed_ids"))

        prop_detected = mal_ids - prop_missed

        # Proposed may detect all except missed_ids; sanity fallback if needed
        prop_count = int(p["caught"])
        seg_count = int(s["detected"])
        mal_count = int(s["malicious"])
        hon_count = int(s["honest"])

        all_mal_total += mal_count
        all_hon_total += hon_count
        prop_total_det += prop_count
        seg_total_det += seg_count
        prop_total_fp += int(p["false_positive"])
        seg_total_fp += int(s["false_positive"])

        for cid in mal_ids:
            pd = cid in prop_detected
            sd = cid in seg_detected
            if pd and sd:
                both_detect += 1
            elif pd and not sd:
                mcnemar_prop_only += 1
            elif sd and not pd:
                mcnemar_seg_only += 1
            else:
                both_miss += 1

        prop_fp_ids = parse_ids(p.get("false_positive_ids"))
        seg_fp_ids = parse_ids(s.get("false_positive_ids"))

        # Honest ID universe is not always explicitly listed, so count FP discordance by IDs where available.
        for cid in (prop_fp_ids | seg_fp_ids):
            pf = cid in prop_fp_ids
            sf = cid in seg_fp_ids
            if pf and sf:
                fp_both += 1
            elif pf and not sf:
                fp_prop_only += 1
            elif sf and not pf:
                fp_seg_only += 1

        diff = prop_count - seg_count
        if diff > 0:
            per_seed_prop_better += 1
        elif diff < 0:
            per_seed_seg_better += 1
        else:
            per_seed_ties += 1

        seed_pairs.append({
            "condition": condition,
            "seed": seed,
            "selected_K": K,
            "proposed_detected": prop_count,
            "segment_reset_detected": seg_count,
            "diff": diff,
            "proposed_fp": int(p["false_positive"]),
            "segment_reset_fp": int(s["false_positive"]),
        })

    prop_ci = wilson_ci(prop_total_det, all_mal_total)
    seg_ci = wilson_ci(seg_total_det, all_mal_total)
    prop_fpr_ci = wilson_ci(prop_total_fp, all_hon_total)
    seg_fpr_ci = wilson_ci(seg_total_fp, all_hon_total)

    stats_rows.append({
        "condition": condition,
        "selected_baseline_K": K,
        "valid_seeds": len(seed_pairs),

        "proposed_caught": f"{prop_total_det}/{all_mal_total}",
        "proposed_DR_percent": pct(prop_total_det, all_mal_total),
        "proposed_DR_CI95_low": prop_ci[0],
        "proposed_DR_CI95_high": prop_ci[1],
        "proposed_false_positive": f"{prop_total_fp}/{all_hon_total}",
        "proposed_FPR_percent": pct(prop_total_fp, all_hon_total),
        "proposed_FPR_CI95_low": prop_fpr_ci[0],
        "proposed_FPR_CI95_high": prop_fpr_ci[1],

        "segment_reset_caught": f"{seg_total_det}/{all_mal_total}",
        "segment_reset_DR_percent": pct(seg_total_det, all_mal_total),
        "segment_reset_DR_CI95_low": seg_ci[0],
        "segment_reset_DR_CI95_high": seg_ci[1],
        "segment_reset_false_positive": f"{seg_total_fp}/{all_hon_total}",
        "segment_reset_FPR_percent": pct(seg_total_fp, all_hon_total),
        "segment_reset_FPR_CI95_low": seg_fpr_ci[0],
        "segment_reset_FPR_CI95_high": seg_fpr_ci[1],

        "DR_gain_percentage_points": round(pct(prop_total_det, all_mal_total) - pct(seg_total_det, all_mal_total), 2),
        "FPR_gain_percentage_points": round(pct(seg_total_fp, all_hon_total) - pct(prop_total_fp, all_hon_total), 2),

        "mcnemar_prop_only_detected": mcnemar_prop_only,
        "mcnemar_segment_only_detected": mcnemar_seg_only,
        "mcnemar_both_detected": both_detect,
        "mcnemar_both_missed": both_miss,
        "mcnemar_exact_two_sided_p": exact_binomial_two_sided(mcnemar_prop_only, mcnemar_seg_only),

        "per_seed_proposed_better": per_seed_prop_better,
        "per_seed_segment_reset_better": per_seed_seg_better,
        "per_seed_ties": per_seed_ties,
        "per_seed_sign_test_two_sided_p": exact_binomial_two_sided(per_seed_prop_better, per_seed_seg_better),

        "false_positive_prop_only_ids": fp_prop_only,
        "false_positive_segment_only_ids": fp_seg_only,
        "false_positive_both_ids": fp_both,
    })

with OUT_STATS.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(stats_rows[0].keys()))
    writer.writeheader()
    writer.writerows(stats_rows)

# Fragmented case table
frag_rows = list(csv.DictReader(FRAG_CID.open()))
cases = [
    r for r in frag_rows
    if r["malicious"] == "YES" and r["strong_fragmentation_case"] == "YES"
]

case_cols = [
    "seed", "cid", "proposed_detected",
    "beacons", "total_violating_observations",
    "central_detected", "central_max_window_violations",
    "rxuav_memory_detected", "rxuav_memory_max_window_violations",
    "rxuav_segment_detected", "rxuav_segment_max_window_violations",
    "zone_segment_detected", "zone_segment_max_window_violations",
    "rxuav_changes", "zone_changes",
    "source_log_path"
]

with OUT_CASES.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=case_cols)
    writer.writeheader()
    for r in cases:
        writer.writerow({c: r[c] for c in case_cols})

# Master summary table
threshold_rows = list(csv.DictReader(THRESHOLD.open()))
master_rows = []

for r in threshold_rows:
    master_rows.append({
        "section": "threshold_policy",
        "condition": "CLEAN_HONEST",
        "method": f"Local_Segment_Reset_VeReMi_K{r['K']}_W5",
        "main_result": f"clean_FP={r['clean_false_positive']}, clean_FPR={r['clean_FPR_percent']}%",
        "interpretation": r["decision"],
    })

for r in stats_rows:
    master_rows.append({
        "section": "fair_packet_loss_comparison",
        "condition": r["condition"],
        "method": "Proposed_vs_Best_Clean_Safe_Local_Segment_Reset_VeReMi",
        "main_result": (
            f"Proposed {r['proposed_caught']} DR={r['proposed_DR_percent']}%, "
            f"FPR={r['proposed_FPR_percent']}%; "
            f"Baseline {r['segment_reset_caught']} DR={r['segment_reset_DR_percent']}%, "
            f"FPR={r['segment_reset_FPR_percent']}%; "
            f"DR_gain={r['DR_gain_percentage_points']}pp"
        ),
        "interpretation": (
            "proposed maintains handover trust continuity; local baseline resets memory at each contiguous RXUAV segment"
        ),
    })

master_rows.append({
    "section": "fragmented_case_study",
    "condition": "DROP0",
    "method": "Proposed_vs_Local_Segment_Reset_VeReMi",
    "main_result": f"{len(cases)} malicious fragmented cases: proposed/central detect while local segment-reset misses",
    "interpretation": "direct evidence that cross-handover trust continuity closes the fragmentation gap",
})

with OUT_MASTER.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(master_rows[0].keys()))
    writer.writeheader()
    writer.writerows(master_rows)

print("Saved:")
print(OUT_STATS)
print(OUT_CASES)
print(OUT_MASTER)

print()
print("===== STATISTICAL TESTS =====")
for r in stats_rows:
    print(r)

print()
print("===== FRAGMENTED CASES =====")
print("case_count:", len(cases))
for r in cases:
    print(
        f"seed={r['seed']} cid={r['cid']} proposed={r['proposed_detected']} "
        f"central_max={r['central_max_window_violations']} "
        f"rxseg_detected={r['rxuav_segment_detected']} "
        f"rxseg_max={r['rxuav_segment_max_window_violations']}"
    )
