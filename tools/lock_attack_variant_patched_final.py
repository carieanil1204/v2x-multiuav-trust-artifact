import csv, re, math, statistics as st
from pathlib import Path

OUTDIR = Path("results/final_locked_csv/attack_variants_patched_final")
OUTDIR.mkdir(parents=True, exist_ok=True)

ATTACK_NAMES = {
    0: "composite",
    1: "timestamp_only",
    2: "gps_only",
    3: "speed_only",
    4: "stealthy",
    5: "adaptive",
}
DROPS = [0, 10, 20]
SEEDS_EXPECTED = 15

payoff_re = re.compile(
    r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)"
)

def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z*z/n
    centre = p + z*z/(2*n)
    margin = z * math.sqrt((p*(1-p) + z*z/(4*n)) / n)
    lo = (centre - margin) / den
    hi = (centre + margin) / den
    return (100*lo, 100*hi)

per_seed_rows = []
summary_rows = []
source_rows = []

for at in range(6):
    for drop in DROPS:
        d = Path(f"results/attack_type_robustness_AT{at}_DROP{drop}_guarded_cusum_15seed")
        logs = sorted(d.glob("ON_seed*_x560_720_t36.log"))

        seed_rows = []
        for log in logs:
            seed_m = re.search(r"ON_seed(\d+)_", log.name)
            if not seed_m:
                continue
            seed = int(seed_m.group(1))
            txt = log.read_text(errors="ignore")

            complete = "SIMULATION COMPLETE" in txt
            fallback = txt.count("[EDGE-FALLBACK]")

            mal = caught = hon = fp = 0
            for line in txt.splitlines():
                m = payoff_re.search(line)
                if not m:
                    continue
                cid, demoted, malicious = m.groups()
                if malicious == "YES":
                    mal += 1
                    caught += int(demoted == "YES")
                else:
                    hon += 1
                    fp += int(demoted == "YES")

            row = {
                "experiment": "attack_variant_robustness_patched_final",
                "attack_type": at,
                "attack_name": ATTACK_NAMES[at],
                "condition": f"DROP{drop}",
                "seed": seed,
                "complete": int(complete),
                "fallback_count": fallback,
                "malicious": mal,
                "caught": caught,
                "honest": hon,
                "false_positive": fp,
                "DR_percent": round(100*caught/mal, 2) if mal else "",
                "FPR_percent": round(100*fp/hon, 2) if hon else "",
                "log_path": str(log),
            }
            seed_rows.append(row)
            per_seed_rows.append(row)
            source_rows.append({
                "attack_type": at,
                "attack_name": ATTACK_NAMES[at],
                "condition": f"DROP{drop}",
                "seed": seed,
                "log_path": str(log),
            })

        valid = [r for r in seed_rows if r["complete"] == 1]
        total_mal = sum(r["malicious"] for r in valid)
        total_caught = sum(r["caught"] for r in valid)
        total_hon = sum(r["honest"] for r in valid)
        total_fp = sum(r["false_positive"] for r in valid)
        total_fallback = sum(r["fallback_count"] for r in valid)

        drs = [float(r["DR_percent"]) for r in valid if r["DR_percent"] != ""]
        fprs = [float(r["FPR_percent"]) for r in valid if r["FPR_percent"] != ""]

        dr_lo, dr_hi = wilson(total_caught, total_mal)
        fpr_lo, fpr_hi = wilson(total_fp, total_hon)

        summary_rows.append({
            "experiment": "attack_variant_robustness_patched_final",
            "attack_type": at,
            "attack_name": ATTACK_NAMES[at],
            "condition": f"DROP{drop}",
            "valid_seeds": f"{len(valid)}/{SEEDS_EXPECTED}",
            "caught": f"{total_caught}/{total_mal}",
            "pooled_DR_percent": round(100*total_caught/total_mal, 2) if total_mal else "",
            "DR_mean_percent": round(st.mean(drs), 2) if drs else "",
            "DR_std": round(st.stdev(drs), 2) if len(drs) > 1 else 0.0,
            "DR_CI95_low": round(dr_lo, 2),
            "DR_CI95_high": round(dr_hi, 2),
            "false_positive": f"{total_fp}/{total_hon}",
            "pooled_FPR_percent": round(100*total_fp/total_hon, 2) if total_hon else "",
            "FPR_mean_percent": round(st.mean(fprs), 2) if fprs else "",
            "FPR_std": round(st.stdev(fprs), 2) if len(fprs) > 1 else 0.0,
            "FPR_CI95_low": round(fpr_lo, 2),
            "FPR_CI95_high": round(fpr_hi, 2),
            "fallback_total": total_fallback,
            "source_dir": str(d),
            "config": "hard_only; speed_tol=6.0; pos_tol=15.0; max_gap=3.0; min_violations=2; overlap_ban_guard=1; overlap_ban_min_p=0.50; cusum_input=veremi",
        })

def write_csv(path, rows):
    if not rows:
        return
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

write_csv(OUTDIR / "attack_variant_patched_final_per_seed_raw.csv", per_seed_rows)
write_csv(OUTDIR / "attack_variant_patched_final_aggregate_summary.csv", summary_rows)
write_csv(OUTDIR / "attack_variant_patched_final_source_paths.csv", source_rows)

with (OUTDIR / "attack_variant_patched_final_config.txt").open("w") as f:
    f.write("Final patched attack-variant robustness configuration\n")
    f.write("VEREMI_EVIDENCE_ENABLE=1\n")
    f.write("VEREMI_MODE=hard_only\n")
    f.write("VEREMI_GATE=0.12\n")
    f.write("VEREMI_SPEED_TOL=6.0\n")
    f.write("VEREMI_POS_TOL=15.0\n")
    f.write("VEREMI_MAX_GAP=3.0\n")
    f.write("VEREMI_MIN_VIOLATIONS=2\n")
    f.write("EDGE_OVERLAP_BAN_GUARD=1\n")
    f.write("EDGE_OVERLAP_BAN_MIN_P=0.50\n")
    f.write("CUSUM_INPUT_MODE=veremi\n")
    f.write("Strong early-confirm override=enabled\n")

print("Wrote:")
for p in sorted(OUTDIR.iterdir()):
    print(" ", p)
