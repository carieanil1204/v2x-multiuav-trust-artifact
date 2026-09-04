import csv, re, math, statistics as st
from pathlib import Path

OUTDIR = Path("results/final_locked_csv/overlap_guard_ablation")
OUTDIR.mkdir(parents=True, exist_ok=True)

cases = [
    ("GUARD_OFF", 0, Path("results/overlap_guard_ablation_AT5_DROP20_GUARD_OFF_15seed")),
    ("GUARD_ON", 1, Path("results/overlap_guard_ablation_AT5_DROP20_GUARD_ON_locked")),
]

payoff_re = re.compile(r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)")

def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z*z/n
    centre = p + z*z/(2*n)
    margin = z * math.sqrt((p*(1-p) + z*z/(4*n)) / n)
    return (100*(centre-margin)/den, 100*(centre+margin)/den)

per_seed = []
summary = []
source_paths = []

for label, guard, root in cases:
    seed_rows = []
    for log in sorted(root.glob("ON_seed*_x560_720_t36.log")):
        mseed = re.search(r"ON_seed(\d+)_", log.name)
        if not mseed:
            continue
        seed = int(mseed.group(1))
        txt = log.read_text(errors="ignore")

        complete = int("SIMULATION COMPLETE" in txt)
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
            "experiment": "overlap_guard_ablation_AT5_DROP20",
            "condition": label,
            "EDGE_OVERLAP_BAN_GUARD": guard,
            "attack_type": 5,
            "attack_name": "adaptive",
            "packet_drop": 20,
            "seed": seed,
            "complete": complete,
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
        per_seed.append(row)
        source_paths.append({
            "condition": label,
            "EDGE_OVERLAP_BAN_GUARD": guard,
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

    summary.append({
        "experiment": "overlap_guard_ablation_AT5_DROP20",
        "condition": label,
        "EDGE_OVERLAP_BAN_GUARD": guard,
        "valid_seeds": f"{len(valid)}/15",
        "caught": f"{total_caught}/{total_mal}",
        "pooled_DR_percent": round(100*total_caught/total_mal, 2),
        "DR_mean_percent": round(st.mean(drs), 2),
        "DR_std": round(st.stdev(drs), 2) if len(drs) > 1 else 0.0,
        "DR_CI95_low": round(dr_lo, 2),
        "DR_CI95_high": round(dr_hi, 2),
        "false_positive": f"{total_fp}/{total_hon}",
        "pooled_FPR_percent": round(100*total_fp/total_hon, 2),
        "FPR_mean_percent": round(st.mean(fprs), 2),
        "FPR_std": round(st.stdev(fprs), 2) if len(fprs) > 1 else 0.0,
        "FPR_CI95_low": round(fpr_lo, 2),
        "FPR_CI95_high": round(fpr_hi, 2),
        "fallback_total": total_fallback,
        "source_dir": str(root),
        "config": "AT5 adaptive; DROP20; hard_only; speed_tol=6.0; overlap_ban_min_p=0.50; cusum_input=veremi",
    })

def write_csv(path, rows):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

write_csv(OUTDIR / "overlap_guard_ablation_AT5_DROP20_summary.csv", summary)
write_csv(OUTDIR / "overlap_guard_ablation_AT5_DROP20_per_seed_raw.csv", per_seed)
write_csv(OUTDIR / "overlap_guard_ablation_AT5_DROP20_source_paths.csv", source_paths)

print("Wrote:")
for p in sorted(OUTDIR.iterdir()):
    print(" ", p)
