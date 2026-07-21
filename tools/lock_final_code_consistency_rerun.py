import csv, re, math, statistics as st
from pathlib import Path

ROOT = Path("results/final_code_consistency_rerun")
OUTDIR = Path("results/final_locked_csv/final_code_consistency_rerun")
OUTDIR.mkdir(parents=True, exist_ok=True)

payoff_re = re.compile(r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)")

experiments = [
    ("clean_safety_final_patch", "clean_safety", "CLEAN_HONEST"),
    ("packet_loss_final_patch_DROP0", "packet_loss", "DROP0"),
    ("packet_loss_final_patch_DROP5", "packet_loss", "DROP5"),
    ("packet_loss_final_patch_DROP10", "packet_loss", "DROP10"),
    ("packet_loss_final_patch_DROP20", "packet_loss", "DROP20"),
    ("handover_final_patch_ON", "handover_onoff", "ON"),
    ("handover_final_patch_OFF", "handover_onoff", "OFF"),
    ("cusum_final_patch_ON", "cusum_onoff", "ON"),
    ("cusum_final_patch_OFF", "cusum_onoff", "OFF"),
]

def wilson(k, n, z=1.96):
    if n == 0:
        return ("", "")
    p = k / n
    den = 1 + z*z/n
    centre = p + z*z/(2*n)
    margin = z * math.sqrt((p*(1-p) + z*z/(4*n)) / n)
    return round(100*(centre-margin)/den, 2), round(100*(centre+margin)/den, 2)

per_seed = []
summary = []

for folder, exp, condition in experiments:
    d = ROOT / folder
    seed_rows = []

    for log in sorted(d.glob("*.log")):
        seed_m = re.search(r"seed(\d+)", log.name)
        seed = int(seed_m.group(1)) if seed_m else ""

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
            "experiment": exp,
            "condition": condition,
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
        "experiment": exp,
        "condition": condition,
        "valid_seeds": f"{len(valid)}/15",
        "caught": f"{total_caught}/{total_mal}" if total_mal else "",
        "pooled_DR_percent": round(100*total_caught/total_mal, 2) if total_mal else "",
        "DR_mean_percent": round(st.mean(drs), 2) if drs else "",
        "DR_std": round(st.stdev(drs), 2) if len(drs) > 1 else 0.0,
        "DR_CI95_low": dr_lo,
        "DR_CI95_high": dr_hi,
        "false_positive": f"{total_fp}/{total_hon}" if total_hon else "",
        "pooled_FPR_percent": round(100*total_fp/total_hon, 2) if total_hon else "",
        "FPR_mean_percent": round(st.mean(fprs), 2) if fprs else "",
        "FPR_std": round(st.stdev(fprs), 2) if len(fprs) > 1 else 0.0,
        "FPR_CI95_low": fpr_lo,
        "FPR_CI95_high": fpr_hi,
        "fallback_total": total_fallback,
        "source_dir": str(d),
        "config": "final_patched_code; hard_only; speed_tol=6.0; overlap_ban_guard=1; overlap_ban_min_p=0.50; cusum_input=veremi",
    })

def write_csv(path, rows):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

write_csv(OUTDIR / "final_code_consistency_per_seed_raw.csv", per_seed)
write_csv(OUTDIR / "final_code_consistency_aggregate_summary.csv", summary)

print("Wrote:")
for p in sorted(OUTDIR.iterdir()):
    print(" ", p)
