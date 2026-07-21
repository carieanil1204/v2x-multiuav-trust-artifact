#!/usr/bin/env python3
import re
import csv
import statistics as stats
from pathlib import Path

ROOT = Path("results")
OUTDIR = Path("results/final_locked_csv/attack_variants_after_override")
OUTDIR.mkdir(parents=True, exist_ok=True)

attack_names = {
    1: "AT1_TS_only",
    2: "AT2_GPS_only",
}

drops = [0, 10, 20]
seeds = list(range(1, 16))

payoff_re = re.compile(
    r"\[PAYOFF\]\s+CID:(\d+).*?"
    r"warn_count=(\d+).*?"
    r"adverse_count=(\d+).*?"
    r"demoted=(YES|NO).*?"
    r"malicious=(YES|NO)"
)

raw_rows = []
summary_rows = []

for at in [1, 2]:
    for drop in drops:
        d = ROOT / f"attack_type_robustness_AT{at}_DROP{drop}_guarded_cusum_15seed"

        seed_dr = []
        seed_fpr = []

        total_mal = 0
        total_hon = 0
        total_caught = 0
        total_fp = 0
        valid_seeds = 0

        for seed in seeds:
            log = d / f"ON_seed{seed}_x560_720_t36.log"
            if not log.exists():
                print(f"Missing log: {log}")
                continue

            txt = log.read_text(errors="ignore")
            if "SIMULATION COMPLETE" not in txt:
                print(f"Incomplete log: {log}")
                continue
            if "[EDGE-FALLBACK]" in txt:
                print(f"WARNING fallback found in: {log}")

            mal = hon = caught = fp = 0
            warn_mal = warn_hon = 0

            for line in txt.splitlines():
                m = payoff_re.search(line)
                if not m:
                    continue

                cid = int(m.group(1))
                warn_count = int(m.group(2))
                adverse_count = int(m.group(3))
                demoted = m.group(4)
                malicious = m.group(5)

                if malicious == "YES":
                    mal += 1
                    if demoted == "YES":
                        caught += 1
                    if warn_count > 0:
                        warn_mal += 1
                else:
                    hon += 1
                    if demoted == "YES":
                        fp += 1
                    if warn_count > 0:
                        warn_hon += 1

                raw_rows.append({
                    "attack_type": at,
                    "attack_name": attack_names[at],
                    "drop_percent": drop,
                    "seed": seed,
                    "cid": cid,
                    "malicious": malicious,
                    "demoted": demoted,
                    "warn_count": warn_count,
                    "adverse_count": adverse_count,
                    "log_path": str(log),
                })

            if mal + hon == 0:
                print(f"No PAYOFF lines parsed: {log}")
                continue

            valid_seeds += 1
            total_mal += mal
            total_hon += hon
            total_caught += caught
            total_fp += fp

            dr = 100.0 * caught / mal if mal else 0.0
            fpr = 100.0 * fp / hon if hon else 0.0
            seed_dr.append(dr)
            seed_fpr.append(fpr)

        pooled_dr = 100.0 * total_caught / total_mal if total_mal else 0.0
        pooled_fpr = 100.0 * total_fp / total_hon if total_hon else 0.0

        summary_rows.append({
            "attack_type": at,
            "attack_name": attack_names[at],
            "drop_percent": drop,
            "valid_seeds": f"{valid_seeds}/15",
            "caught": f"{total_caught}/{total_mal}",
            "pooled_DR_percent": round(pooled_dr, 2),
            "DR_mean_percent": round(stats.mean(seed_dr), 2) if seed_dr else "",
            "DR_std": round(stats.stdev(seed_dr), 2) if len(seed_dr) > 1 else 0.0,
            "false_positive": f"{total_fp}/{total_hon}",
            "pooled_FPR_percent": round(pooled_fpr, 2),
            "FPR_mean_percent": round(stats.mean(seed_fpr), 2) if seed_fpr else "",
            "FPR_std": round(stats.stdev(seed_fpr), 2) if len(seed_fpr) > 1 else 0.0,
            "source_dir": str(d),
        })

raw_csv = OUTDIR / "attack_variant_at1_at2_per_vehicle_raw.csv"
summary_csv = OUTDIR / "attack_variant_at1_at2_aggregate_summary.csv"

with raw_csv.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
    writer.writeheader()
    writer.writerows(raw_rows)

with summary_csv.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
    writer.writeheader()
    writer.writerows(summary_rows)

print("WROTE:", raw_csv)
print("WROTE:", summary_csv)
print()
print("===== ATTACK VARIANT SUMMARY =====")
for r in summary_rows:
    print(
        f"{r['attack_name']} DROP{r['drop_percent']}: "
        f"caught={r['caught']} DR={r['pooled_DR_percent']}% "
        f"FP={r['false_positive']} FPR={r['pooled_FPR_percent']}%"
    )
