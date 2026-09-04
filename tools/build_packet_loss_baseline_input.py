import csv
import re
from pathlib import Path

ROOT = Path("results")
BASE = Path("results/final_locked_csv")
OUTDIR = BASE / "baseline_veremi"
OUTDIR.mkdir(parents=True, exist_ok=True)

RAW = BASE / "packet_loss_robustness_per_seed_raw.csv"
OUT = OUTDIR / "baseline_input_packet_loss_log_paths.csv"

def condition_to_drop(cond):
    m = re.search(r"(\d+)", cond)
    if not m:
        raise ValueError(f"Cannot parse drop condition: {cond}")
    return int(m.group(1))

def find_complete_log(drop, seed):
    patterns = [
        f"packet_loss_robustness_DROP{drop}_guarded_cusum_15seed/ON_seed{seed}_*.log",
        f"packet_ls_robustness_DROP{drop}_guarded_cusum_15seed/ON_seed{seed}_*.log",
        f"*DROP{drop}*guarded_cusum*15seed*/ON_seed{seed}_*.log",
    ]

    candidates = []
    for pat in patterns:
        candidates.extend(ROOT.glob(pat))

    candidates = sorted(set(candidates), key=lambda p: str(p))

    complete = []
    for p in candidates:
        txt = p.read_text(errors="ignore")
        payoff_count = txt.count("[PAYOFF]")
        is_complete = "SIMULATION COMPLETE" in txt and payoff_count >= 10
        complete.append((p, is_complete, payoff_count))

    good = [p for p, ok, pc in complete if ok]
    if good:
        return good[-1], complete

    return None, complete

rows_out = []
missing = []

with RAW.open() as f:
    reader = csv.DictReader(f)
    for r in reader:
        cond = r["condition"]
        seed = int(r["seed"])
        drop = condition_to_drop(cond)

        log, candidates = find_complete_log(drop, seed)

        if log is None:
            missing.append((cond, seed, candidates))
            continue

        rows_out.append({
            "condition": cond,
            "drop_percent": drop,
            "seed": seed,
            "proposed_caught": r["caught"],
            "proposed_malicious": r["malicious"],
            "proposed_DR_percent": r["DR_percent"],
            "proposed_false_positive": r["false_positive"],
            "proposed_honest": r["honest"],
            "proposed_FPR_percent": r["FPR_percent"],
            "log_path": str(log.resolve()),
        })

rows_out = sorted(rows_out, key=lambda x: (x["drop_percent"], x["seed"]))

if rows_out:
    with OUT.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
        writer.writeheader()
        writer.writerows(rows_out)

print("Saved:", OUT)
print("Rows written:", len(rows_out))
print("Missing/incomplete:", len(missing))

for cond, seed, candidates in missing:
    print()
    print(f"MISSING COMPLETE LOG: condition={cond} seed={seed}")
    if not candidates:
        print("  no candidates found")
    for p, ok, pc in candidates:
        print(f"  ok={ok} payoff_count={pc} path={p}")

print()
print("Row counts by condition:")
from collections import Counter
c = Counter(r["condition"] for r in rows_out)
for k in sorted(c, key=lambda x: int(re.search(r'\\d+', x).group())):
    print(k, c[k])
