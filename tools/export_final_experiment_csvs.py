import re
import csv
import statistics as st
from pathlib import Path

ROOT = Path("results")
OUT = ROOT / "final_csv_exports"
OUT.mkdir(parents=True, exist_ok=True)

EXPERIMENTS = {
    "handover_onoff": {
        "summary_files": [
            "results/handover_tuned_x560_640_t32_5seed/HANDOVER_15SEED_SUMMARY.txt",
            "results/handover_tuned_x560_640_t32_5seed/HANDOVER_15SEED_STATS.txt",
        ],
        "fallback_dirs": [
            "results/handover_tuned_x560_640_t32_5seed",
        ],
        "include_any": ["handover_tuned"],
        "exclude_any": [],
    },

    "cusum_onoff": {
        "summary_files": [
            "results/CUSUM_H08_MINOBS3_EDGEMAX05_15SEED_SUMMARY.txt",
            "results/ablation_cusum_off_x560_640_t32_5seed/CUSUM_ABLATION_5SEED_SUMMARY.txt",
        ],
        "fallback_dirs": [
            "results/ablation_cusum_off_x560_640_t32_5seed",
        ],
        "include_any": [
            "cusum_h08_minobs3_edgemax05",
            "ablation_cusum_off",
            "cusum_ablation",
        ],
        "exclude_any": [
            "clean",
            "sweep",
            "specific",
            "tuning",
            "ban_reason",
            "packet",
            "attack_rate",
            "htd",
            "scalability",
        ],
    },

    "clean_cusum_safety": {
        "summary_files": [
            "results/CUSUM_CLEAN_H08_MINOBS3_EDGEMAX05_15SEED_SUMMARY.txt",
        ],
        "fallback_dirs": [],
        "include_any": [
            "cusum_clean_h08_minobs3_edgemax05",
            "clean_multiseed_v91_20260706_230602",
            "hybrid_guarded",
            "guarded_clean",
        ],
        "exclude_any": [
            "attack_rate",
            "packet",
            "htd",
            "scalability",
            "handover_tuned",
        ],
    },

    "htd_sensitivity": {
        "summary_files": [
            "results/HTD_SENSITIVITY_GUARDED_CUSUM_15SEED_SUMMARY.txt",
            "results/htd_sensitivity_20260706_100005/payoff_summary.txt",
            "results/htd_sensitivity_20260706_130128/payoff_summary.txt",
        ],
        "fallback_dirs": [
            "results/htd_sensitivity_20260706_100005",
            "results/htd_sensitivity_20260706_130128",
        ],
        "include_any": ["htd_sensitivity"],
        "exclude_any": ["scalability"],
    },

    "attack_rate_robustness": {
        "summary_files": [
            "results/ATTACK_RATE_ROBUSTNESS_EXTENDED_GUARDED_CUSUM_15SEED_SUMMARY.txt",
            "results/ATTACK_RATE_ROBUSTNESS_GUARDED_CUSUM_15SEED_SUMMARY.txt",
        ],
        "fallback_dirs": [],
        "include_any": [
            "attack_rate_robustness",
            "ar20",
            "ar50",
            "ar70",
        ],
        "exclude_any": [
            "scalability",
            "packet",
            "htd",
        ],
    },

    "packet_loss_robustness": {
        "summary_files": [
            "results/PACKET_LOSS_ROBUSTNESS_GUARDED_CUSUM_15SEED_SUMMARY.txt",
        ],
        "fallback_dirs": [],
        "include_any": [
            "packet_loss",
            "pktdrop",
            "drop",
        ],
        "exclude_any": [
            "scalability",
            "attack_rate",
            "htd",
        ],
    },
}


RAW_FIELDS = [
    "experiment",
    "condition",
    "nCars",
    "seed",
    "status",
    "log_path",
    "detected",
    "malicious",
    "DR_percent",
    "false_positive",
    "honest",
    "FPR_percent",
    "CUSUM_BAN",
    "CUSUM_HOLD",
    "NASH_GATE",
    "HANDOVER_HTD_LOGS",
    "runtime_sec",
    "attack_rate_percent",
    "pkt_drop_percent",
    "htd_value",
    "missed_ids",
    "false_positive_ids",
    "summary_source_paths",
]

SUMMARY_FIELDS = [
    "experiment",
    "condition",
    "valid_rows",
    "valid_seeds",
    "caught",
    "pooled_DR_percent",
    "DR_mean_percent",
    "DR_std",
    "false_positive",
    "pooled_FPR_percent",
    "FPR_mean_percent",
    "FPR_std",
    "CUSUM_BAN_total",
    "CUSUM_HOLD_total",
    "NASH_GATE_total",
    "HANDOVER_HTD_LOGS_total",
    "runtime_mean_sec",
    "runtime_std_sec",
    "raw_csv_path",
]

STATUS_FIELDS = [
    "experiment",
    "raw_csv_path",
    "aggregate_csv_path",
    "raw_rows",
    "complete_rows",
    "conditions_found",
    "summary_sources_found",
    "status",
]


def read_text(path):
    try:
        return path.read_text(errors="ignore")
    except Exception:
        return ""


def find_explicit_log_paths_from_summary(summary_path):
    text = read_text(summary_path)
    found = set()

    for m in re.finditer(r"(/[^\s]+?\.log|results/[^\s]+?\.log)", text):
        raw = m.group(1).strip()
        p = Path(raw)
        if not p.is_absolute():
            p = Path.cwd() / p
        if p.exists():
            found.add(p.resolve())

    return found


def all_logs():
    return sorted(ROOT.rglob("*.log"))


def parse_runtime_from_nearby(path):
    runtime_file = path.parent / "runtime_seconds.txt"
    if not runtime_file.exists():
        return {}

    runtimes = {}
    text = read_text(runtime_file)

    for line in text.splitlines():
        m = re.search(r"SEED=(\d+)\s+RUNTIME_SEC=(\d+)", line)
        if m:
            runtimes[int(m.group(1))] = int(m.group(2))

    return runtimes


def parse_seed(path, text):
    patterns = [
        r"RngRun=(\d+)",
        r"seed[_-]?(\d+)",
        r"SEED=(\d+)",
    ]

    joined = str(path) + "\n" + text

    for pat in patterns:
        m = re.search(pat, joined, flags=re.IGNORECASE)
        if m:
            return int(m.group(1))

    return ""


def parse_ncars(path, text):
    joined = str(path) + "\n" + text

    patterns = [
        r"nCars=(\d+)",
        r"NCARS=(\d+)",
        r"scalability_N(\d+)",
        r"N(\d+)_AR",
    ]

    for pat in patterns:
        m = re.search(pat, joined, flags=re.IGNORECASE)
        if m:
            return int(m.group(1))

    return ""


def parse_attack_rate(path, text):
    joined = str(path) + "\n" + text

    patterns = [
        r"attackRate=(\d+)%",
        r"AR(\d+)",
        r"ATTACK_RATE[_-]?(\d+)",
    ]

    for pat in patterns:
        m = re.search(pat, joined, flags=re.IGNORECASE)
        if m:
            return float(m.group(1))

    return ""


def parse_pkt_drop(path, text):
    joined = str(path) + "\n" + text

    patterns = [
        r"PktDropRate=([0-9.]+)",
        r"PKT_DROP_RATE=([0-9.]+)",
        r"drop[_-]?([0-9.]+)",
        r"pktdrop[_-]?([0-9.]+)",
    ]

    for pat in patterns:
        m = re.search(pat, joined, flags=re.IGNORECASE)
        if m:
            return float(m.group(1))

    return ""


def parse_htd(path, text):
    joined = str(path) + "\n" + text

    patterns = [
        r"HTD[=_-]([01](?:\.\d+)?)",
        r"htd[_-]?([01](?:\.\d+)?)",
    ]

    for pat in patterns:
        m = re.search(pat, joined, flags=re.IGNORECASE)
        if m:
            return float(m.group(1))

    return ""


def infer_onoff(path):
    low = str(path).lower()

    if (
        re.search(r"(^|[/_\-])off([/_\-.]|seed)", low)
        or "cusum_off" in low
        or "handover_off" in low
        or "off_seed" in low
    ):
        return "OFF"

    if (
        re.search(r"(^|[/_\-])on([/_\-.]|seed)", low)
        or "cusum_on" in low
        or "handover_on" in low
        or "on_seed" in low
    ):
        return "ON"

    return ""


def parse_log(path):
    text = read_text(path)
    lines = text.splitlines()

    complete = any("SIMULATION COMPLETE" in line for line in lines)

    malicious = 0
    detected = 0
    honest = 0
    false_positive = 0
    missed_ids = []
    false_positive_ids = []

    for line in lines:
        if "[PAYOFF]" not in line:
            continue

        cid_match = re.search(r"CID:(\d+)", line)
        if not cid_match:
            continue

        cid = int(cid_match.group(1))
        is_malicious = "malicious=YES" in line
        is_demoted = "demoted=YES" in line

        if is_malicious:
            malicious += 1
            if is_demoted:
                detected += 1
            else:
                missed_ids.append(cid)
        else:
            honest += 1
            if is_demoted:
                false_positive += 1
                false_positive_ids.append(cid)

    dr = 100.0 * detected / malicious if malicious else 0.0
    fpr = 100.0 * false_positive / honest if honest else 0.0

    seed = parse_seed(path, text)
    runtimes = parse_runtime_from_nearby(path)
    runtime = runtimes.get(seed, "")

    return {
        "seed": seed,
        "nCars": parse_ncars(path, text),
        "attack_rate_percent": parse_attack_rate(path, text),
        "pkt_drop_percent": parse_pkt_drop(path, text),
        "htd_value": parse_htd(path, text),
        "status": "COMPLETE" if complete else "INCOMPLETE",
        "detected": detected,
        "malicious": malicious,
        "DR_percent": round(dr, 2),
        "false_positive": false_positive,
        "honest": honest,
        "FPR_percent": round(fpr, 2),
        "CUSUM_BAN": sum("[CUSUM-BAN]" in line for line in lines),
        "CUSUM_HOLD": sum("[CUSUM-HOLD]" in line for line in lines),
        "NASH_GATE": sum("[NASH-GATE]" in line for line in lines),
        "HANDOVER_HTD_LOGS": sum(
            ("[HANDOVER" in line or "[HTD" in line)
            for line in lines
        ),
        "runtime_sec": runtime,
        "missed_ids": ";".join(map(str, missed_ids)),
        "false_positive_ids": ";".join(map(str, false_positive_ids)),
    }


def get_condition(experiment, path, parsed):
    if experiment in {"handover_onoff", "cusum_onoff"}:
        return infer_onoff(path) or "UNKNOWN"

    if experiment == "clean_cusum_safety":
        return "CLEAN_HONEST"

    if experiment == "htd_sensitivity":
        if parsed["htd_value"] != "":
            return f"HTD_{parsed['htd_value']}"
        return "HTD_UNKNOWN"

    if experiment == "attack_rate_robustness":
        if parsed["attack_rate_percent"] != "":
            return f"AR_{int(parsed['attack_rate_percent'])}"
        return "AR_UNKNOWN"

    if experiment == "packet_loss_robustness":
        if parsed["pkt_drop_percent"] != "":
            return f"DROP_{parsed['pkt_drop_percent']}"
        return "DROP_UNKNOWN"

    return "UNKNOWN"


def discover_logs(spec):
    selected = set()
    summary_sources = []

    for s in spec["summary_files"]:
        sp = Path(s)
        if sp.exists():
            summary_sources.append(str(sp.resolve()))
            selected |= find_explicit_log_paths_from_summary(sp)

            # If the summary is inside a specific experiment folder, include logs from that folder.
            if sp.parent != ROOT and sp.parent.exists():
                selected |= {p.resolve() for p in sp.parent.rglob("*.log")}

    for d in spec["fallback_dirs"]:
        dp = Path(d)
        if dp.exists():
            selected |= {p.resolve() for p in dp.rglob("*.log")}

    for p in all_logs():
        low = str(p).lower()

        if spec["include_any"] and not any(k.lower() in low for k in spec["include_any"]):
            continue

        if spec["exclude_any"] and any(k.lower() in low for k in spec["exclude_any"]):
            continue

        selected.add(p.resolve())

    return sorted(selected), summary_sources


def write_csv(path, rows, fields):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fields})


def aggregate_rows(experiment, rows, raw_csv_path):
    complete = [
        r for r in rows
        if r["status"] == "COMPLETE"
        and int(r["malicious"]) + int(r["honest"]) > 0
    ]

    out = []

    conditions = sorted(set(r["condition"] for r in complete))

    for cond in conditions:
        cr = [r for r in complete if r["condition"] == cond]

        detected = sum(int(r["detected"]) for r in cr)
        malicious = sum(int(r["malicious"]) for r in cr)
        fp = sum(int(r["false_positive"]) for r in cr)
        honest = sum(int(r["honest"]) for r in cr)

        dr_values = [float(r["DR_percent"]) for r in cr]
        fpr_values = [float(r["FPR_percent"]) for r in cr]
        runtime_values = [
            float(r["runtime_sec"]) for r in cr
            if str(r["runtime_sec"]).strip() != ""
        ]

        seeds = sorted(set(str(r["seed"]) for r in cr if str(r["seed"]).strip() != ""))

        out.append({
            "experiment": experiment,
            "condition": cond,
            "valid_rows": len(cr),
            "valid_seeds": len(seeds),
            "caught": f"{detected}/{malicious}",
            "pooled_DR_percent": round(100.0 * detected / malicious, 2) if malicious else 0.0,
            "DR_mean_percent": round(st.mean(dr_values), 2) if dr_values else 0.0,
            "DR_std": round(st.stdev(dr_values), 2) if len(dr_values) > 1 else 0.0,
            "false_positive": f"{fp}/{honest}",
            "pooled_FPR_percent": round(100.0 * fp / honest, 2) if honest else 0.0,
            "FPR_mean_percent": round(st.mean(fpr_values), 2) if fpr_values else 0.0,
            "FPR_std": round(st.stdev(fpr_values), 2) if len(fpr_values) > 1 else 0.0,
            "CUSUM_BAN_total": sum(int(r["CUSUM_BAN"]) for r in cr),
            "CUSUM_HOLD_total": sum(int(r["CUSUM_HOLD"]) for r in cr),
            "NASH_GATE_total": sum(int(r["NASH_GATE"]) for r in cr),
            "HANDOVER_HTD_LOGS_total": sum(int(r["HANDOVER_HTD_LOGS"]) for r in cr),
            "runtime_mean_sec": round(st.mean(runtime_values), 2) if runtime_values else "",
            "runtime_std_sec": round(st.stdev(runtime_values), 2) if len(runtime_values) > 1 else "",
            "raw_csv_path": str(raw_csv_path.resolve()),
        })

    return out


status_rows = []

for experiment, spec in EXPERIMENTS.items():
    log_paths, summary_sources = discover_logs(spec)

    raw_rows = []

    for p in log_paths:
        parsed = parse_log(p)
        cond = get_condition(experiment, p, parsed)

        row = {
            "experiment": experiment,
            "condition": cond,
            "log_path": str(p.resolve()),
            "summary_source_paths": " | ".join(summary_sources),
        }
        row.update(parsed)
        raw_rows.append(row)

    raw_csv = ROOT / f"{experiment}_per_seed_raw.csv"
    agg_csv = ROOT / f"{experiment}_aggregate_summary.csv"

    write_csv(raw_csv, raw_rows, RAW_FIELDS)
    agg_rows = aggregate_rows(experiment, raw_rows, raw_csv)
    write_csv(agg_csv, agg_rows, SUMMARY_FIELDS)

    complete_rows = sum(1 for r in raw_rows if r["status"] == "COMPLETE")
    conditions = sorted(set(r["condition"] for r in raw_rows))

    if len(raw_rows) == 0:
        status = "CHECK_NO_RAW_LOGS_FOUND"
    elif "UNKNOWN" in conditions or any(c.endswith("_UNKNOWN") for c in conditions):
        status = "CHECK_UNKNOWN_CONDITION_PRESENT"
    else:
        status = "OK"

    status_rows.append({
        "experiment": experiment,
        "raw_csv_path": str(raw_csv.resolve()),
        "aggregate_csv_path": str(agg_csv.resolve()),
        "raw_rows": len(raw_rows),
        "complete_rows": complete_rows,
        "conditions_found": ";".join(conditions),
        "summary_sources_found": len(summary_sources),
        "status": status,
    })


status_csv = ROOT / "ALL_COMPLETED_EXPERIMENTS_CSV_EXPORT_STATUS.csv"
write_csv(status_csv, status_rows, STATUS_FIELDS)

print("Created experiment CSV exports.")
print(f"Status file: {status_csv}")
print()

for r in status_rows:
    print(
        f"{r['experiment']}: "
        f"raw_rows={r['raw_rows']} "
        f"complete={r['complete_rows']} "
        f"conditions={r['conditions_found']} "
        f"status={r['status']}"
    )

print()
print("CSV files created:")
for p in sorted(ROOT.glob("*_per_seed_raw.csv")):
    print(p)
for p in sorted(ROOT.glob("*_aggregate_summary.csv")):
    print(p)
