import csv
import re
import math
import statistics as st
from pathlib import Path
from collections import defaultdict, deque

BASE_DIR = Path("results/final_locked_csv")
OUT_DIR = BASE_DIR / "baseline_veremi"
OUT_DIR.mkdir(parents=True, exist_ok=True)

PROPOSED_AGG = BASE_DIR / "packet_loss_robustness_aggregate_summary.csv"
PROPOSED_RAW = OUT_DIR / "baseline_input_packet_loss_log_paths.csv"

OUT_RAW = OUT_DIR / "veremi_packet_loss_k3_per_seed_raw.csv"
OUT_AGG = OUT_DIR / "veremi_packet_loss_k3_aggregate_summary.csv"
OUT_COMPARE = OUT_DIR / "proposed_vs_veremi_packet_loss_k3_comparison.csv"

CFG = {
    "window_W": 5,
    "K": 3,
    "scope": "Local_CID_RXUAV",

    "max_dt_gap": 1.50,
    "max_sim_ts_mismatch": 0.25,
    "pos_residual_m": 7.50,
    "speed_residual_mps": 7.50,
    "accel_limit_mps2": 8.00,
    "heading_residual_deg": 35.00,
    "lane_width_m": 10.0,
    "lane_tolerance_m": 4.0,
    "min_disp_for_heading_m": 2.0,
}


def parse_kv(line):
    out = {}
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_\-]*)\s*:\s*([^,\s\]]+)", line):
        key = m.group(1)
        val = m.group(2)
        try:
            if "." in val or "e" in val.lower():
                out[key] = float(val)
            else:
                out[key] = int(val)
        except ValueError:
            out[key] = val
    return out


def find_col(row, candidates):
    for c in candidates:
        if c in row:
            return c
    return None


def normalize_condition(row):
    for c in ["condition", "drop", "Drop", "pkt_drop", "PktDropRate", "drop_condition"]:
        if c in row and row[c] != "":
            v = str(row[c])
            if v.startswith("DROP"):
                return v
            try:
                return "DROP" + str(int(float(v)))
            except Exception:
                return v

    lp = row.get("log_path", "") or row.get("source_log_path", "")
    m = re.search(r"DROP(\d+)", lp, re.I)
    if m:
        return "DROP" + m.group(1)

    m = re.search(r"PktDropRate[_=]?(\d+)", lp, re.I)
    if m:
        return "DROP" + m.group(1)

    return "UNKNOWN"


def parse_passive_beacons(log_path):
    beacons = []

    for line in Path(log_path).read_text(errors="ignore").splitlines():
        if "[PASSIVE-BEACON]" not in line:
            continue

        kv = parse_kv(line)
        required = ["SIMNOW", "CID", "ZONE", "RXUAV", "TS", "SPD", "HDG", "PX", "PY", "LAN"]
        if not all(k in kv for k in required):
            continue

        beacons.append({
            "simnow": float(kv["SIMNOW"]),
            "cid": int(kv["CID"]),
            "zone": int(kv["ZONE"]),
            "rxuav": int(kv["RXUAV"]),
            "ts": float(kv["TS"]),
            "spd": float(kv["SPD"]),
            "hdg": float(kv["HDG"]),
            "px": float(kv["PX"]),
            "py": float(kv["PY"]),
            "lan": int(kv["LAN"]),
        })

    beacons.sort(key=lambda r: (r["simnow"], r["ts"], r["cid"]))
    return beacons


def parse_ground_truth(log_path):
    malicious = set()
    honest = set()

    for line in Path(log_path).read_text(errors="ignore").splitlines():
        if "[PAYOFF]" not in line:
            continue

        m = re.search(r"CID:(\d+)", line)
        if not m:
            continue

        cid = int(m.group(1))
        if "malicious=YES" in line:
            malicious.add(cid)
        else:
            honest.add(cid)

    return malicious, honest


def angle_diff_deg(a, b):
    return abs((a - b + 180.0) % 360.0 - 180.0)


def evaluate_local_rxuav(beacons):
    by_state = defaultdict(list)

    for b in beacons:
        by_state[(b["cid"], b["rxuav"])].append(b)

    events_by_state = defaultdict(list)

    for state_key, rows in by_state.items():
        rows.sort(key=lambda r: (r["simnow"], r["ts"]))
        prev = None

        for r in rows:
            violations = []

            expected_py = -CFG["lane_width_m"] * float(r["lan"])
            if abs(r["py"] - expected_py) > CFG["lane_tolerance_m"]:
                violations.append("C_LANE")

            if prev is not None:
                dt_ts = r["ts"] - prev["ts"]
                dt_sim = r["simnow"] - prev["simnow"]

                if dt_ts <= 0 or dt_ts > CFG["max_dt_gap"]:
                    violations.append("C_TS_MONO_GAP")

                if abs(dt_sim - dt_ts) > CFG["max_sim_ts_mismatch"]:
                    violations.append("C_TS_SIM_MISMATCH")

                if dt_ts > 0:
                    dx = r["px"] - prev["px"]
                    dy = r["py"] - prev["py"]
                    disp = math.hypot(dx, dy)

                    expected_disp = prev["spd"] * dt_ts
                    if abs(disp - expected_disp) > CFG["pos_residual_m"]:
                        violations.append("C_POS_PRED")

                    obs_speed = disp / dt_ts
                    if abs(obs_speed - r["spd"]) > CFG["speed_residual_mps"]:
                        violations.append("C_SPEED_POS")

                    accel = abs(r["spd"] - prev["spd"]) / dt_ts
                    if accel > CFG["accel_limit_mps2"]:
                        violations.append("C_ACCEL")

                    if disp >= CFG["min_disp_for_heading_m"]:
                        obs_heading = math.degrees(math.atan2(dy, dx))
                        if angle_diff_deg(obs_heading, r["hdg"]) > CFG["heading_residual_deg"]:
                            violations.append("C_HEADING")

            if violations:
                events_by_state[state_key].append({
                    "cid": r["cid"],
                    "simnow": r["simnow"],
                    "violations": violations,
                })

            prev = r

    return events_by_state


def detect_k3(events_by_state):
    detected = set()
    detection_time = {}

    for state_key, evs in events_by_state.items():
        q = deque()

        for ev in evs:
            q.append(ev)

            while len(q) > CFG["window_W"]:
                q.popleft()

            if len(q) >= CFG["K"]:
                cid = ev["cid"]
                if cid not in detected:
                    detected.add(cid)
                    detection_time[cid] = ev["simnow"]
                break

    return detected, detection_time


def pct(num, den):
    return 100.0 * num / den if den else None


def safe_mean(xs):
    return round(st.mean(xs), 2) if xs else ""


def safe_std(xs):
    return round(st.stdev(xs), 2) if len(xs) > 1 else 0.0


def precision_recall_f1(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


raw_rows = []

with PROPOSED_RAW.open() as f:
    reader = csv.DictReader(f)
    for row in reader:
        log_col = find_col(row, ["log_path"])
        seed_col = find_col(row, ["seed", "Seed"])

        if not log_col or not seed_col:
            raise RuntimeError("Could not find seed/log_path columns in packet_loss_robustness_per_seed_raw.csv")

        log_path = Path(row[log_col])
        if not log_path.exists():
            print("MISSING:", log_path)
            continue

        condition = row["condition"]
        seed = int(float(row[seed_col]))

        beacons = parse_passive_beacons(log_path)
        malicious, honest = parse_ground_truth(log_path)
        events_by_state = evaluate_local_rxuav(beacons)
        detected, detection_time = detect_k3(events_by_state)

        tp_ids = sorted(detected & malicious)
        fp_ids = sorted(detected & honest)
        fn_ids = sorted(malicious - detected)

        tp = len(tp_ids)
        fp = len(fp_ids)
        fn = len(fn_ids)

        precision, recall, f1 = precision_recall_f1(tp, fp, fn)

        det_times = [detection_time[cid] for cid in tp_ids if cid in detection_time]

        raw_rows.append({
            "condition": condition,
            "baseline_variant": "Local_CID_RXUAV_K3_W5",
            "seed": seed,
            "beacon_count": len(beacons),
            "malicious": len(malicious),
            "honest": len(honest),
            "detected": tp,
            "false_positive": fp,
            "missed": fn,
            "DR_percent": round(pct(tp, len(malicious)), 2),
            "FPR_percent": round(pct(fp, len(honest)), 2),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "F1": round(f1, 4),
            "mean_detection_time": round(st.mean(det_times), 3) if det_times else "",
            "detected_ids": ";".join(map(str, tp_ids)),
            "missed_ids": ";".join(map(str, fn_ids)),
            "false_positive_ids": ";".join(map(str, fp_ids)),
            "source_log_path": str(log_path.resolve()),
        })


with OUT_RAW.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
    writer.writeheader()
    writer.writerows(sorted(raw_rows, key=lambda r: (r["condition"], int(r["seed"]))))


agg_rows = []
for condition in sorted(set(r["condition"] for r in raw_rows), key=lambda x: int(re.sub(r"\D", "", x) or 0)):
    cr = [r for r in raw_rows if r["condition"] == condition]

    total_detected = sum(int(r["detected"]) for r in cr)
    total_malicious = sum(int(r["malicious"]) for r in cr)
    total_fp = sum(int(r["false_positive"]) for r in cr)
    total_honest = sum(int(r["honest"]) for r in cr)

    dr_vals = [float(r["DR_percent"]) for r in cr]
    fpr_vals = [float(r["FPR_percent"]) for r in cr]
    f1_vals = [float(r["F1"]) for r in cr]

    agg_rows.append({
        "condition": condition,
        "baseline_variant": "Local_CID_RXUAV_K3_W5",
        "valid_seeds": len(cr),
        "caught": f"{total_detected}/{total_malicious}",
        "pooled_DR_percent": round(pct(total_detected, total_malicious), 2),
        "DR_mean_percent": safe_mean(dr_vals),
        "DR_std": safe_std(dr_vals),
        "false_positive": f"{total_fp}/{total_honest}",
        "pooled_FPR_percent": round(pct(total_fp, total_honest), 2),
        "FPR_mean_percent": safe_mean(fpr_vals),
        "FPR_std": safe_std(fpr_vals),
        "F1_mean": safe_mean(f1_vals),
        "F1_std": safe_std(f1_vals),
        "raw_csv_path": str(OUT_RAW.resolve()),
    })


with OUT_AGG.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(agg_rows[0].keys()))
    writer.writeheader()
    writer.writerows(agg_rows)


proposed_rows = list(csv.DictReader(PROPOSED_AGG.open()))

compare_rows = []
for p in proposed_rows:
    cond = p["condition"]
    compare_rows.append({
        "condition": cond,
        "method": "Proposed_UAV_Edge_Trust_Framework",
        "caught": p["caught"],
        "pooled_DR_percent": p["pooled_DR_percent"],
        "DR_mean_percent": p["DR_mean_percent"],
        "DR_std": p["DR_std"],
        "false_positive": p["false_positive"],
        "pooled_FPR_percent": p["pooled_FPR_percent"],
        "FPR_mean_percent": p["FPR_mean_percent"],
        "FPR_std": p["FPR_std"],
        "F1_mean": "",
    })

    match = [a for a in agg_rows if a["condition"] == cond]
    if match:
        a = match[0]
        compare_rows.append({
            "condition": cond,
            "method": "Local_CID_RXUAV_K3_W5",
            "caught": a["caught"],
            "pooled_DR_percent": a["pooled_DR_percent"],
            "DR_mean_percent": a["DR_mean_percent"],
            "DR_std": a["DR_std"],
            "false_positive": a["false_positive"],
            "pooled_FPR_percent": a["pooled_FPR_percent"],
            "FPR_mean_percent": a["FPR_mean_percent"],
            "FPR_std": a["FPR_std"],
            "F1_mean": a["F1_mean"],
        })


with OUT_COMPARE.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(compare_rows[0].keys()))
    writer.writeheader()
    writer.writerows(compare_rows)


print("Saved:")
print(OUT_RAW)
print(OUT_AGG)
print(OUT_COMPARE)

print()
print("===== VEREMI PACKET LOSS AGGREGATE =====")
for r in agg_rows:
    print(r)

print()
print("===== PROPOSED VS VEREMI PACKET LOSS =====")
for r in compare_rows:
    print(r)
