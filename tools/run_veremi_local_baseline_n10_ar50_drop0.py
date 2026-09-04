import csv
import re
import math
import statistics as st
from pathlib import Path
from collections import defaultdict, deque, Counter

BASE_DIR = Path("results/final_locked_csv/baseline_veremi")
BASE_DIR.mkdir(parents=True, exist_ok=True)

INPUT_CSV = BASE_DIR / "baseline_input_n10_ar50_drop0_log_paths.csv"

OUT_RAW = BASE_DIR / "veremi_local_baseline_n10_ar50_drop0_per_seed_raw.csv"
OUT_AGG = BASE_DIR / "veremi_local_baseline_n10_ar50_drop0_aggregate_summary.csv"
OUT_COMPARE = BASE_DIR / "proposed_vs_veremi_local_n10_ar50_drop0_comparison.csv"
OUT_OVERLAP = BASE_DIR / "proposed_vs_veremi_local_n10_ar50_drop0_overlap.csv"
OUT_CAUSES = BASE_DIR / "veremi_local_violation_causes_n10_ar50_drop0.csv"

CFG = {
    "window_W": 5,
    "K_values": [1, 2, 3],

    # Timing consistency
    "max_dt_gap": 1.50,
    "max_sim_ts_mismatch": 0.25,

    # Motion consistency
    "pos_residual_m": 7.50,
    "speed_residual_mps": 7.50,
    "accel_limit_mps2": 8.00,
    "heading_residual_deg": 35.00,

    # Lane consistency
    "lane_width_m": 10.0,
    "lane_tolerance_m": 4.0,

    "min_disp_for_heading_m": 2.0,
}

SCOPES = {
    "Centralized_CID": lambda r: (r["cid"],),
    "Local_CID_RXUAV": lambda r: (r["cid"], r["rxuav"]),
    "Local_CID_ZONE": lambda r: (r["cid"], r["zone"]),
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


def parse_ground_truth_and_proposed(log_path):
    malicious = set()
    honest = set()
    proposed_detected = set()

    for line in Path(log_path).read_text(errors="ignore").splitlines():
        if "[PAYOFF]" not in line:
            continue

        cid_m = re.search(r"CID:(\d+)", line)
        if not cid_m:
            continue

        cid = int(cid_m.group(1))
        is_mal = "malicious=YES" in line
        is_demoted = "demoted=YES" in line

        if is_mal:
            malicious.add(cid)
            if is_demoted:
                proposed_detected.add(cid)
        else:
            honest.add(cid)

    return malicious, honest, proposed_detected


def angle_diff_deg(a, b):
    return abs((a - b + 180.0) % 360.0 - 180.0)


def evaluate_scope(beacons, scope_name, key_fn):
    by_state = defaultdict(list)

    for b in beacons:
        by_state[key_fn(b)].append(b)

    events_by_state = defaultdict(list)
    cause_counter = Counter()

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
                for v in violations:
                    cause_counter[v] += 1

                events_by_state[state_key].append({
                    "cid": r["cid"],
                    "state_key": "|".join(map(str, state_key)),
                    "simnow": r["simnow"],
                    "ts": r["ts"],
                    "violations": violations,
                    "violation_count": len(violations),
                })

            prev = r

    return events_by_state, cause_counter


def detect_by_window(events_by_state, K, W):
    detected = set()
    detection_time = {}
    detection_state = {}

    for state_key, evs in events_by_state.items():
        q = deque()

        for ev in evs:
            q.append(ev)

            while len(q) > W:
                q.popleft()

            if len(q) >= K:
                cid = ev["cid"]

                if cid not in detected:
                    detected.add(cid)
                    detection_time[cid] = ev["simnow"]
                    detection_state[cid] = ev["state_key"]

                break

    return detected, detection_time, detection_state


def pct(num, den):
    return 100.0 * num / den if den else None


def precision_recall_f1(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def safe_mean(xs):
    return round(st.mean(xs), 2) if xs else ""


def safe_std(xs):
    return round(st.stdev(xs), 2) if len(xs) > 1 else 0.0


input_rows = list(csv.DictReader(INPUT_CSV.open()))

raw_rows = []
overlap_rows = []
cause_rows = []

for inp in input_rows:
    seed = int(inp["seed"])
    log_path = Path(inp["log_path"])

    beacons = parse_passive_beacons(log_path)
    malicious, honest, proposed_detected = parse_ground_truth_and_proposed(log_path)

    for scope_name, key_fn in SCOPES.items():
        events_by_state, cause_counter = evaluate_scope(beacons, scope_name, key_fn)

        for cause, count in sorted(cause_counter.items()):
            cause_rows.append({
                "scope": scope_name,
                "seed": seed,
                "cause": cause,
                "count": count,
                "source_log_path": str(log_path.resolve()),
            })

        for K in CFG["K_values"]:
            variant = f"{scope_name}_K{K}_W{CFG['window_W']}"

            baseline_detected, detection_time, detection_state = detect_by_window(
                events_by_state,
                K=K,
                W=CFG["window_W"]
            )

            tp_ids = sorted(baseline_detected & malicious)
            fp_ids = sorted(baseline_detected & honest)
            fn_ids = sorted(malicious - baseline_detected)

            tp = len(tp_ids)
            fp = len(fp_ids)
            fn = len(fn_ids)

            precision, recall, f1 = precision_recall_f1(tp, fp, fn)
            det_times = [detection_time[cid] for cid in tp_ids if cid in detection_time]

            raw_rows.append({
                "baseline_variant": variant,
                "scope": scope_name,
                "K": K,
                "W": CFG["window_W"],
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

            for cid in sorted(malicious | honest):
                is_mal = cid in malicious
                b_det = cid in baseline_detected
                p_det = cid in proposed_detected

                if is_mal:
                    if b_det and p_det:
                        category = "caught_by_both"
                    elif p_det and not b_det:
                        category = "proposed_only"
                    elif b_det and not p_det:
                        category = "veremi_only"
                    else:
                        category = "missed_by_both"
                else:
                    if b_det and p_det:
                        category = "both_false_positive"
                    elif p_det and not b_det:
                        category = "proposed_fp_only"
                    elif b_det and not p_det:
                        category = "veremi_fp_only"
                    else:
                        category = "honest_clean"

                overlap_rows.append({
                    "baseline_variant": variant,
                    "scope": scope_name,
                    "K": K,
                    "W": CFG["window_W"],
                    "seed": seed,
                    "cid": cid,
                    "malicious": "YES" if is_mal else "NO",
                    "proposed_detected": "YES" if p_det else "NO",
                    "veremi_detected": "YES" if b_det else "NO",
                    "category": category,
                    "veremi_detection_time": detection_time.get(cid, ""),
                    "veremi_detection_state": detection_state.get(cid, ""),
                    "source_log_path": str(log_path.resolve()),
                })


with OUT_RAW.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
    writer.writeheader()
    writer.writerows(raw_rows)

with OUT_OVERLAP.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(overlap_rows[0].keys()))
    writer.writeheader()
    writer.writerows(overlap_rows)

with OUT_CAUSES.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(cause_rows[0].keys()))
    writer.writeheader()
    writer.writerows(cause_rows)


agg_rows = []
for variant in sorted(set(r["baseline_variant"] for r in raw_rows)):
    vr = [r for r in raw_rows if r["baseline_variant"] == variant]

    total_detected = sum(int(r["detected"]) for r in vr)
    total_malicious = sum(int(r["malicious"]) for r in vr)
    total_fp = sum(int(r["false_positive"]) for r in vr)
    total_honest = sum(int(r["honest"]) for r in vr)

    dr_vals = [float(r["DR_percent"]) for r in vr]
    fpr_vals = [float(r["FPR_percent"]) for r in vr]
    f1_vals = [float(r["F1"]) for r in vr]

    agg_rows.append({
        "baseline_variant": variant,
        "scope": vr[0]["scope"],
        "K": vr[0]["K"],
        "W": vr[0]["W"],
        "valid_seeds": len(vr),
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


compare_rows = [{
    "method": "Proposed_UAV_Edge_Trust_Framework",
    "scope": "handover_state_transfer",
    "K": "",
    "W": "",
    "caught": "101/105",
    "pooled_DR_percent": 96.19,
    "DR_mean_percent": 96.19,
    "DR_std": 6.54,
    "false_positive": "0/45",
    "pooled_FPR_percent": 0.00,
    "F1_mean": "",
}]

for a in agg_rows:
    compare_rows.append({
        "method": a["baseline_variant"],
        "scope": a["scope"],
        "K": a["K"],
        "W": a["W"],
        "caught": a["caught"],
        "pooled_DR_percent": a["pooled_DR_percent"],
        "DR_mean_percent": a["DR_mean_percent"],
        "DR_std": a["DR_std"],
        "false_positive": a["false_positive"],
        "pooled_FPR_percent": a["pooled_FPR_percent"],
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
print(OUT_OVERLAP)
print(OUT_CAUSES)

print()
print("Aggregate local-baseline results:")
for r in agg_rows:
    print(r)

print()
print("Recommended rows to inspect:")
for r in compare_rows:
    if (
        r["method"] == "Proposed_UAV_Edge_Trust_Framework"
        or r["method"] in {
            "Centralized_CID_K3_W5",
            "Local_CID_RXUAV_K3_W5",
            "Local_CID_ZONE_K3_W5",
        }
    ):
        print(r)
