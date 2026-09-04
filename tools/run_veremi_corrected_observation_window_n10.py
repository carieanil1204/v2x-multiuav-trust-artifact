import csv
import re
import math
import statistics as st
from pathlib import Path
from collections import defaultdict, deque

BASE_DIR = Path("results/final_locked_csv/baseline_veremi")
INPUT_CSV = BASE_DIR / "baseline_input_n10_ar50_drop0_log_paths.csv"

OUT_RAW = BASE_DIR / "veremi_corrected_obs_window_n10_ar50_drop0_per_seed_raw.csv"
OUT_AGG = BASE_DIR / "veremi_corrected_obs_window_n10_ar50_drop0_aggregate_summary.csv"
OUT_COMPARE = BASE_DIR / "proposed_vs_veremi_corrected_obs_window_n10_ar50_drop0.csv"

CFG = {
    "window_W": 5,
    "K_values": [1, 2, 3],
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

SCOPES = {
    "Centralized_CID": lambda r: (r["cid"],),
    "Local_CID_RXUAV": lambda r: (r["cid"], r["rxuav"]),
    "Local_CID_ZONE": lambda r: (r["cid"], r["zone"]),
}

def parse_kv(line):
    out = {}
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_\-]*)\s*:\s*([^,\s\]]+)", line):
        key, val = m.group(1), m.group(2)
        try:
            out[key] = float(val) if "." in val or "e" in val.lower() else int(val)
        except ValueError:
            out[key] = val
    return out

def parse_beacons(log_path):
    rows = []
    for line in Path(log_path).read_text(errors="ignore").splitlines():
        if "[PASSIVE-BEACON]" not in line:
            continue
        kv = parse_kv(line)
        req = ["SIMNOW", "CID", "ZONE", "RXUAV", "TS", "SPD", "HDG", "PX", "PY", "LAN"]
        if not all(k in kv for k in req):
            continue
        rows.append({
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
    rows.sort(key=lambda r: (r["simnow"], r["ts"], r["cid"]))
    return rows

def parse_truth_and_proposed(log_path):
    malicious, honest, proposed = set(), set(), set()
    for line in Path(log_path).read_text(errors="ignore").splitlines():
        if "[PAYOFF]" not in line:
            continue
        m = re.search(r"CID:(\d+)", line)
        if not m:
            continue
        cid = int(m.group(1))
        if "malicious=YES" in line:
            malicious.add(cid)
            if "demoted=YES" in line:
                proposed.add(cid)
        else:
            honest.add(cid)
    return malicious, honest, proposed

def angle_diff(a, b):
    return abs((a - b + 180.0) % 360.0 - 180.0)

def violation_flags(prev, r):
    causes = []

    expected_py = -CFG["lane_width_m"] * float(r["lan"])
    if abs(r["py"] - expected_py) > CFG["lane_tolerance_m"]:
        causes.append("C_LANE")

    if prev is None:
        return causes

    dt_ts = r["ts"] - prev["ts"]
    dt_sim = r["simnow"] - prev["simnow"]

    if dt_ts <= 0 or dt_ts > CFG["max_dt_gap"]:
        causes.append("C_TS_MONO_GAP")

    if abs(dt_sim - dt_ts) > CFG["max_sim_ts_mismatch"]:
        causes.append("C_TS_SIM_MISMATCH")

    if dt_ts > 0:
        dx = r["px"] - prev["px"]
        dy = r["py"] - prev["py"]
        disp = math.hypot(dx, dy)

        expected_disp = prev["spd"] * dt_ts
        if abs(disp - expected_disp) > CFG["pos_residual_m"]:
            causes.append("C_POS_PRED")

        obs_speed = disp / dt_ts
        if abs(obs_speed - r["spd"]) > CFG["speed_residual_mps"]:
            causes.append("C_SPEED_POS")

        accel = abs(r["spd"] - prev["spd"]) / dt_ts
        if accel > CFG["accel_limit_mps2"]:
            causes.append("C_ACCEL")

        if disp >= CFG["min_disp_for_heading_m"]:
            obs_heading = math.degrees(math.atan2(dy, dx))
            if angle_diff(obs_heading, r["hdg"]) > CFG["heading_residual_deg"]:
                causes.append("C_HEADING")

    return causes

def build_observation_stream(beacons, key_fn):
    by_state = defaultdict(list)
    for b in beacons:
        by_state[key_fn(b)].append(b)

    streams = defaultdict(list)

    for state, rows in by_state.items():
        rows.sort(key=lambda r: (r["simnow"], r["ts"]))
        prev = None
        for r in rows:
            causes = violation_flags(prev, r)
            streams[state].append({
                "cid": r["cid"],
                "simnow": r["simnow"],
                "violation": 1 if causes else 0,
                "causes": ";".join(causes),
            })
            prev = r

    return streams

def detect_obs_window(streams, K, W):
    detected = set()
    detection_time = {}

    for state, obs in streams.items():
        q = deque()
        for o in obs:
            q.append(o["violation"])
            while len(q) > W:
                q.popleft()

            if len(q) == W and sum(q) >= K:
                cid = o["cid"]
                if cid not in detected:
                    detected.add(cid)
                    detection_time[cid] = o["simnow"]
                break

    return detected, detection_time

def pct(a, b):
    return 100.0 * a / b if b else 0.0

def mean(xs):
    return round(st.mean(xs), 2) if xs else ""

def sd(xs):
    return round(st.stdev(xs), 2) if len(xs) > 1 else 0.0

raw_rows = []

for inp in csv.DictReader(INPUT_CSV.open()):
    seed = int(inp["seed"])
    log_path = Path(inp["log_path"])

    beacons = parse_beacons(log_path)
    malicious, honest, proposed = parse_truth_and_proposed(log_path)

    for scope_name, key_fn in SCOPES.items():
        streams = build_observation_stream(beacons, key_fn)

        for K in CFG["K_values"]:
            detected, det_time = detect_obs_window(streams, K, CFG["window_W"])

            tp_ids = sorted(detected & malicious)
            fp_ids = sorted(detected & honest)
            fn_ids = sorted(malicious - detected)

            tp, fp, fn = len(tp_ids), len(fp_ids), len(fn_ids)

            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

            raw_rows.append({
                "baseline_variant": f"{scope_name}_OBS_K{K}_W{CFG['window_W']}",
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
                "detected_ids": ";".join(map(str, tp_ids)),
                "missed_ids": ";".join(map(str, fn_ids)),
                "false_positive_ids": ";".join(map(str, fp_ids)),
                "source_log_path": str(log_path.resolve()),
            })

with OUT_RAW.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
    writer.writeheader()
    writer.writerows(raw_rows)

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
        "DR_mean_percent": mean(dr_vals),
        "DR_std": sd(dr_vals),
        "false_positive": f"{total_fp}/{total_honest}",
        "pooled_FPR_percent": round(pct(total_fp, total_honest), 2),
        "FPR_mean_percent": mean(fpr_vals),
        "FPR_std": sd(fpr_vals),
        "F1_mean": mean(f1_vals),
        "F1_std": sd(f1_vals),
        "raw_csv_path": str(OUT_RAW.resolve()),
    })

with OUT_AGG.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(agg_rows[0].keys()))
    writer.writeheader()
    writer.writerows(agg_rows)

compare_rows = [{
    "method": "Proposed_UAV_Edge_Trust_Framework",
    "caught": "101/105",
    "pooled_DR_percent": 96.19,
    "DR_mean_percent": 96.19,
    "DR_std": 6.54,
    "false_positive": "0/45",
    "pooled_FPR_percent": 0.00,
    "note": "final_locked_scalability_N10_AR50_DROP0",
}]

for a in agg_rows:
    compare_rows.append({
        "method": a["baseline_variant"],
        "caught": a["caught"],
        "pooled_DR_percent": a["pooled_DR_percent"],
        "DR_mean_percent": a["DR_mean_percent"],
        "DR_std": a["DR_std"],
        "false_positive": a["false_positive"],
        "pooled_FPR_percent": a["pooled_FPR_percent"],
        "note": "corrected_observation_window",
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
print("===== CORRECTED OBSERVATION-WINDOW AGGREGATE =====")
for r in agg_rows:
    print(r)

print()
print("===== KEY ROWS =====")
for r in compare_rows:
    if r["method"] == "Proposed_UAV_Edge_Trust_Framework" or r["method"] in {
        "Centralized_CID_OBS_K3_W5",
        "Local_CID_RXUAV_OBS_K3_W5",
        "Local_CID_ZONE_OBS_K3_W5",
    }:
        print(r)
