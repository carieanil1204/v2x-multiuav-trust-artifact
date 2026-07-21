import csv
import re
import math
import statistics as st
from pathlib import Path
from collections import defaultdict, deque

BASE = Path("results/final_locked_csv")
B = BASE / "baseline_veremi"

INPUT = B / "baseline_input_packet_loss_log_paths.csv"
FAIR = B / "proposed_vs_best_clean_safe_segment_reset_veremi_packet_loss.csv"

OUT_PER_CID = B / "detection_delay_proposed_vs_best_clean_safe_segment_reset_per_cid.csv"
OUT_AGG = B / "detection_delay_proposed_vs_best_clean_safe_segment_reset_summary.csv"

CFG = {
    "W": 5,
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
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*([^,\s\]]+)", line):
        k, v = m.group(1), m.group(2)
        try:
            out[k] = float(v) if "." in v or "e" in v.lower() else int(v)
        except ValueError:
            out[k] = v
    return out

def parse_beacons_with_line(log_path):
    rows = []
    lines = Path(log_path).read_text(errors="ignore").splitlines()

    for idx, line in enumerate(lines):
        if "[PASSIVE-BEACON]" not in line:
            continue

        kv = parse_kv(line)
        req = ["SIMNOW", "CID", "ZONE", "RXUAV", "TS", "SPD", "HDG", "PX", "PY", "LAN"]
        if not all(k in kv for k in req):
            continue

        rows.append({
            "line_index": idx,
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

    rows.sort(key=lambda r: (r["cid"], r["simnow"], r["ts"]))
    return rows, lines

def parse_truth(log_path):
    malicious, honest = set(), set()

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

def angle_diff(a, b):
    return abs((a - b + 180.0) % 360.0 - 180.0)

def violation_causes(prev, r):
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

def first_physical_violation_time(beacons):
    by_cid = defaultdict(list)
    for b in beacons:
        by_cid[b["cid"]].append(b)

    first = {}

    for cid, rows in by_cid.items():
        rows.sort(key=lambda r: (r["simnow"], r["ts"]))
        prev = None

        for r in rows:
            causes = violation_causes(prev, r)
            if causes:
                first[cid] = r["simnow"]
                break
            prev = r

    return first

def make_contiguous_rxuav_segments(beacons):
    by_cid = defaultdict(list)
    for b in beacons:
        by_cid[b["cid"]].append(b)

    segments = []
    for cid, rows in by_cid.items():
        rows.sort(key=lambda r: (r["simnow"], r["ts"]))

        current = []
        current_rx = None
        seg_id = 0

        for r in rows:
            if current and r["rxuav"] != current_rx:
                segments.append((cid, seg_id, current_rx, current))
                seg_id += 1
                current = []

            current.append(r)
            current_rx = r["rxuav"]

        if current:
            segments.append((cid, seg_id, current_rx, current))

    return segments

def baseline_segment_reset_detection_time(beacons, K):
    detected_time = {}

    for cid, seg_id, rxuav, rows in make_contiguous_rxuav_segments(beacons):
        rows.sort(key=lambda r: (r["simnow"], r["ts"]))
        prev = None
        q = deque()

        for r in rows:
            causes = violation_causes(prev, r)
            q.append(1 if causes else 0)

            while len(q) > CFG["W"]:
                q.popleft()

            if len(q) == CFG["W"] and sum(q) >= K:
                if cid not in detected_time:
                    detected_time[cid] = r["simnow"]
                break

            prev = r

    return detected_time

def proposed_first_warn_time(lines, beacons):
    # Approximate WARN event time using nearest previous PASSIVE-BEACON for same CID.
    # This is safer than line number time because WARN lines do not contain SIMNOW directly.
    passive_before_line = defaultdict(list)
    for b in beacons:
        passive_before_line[b["cid"]].append((b["line_index"], b["simnow"]))

    for cid in passive_before_line:
        passive_before_line[cid].sort()

    first_warn = {}

    for idx, line in enumerate(lines):
        m = re.search(r"\[CAR\s+(\d+)\]\s+ACT=WARN", line)
        if not m:
            continue

        cid = int(m.group(1))
        if cid in first_warn:
            continue

        # nearest previous passive beacon for same CID
        nearest = None
        for line_idx, simnow in reversed(passive_before_line.get(cid, [])):
            if line_idx < idx:
                nearest = simnow
                break

        if nearest is not None:
            first_warn[cid] = nearest

    return first_warn

def selected_k_by_condition():
    out = {}
    for r in csv.DictReader(FAIR.open()):
        if r["method"] != "Best_Clean_Safe_Local_Segment_Reset_VeReMi":
            continue
        m = re.search(r"K=(\d+)", r["threshold_policy"])
        if m:
            out[r["condition"]] = int(m.group(1))
    return out

def mean(xs):
    return round(st.mean(xs), 3) if xs else ""

def median(xs):
    return round(st.median(xs), 3) if xs else ""

def sd(xs):
    return round(st.stdev(xs), 3) if len(xs) > 1 else 0.0

def pct(a, b):
    return round(100.0 * a / b, 2) if b else 0.0

selected_k = selected_k_by_condition()
per_cid_rows = []

for r in csv.DictReader(INPUT.open()):
    cond = r["condition"]
    seed = int(r["seed"])
    log_path = Path(r["log_path"])
    K = selected_k.get(cond, 2)

    beacons, lines = parse_beacons_with_line(log_path)
    malicious, honest = parse_truth(log_path)

    first_violation = first_physical_violation_time(beacons)
    baseline_time = baseline_segment_reset_detection_time(beacons, K)
    proposed_time = proposed_first_warn_time(lines, beacons)

    all_cids = sorted(malicious)

    for cid in all_cids:
        fv = first_violation.get(cid)
        pt = proposed_time.get(cid)
        bt = baseline_time.get(cid)

        proposed_detected = pt is not None
        baseline_detected = bt is not None

        proposed_delay = round(pt - fv, 3) if proposed_detected and fv is not None else ""
        baseline_delay = round(bt - fv, 3) if baseline_detected and fv is not None else ""

        common_detected = proposed_detected and baseline_detected and fv is not None

        per_cid_rows.append({
            "condition": cond,
            "seed": seed,
            "cid": cid,
            "selected_baseline_K": K,
            "first_physical_violation_time": fv if fv is not None else "",
            "proposed_first_WARN_time_est": pt if pt is not None else "",
            "baseline_segment_reset_detection_time": bt if bt is not None else "",
            "proposed_detected": "YES" if proposed_detected else "NO",
            "baseline_detected": "YES" if baseline_detected else "NO",
            "common_detected": "YES" if common_detected else "NO",
            "proposed_delay_sec": proposed_delay,
            "baseline_delay_sec": baseline_delay,
            "proposed_minus_baseline_delay_sec": round(proposed_delay - baseline_delay, 3) if common_detected else "",
            "source_log_path": str(log_path.resolve()),
        })

per_cid_rows = sorted(per_cid_rows, key=lambda x: (int(re.search(r"\d+", x["condition"]).group()), x["seed"], x["cid"]))

with OUT_PER_CID.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(per_cid_rows[0].keys()))
    writer.writeheader()
    writer.writerows(per_cid_rows)

agg_rows = []

for cond in sorted(set(r["condition"] for r in per_cid_rows), key=lambda x: int(re.search(r"\d+", x).group())):
    rows = [r for r in per_cid_rows if r["condition"] == cond]
    common = [r for r in rows if r["common_detected"] == "YES"]

    pd = [float(r["proposed_delay_sec"]) for r in common]
    bd = [float(r["baseline_delay_sec"]) for r in common]
    diff = [float(r["proposed_minus_baseline_delay_sec"]) for r in common]

    faster_prop = sum(1 for x in diff if x < 0)
    faster_base = sum(1 for x in diff if x > 0)
    ties = sum(1 for x in diff if x == 0)

    agg_rows.append({
        "condition": cond,
        "selected_baseline_K": selected_k.get(cond, 2),
        "malicious_total": len(rows),
        "proposed_detected": sum(1 for r in rows if r["proposed_detected"] == "YES"),
        "baseline_detected": sum(1 for r in rows if r["baseline_detected"] == "YES"),
        "common_detected_for_delay": len(common),

        "proposed_delay_mean_sec": mean(pd),
        "proposed_delay_median_sec": median(pd),
        "proposed_delay_std_sec": sd(pd),

        "baseline_delay_mean_sec": mean(bd),
        "baseline_delay_median_sec": median(bd),
        "baseline_delay_std_sec": sd(bd),

        "proposed_minus_baseline_delay_mean_sec": mean(diff),
        "proposed_minus_baseline_delay_median_sec": median(diff),

        "proposed_faster_count": faster_prop,
        "baseline_faster_count": faster_base,
        "tie_count": ties,

        "interpretation": "negative difference means proposed WARN/enforcement is earlier than local segment-reset baseline",
    })

with OUT_AGG.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(agg_rows[0].keys()))
    writer.writeheader()
    writer.writerows(agg_rows)

print("Saved:")
print(OUT_PER_CID)
print(OUT_AGG)

print()
print("===== DETECTION DELAY SUMMARY =====")
for r in agg_rows:
    print(r)
