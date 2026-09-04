import csv
import re
import math
from pathlib import Path
from collections import defaultdict, Counter, deque

BASE = Path("results/final_locked_csv/baseline_veremi")
INPUT = BASE / "baseline_input_n10_ar50_drop0_log_paths.csv"

OUT_PER_CID = BASE / "fragmentation_audit_n10_ar50_drop0_per_cid.csv"
OUT_SUMMARY = BASE / "fragmentation_audit_n10_ar50_drop0_summary.csv"

CFG = {
    "K": 3,
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
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_\-]*)\s*:\s*([^,\s\]]+)", line):
        k, v = m.group(1), m.group(2)
        try:
            out[k] = float(v) if "." in v or "e" in v.lower() else int(v)
        except ValueError:
            out[k] = v
    return out

def parse_truth_and_proposed(log_path):
    malicious, honest, proposed_detected = set(), set(), set()

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
                proposed_detected.add(cid)
        else:
            honest.add(cid)

    return malicious, honest, proposed_detected

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

def build_obs_for_group(rows):
    rows = sorted(rows, key=lambda r: (r["simnow"], r["ts"]))
    obs = []
    prev = None

    for r in rows:
        causes = violation_causes(prev, r)
        obs.append({
            "cid": r["cid"],
            "simnow": r["simnow"],
            "violation": 1 if causes else 0,
            "causes": causes,
            "rxuav": r["rxuav"],
            "zone": r["zone"],
        })
        prev = r

    return obs

def detect_and_max(obs):
    q = deque()
    max_sum = 0
    detected = False
    detect_time = ""

    for o in obs:
        q.append(o["violation"])
        while len(q) > CFG["W"]:
            q.popleft()

        s = sum(q)
        max_sum = max(max_sum, s)

        if len(q) == CFG["W"] and s >= CFG["K"] and not detected:
            detected = True
            detect_time = o["simnow"]

    return detected, max_sum, detect_time

def make_segments(rows, field):
    rows = sorted(rows, key=lambda r: (r["simnow"], r["ts"]))
    segments = []
    current = []
    current_val = None
    seg_id = 0

    for r in rows:
        val = r[field]
        if current and val != current_val:
            segments.append((seg_id, current_val, current))
            seg_id += 1
            current = []

        current.append(r)
        current_val = val

    if current:
        segments.append((seg_id, current_val, current))

    return segments

def best_over_groups(grouped_rows):
    any_detect = False
    best_max = 0
    first_time = ""

    for _, rows in grouped_rows.items():
        obs = build_obs_for_group(rows)
        det, mx, dt = detect_and_max(obs)
        best_max = max(best_max, mx)

        if det:
            any_detect = True
            if first_time == "" or dt < first_time:
                first_time = dt

    return any_detect, best_max, first_time

def best_over_segments(rows, field):
    any_detect = False
    best_max = 0
    first_time = ""
    best_seg = ""

    for seg_id, val, seg_rows in make_segments(rows, field):
        obs = build_obs_for_group(seg_rows)
        det, mx, dt = detect_and_max(obs)
        best_max = max(best_max, mx)

        if det:
            any_detect = True
            if first_time == "" or dt < first_time:
                first_time = dt
                best_seg = f"{field}={val},segment={seg_id}"

    return any_detect, best_max, first_time, best_seg

per_cid_rows = []

for inp in csv.DictReader(INPUT.open()):
    seed = int(inp["seed"])
    log_path = Path(inp["log_path"])

    malicious, honest, proposed_detected = parse_truth_and_proposed(log_path)
    beacons = parse_beacons(log_path)

    by_cid = defaultdict(list)
    for b in beacons:
        by_cid[b["cid"]].append(b)

    for cid, rows in sorted(by_cid.items()):
        rows = sorted(rows, key=lambda r: (r["simnow"], r["ts"]))

        central_obs = build_obs_for_group(rows)
        central_det, central_max, central_time = detect_and_max(central_obs)

        by_rxuav = defaultdict(list)
        by_zone = defaultdict(list)

        for r in rows:
            by_rxuav[r["rxuav"]].append(r)
            by_zone[r["zone"]].append(r)

        rxuav_mem_det, rxuav_mem_max, rxuav_mem_time = best_over_groups(by_rxuav)
        zone_mem_det, zone_mem_max, zone_mem_time = best_over_groups(by_zone)

        rxuav_seg_det, rxuav_seg_max, rxuav_seg_time, rxuav_seg_label = best_over_segments(rows, "rxuav")
        zone_seg_det, zone_seg_max, zone_seg_time, zone_seg_label = best_over_segments(rows, "zone")

        zones = [r["zone"] for r in rows]
        rxuavs = [r["rxuav"] for r in rows]

        zone_changes = sum(1 for a, b in zip(zones, zones[1:]) if a != b)
        rxuav_changes = sum(1 for a, b in zip(rxuavs, rxuavs[1:]) if a != b)

        total_viol = sum(o["violation"] for o in central_obs)

        strong_fragmentation = (
            central_det
            and not rxuav_seg_det
            and not zone_seg_det
        )

        architecture_gap_candidate = (
            central_det
            and not rxuav_mem_det
        )

        per_cid_rows.append({
            "seed": seed,
            "cid": cid,
            "malicious": "YES" if cid in malicious else "NO",
            "proposed_detected": "YES" if cid in proposed_detected else "NO",
            "beacons": len(rows),
            "total_violating_observations": total_viol,
            "unique_zones": len(set(zones)),
            "unique_rxuavs": len(set(rxuavs)),
            "zone_changes": zone_changes,
            "rxuav_changes": rxuav_changes,

            "central_detected": "YES" if central_det else "NO",
            "central_max_window_violations": central_max,
            "central_detection_time": central_time,

            "rxuav_memory_detected": "YES" if rxuav_mem_det else "NO",
            "rxuav_memory_max_window_violations": rxuav_mem_max,
            "rxuav_memory_detection_time": rxuav_mem_time,

            "zone_memory_detected": "YES" if zone_mem_det else "NO",
            "zone_memory_max_window_violations": zone_mem_max,
            "zone_memory_detection_time": zone_mem_time,

            "rxuav_segment_detected": "YES" if rxuav_seg_det else "NO",
            "rxuav_segment_max_window_violations": rxuav_seg_max,
            "rxuav_segment_detection_time": rxuav_seg_time,
            "rxuav_segment_label": rxuav_seg_label,

            "zone_segment_detected": "YES" if zone_seg_det else "NO",
            "zone_segment_max_window_violations": zone_seg_max,
            "zone_segment_detection_time": zone_seg_time,
            "zone_segment_label": zone_seg_label,

            "strong_fragmentation_case": "YES" if strong_fragmentation else "NO",
            "architecture_gap_candidate": "YES" if architecture_gap_candidate else "NO",
            "source_log_path": str(log_path.resolve()),
        })

with OUT_PER_CID.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(per_cid_rows[0].keys()))
    writer.writeheader()
    writer.writerows(per_cid_rows)

summary_rows = []

for label, subset in [
    ("ALL", per_cid_rows),
    ("MALICIOUS", [r for r in per_cid_rows if r["malicious"] == "YES"]),
    ("HONEST", [r for r in per_cid_rows if r["malicious"] == "NO"]),
]:
    n = len(subset)

    def count_yes(col):
        return sum(1 for r in subset if r[col] == "YES")

    summary_rows.append({
        "group": label,
        "vehicles": n,
        "proposed_detected": count_yes("proposed_detected"),
        "central_detected": count_yes("central_detected"),
        "rxuav_memory_detected": count_yes("rxuav_memory_detected"),
        "zone_memory_detected": count_yes("zone_memory_detected"),
        "rxuav_segment_detected": count_yes("rxuav_segment_detected"),
        "zone_segment_detected": count_yes("zone_segment_detected"),
        "strong_fragmentation_cases": count_yes("strong_fragmentation_case"),
        "architecture_gap_candidates": count_yes("architecture_gap_candidate"),
    })

with OUT_SUMMARY.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
    writer.writeheader()
    writer.writerows(summary_rows)

print("Saved:")
print(OUT_PER_CID)
print(OUT_SUMMARY)

print()
print("===== FRAGMENTATION SUMMARY =====")
for r in summary_rows:
    print(r)

print()
print("===== MALICIOUS STRONG FRAGMENTATION CASES =====")
cases = [
    r for r in per_cid_rows
    if r["malicious"] == "YES" and r["strong_fragmentation_case"] == "YES"
]
print("count:", len(cases))
for r in cases[:30]:
    print(
        f"seed={r['seed']} cid={r['cid']} proposed={r['proposed_detected']} "
        f"central_max={r['central_max_window_violations']} "
        f"rxseg_max={r['rxuav_segment_max_window_violations']} "
        f"zoneseg_max={r['zone_segment_max_window_violations']} "
        f"rx_changes={r['rxuav_changes']}"
    )
