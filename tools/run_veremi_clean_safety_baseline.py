import csv
import re
import math
import statistics as st
from pathlib import Path
from collections import defaultdict, deque

BASE = Path("results/final_locked_csv")
OUTDIR = BASE / "baseline_veremi"
OUTDIR.mkdir(parents=True, exist_ok=True)

CLEAN_RAW = BASE / "clean_cusum_safety_per_seed_raw.csv"
CLEAN_AGG = BASE / "clean_cusum_safety_aggregate_summary.csv"

OUT_INPUT = OUTDIR / "baseline_input_clean_safety_log_paths.csv"
OUT_RAW = OUTDIR / "veremi_clean_safety_k123_per_seed_raw.csv"
OUT_AGG = OUTDIR / "veremi_clean_safety_k123_aggregate_summary.csv"
OUT_COMPARE = OUTDIR / "proposed_vs_veremi_clean_safety_k123.csv"

CFG = {
    "K_values": [1, 2, 3],
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

def find_log(seed):
    patterns = [
        f"results/cusum_clean_veremi_on_H08_minobs3_edgemax05_15seed/ON_seed{seed}_*.log",
        f"results/*clean*15seed*/ON_seed{seed}_*.log",
    ]
    candidates = []
    for pat in patterns:
        candidates.extend(Path(".").glob(pat))
    candidates = sorted(set(candidates), key=lambda p: str(p))

    good = []
    for p in candidates:
        txt = p.read_text(errors="ignore")
        if "SIMULATION COMPLETE" in txt and txt.count("[PAYOFF]") >= 10:
            good.append(p)

    return good[-1] if good else None

def build_input():
    rows = []
    missing = []

    for r in csv.DictReader(CLEAN_RAW.open()):
        seed = int(r["seed"])
        log = find_log(seed)
        if log is None:
            missing.append(seed)
            continue

        rows.append({
            "condition": r["condition"],
            "seed": seed,
            "proposed_honest": r["honest"],
            "proposed_false_positive": r["false_positive"],
            "proposed_FPR_percent": r["FPR_percent"],
            "log_path": str(log.resolve()),
        })

    rows = sorted(rows, key=lambda x: x["seed"])

    with OUT_INPUT.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print("Saved input:", OUT_INPUT)
    print("Rows:", len(rows))
    print("Missing:", missing)

def parse_kv(line):
    out = {}
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*([^,\s\]]+)", line):
        k, v = m.group(1), m.group(2)
        try:
            out[k] = float(v) if "." in v or "e" in v.lower() else int(v)
        except ValueError:
            out[k] = v
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

    rows.sort(key=lambda r: (r["cid"], r["simnow"], r["ts"]))
    return rows

def parse_truth(log_path):
    honest = set()
    malicious = set()

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

    return honest, malicious

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

def make_segments(beacons):
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

def detect_segment_reset(beacons, K):
    detected = set()

    for cid, seg_id, rxuav, rows in make_segments(beacons):
        rows.sort(key=lambda r: (r["simnow"], r["ts"]))
        prev = None
        q = deque()

        for r in rows:
            causes = violation_causes(prev, r)
            q.append(1 if causes else 0)

            while len(q) > CFG["W"]:
                q.popleft()

            if len(q) == CFG["W"] and sum(q) >= K:
                detected.add(cid)
                break

            prev = r

    return detected

def pct(a, b):
    return round(100.0 * a / b, 2) if b else 0.0

def mean(xs):
    return round(st.mean(xs), 2) if xs else ""

def sd(xs):
    return round(st.stdev(xs), 2) if len(xs) > 1 else 0.0

build_input()

raw_rows = []

for r in csv.DictReader(OUT_INPUT.open()):
    seed = int(r["seed"])
    log_path = Path(r["log_path"])

    beacons = parse_beacons(log_path)
    honest, malicious = parse_truth(log_path)

    if malicious:
        print(f"WARNING seed={seed}: clean log has malicious CIDs: {sorted(malicious)}")

    for K in CFG["K_values"]:
        detected = detect_segment_reset(beacons, K)
        fp_ids = sorted(detected & honest)

        raw_rows.append({
            "condition": "CLEAN_HONEST",
            "baseline_variant": f"Local_CID_RXUAV_SEGMENT_RESET_OBS_K{K}_W{CFG['W']}",
            "K": K,
            "W": CFG["W"],
            "seed": seed,
            "beacon_count": len(beacons),
            "honest": len(honest),
            "false_positive": len(fp_ids),
            "FPR_percent": pct(len(fp_ids), len(honest)),
            "false_positive_ids": ";".join(map(str, fp_ids)),
            "source_log_path": str(log_path.resolve()),
        })

raw_rows = sorted(raw_rows, key=lambda x: (x["K"], x["seed"]))

with OUT_RAW.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
    writer.writeheader()
    writer.writerows(raw_rows)

agg_rows = []

for K in CFG["K_values"]:
    kr = [r for r in raw_rows if int(r["K"]) == K]

    total_fp = sum(int(r["false_positive"]) for r in kr)
    total_hon = sum(int(r["honest"]) for r in kr)
    fpr_vals = [float(r["FPR_percent"]) for r in kr]

    agg_rows.append({
        "condition": "CLEAN_HONEST",
        "baseline_variant": f"Local_CID_RXUAV_SEGMENT_RESET_OBS_K{K}_W{CFG['W']}",
        "valid_seeds": len(kr),
        "honest": total_hon,
        "false_positive": f"{total_fp}/{total_hon}",
        "overall_FPR_percent": pct(total_fp, total_hon),
        "FPR_mean_percent": mean(fpr_vals),
        "FPR_std": sd(fpr_vals),
        "raw_csv_path": str(OUT_RAW.resolve()),
    })

with OUT_AGG.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(agg_rows[0].keys()))
    writer.writeheader()
    writer.writerows(agg_rows)

proposed = list(csv.DictReader(CLEAN_AGG.open()))[0]

compare_rows = [{
    "condition": "CLEAN_HONEST",
    "method": "Proposed_UAV_Edge_Trust_Framework",
    "state_model": "trust_state_transferred_across_handover_with_guarded_confirmation",
    "honest": proposed["honest"],
    "false_positive": proposed["false_positive"],
    "overall_FPR_percent": proposed["overall_FPR_percent"],
    "FPR_mean_percent": "0.0",
    "FPR_std": "0.0",
}]

for a in agg_rows:
    compare_rows.append({
        "condition": "CLEAN_HONEST",
        "method": a["baseline_variant"],
        "state_model": "memory_resets_at_each_contiguous_RXUAV_segment",
        "honest": a["honest"],
        "false_positive": a["false_positive"],
        "overall_FPR_percent": a["overall_FPR_percent"],
        "FPR_mean_percent": a["FPR_mean_percent"],
        "FPR_std": a["FPR_std"],
    })

with OUT_COMPARE.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(compare_rows[0].keys()))
    writer.writeheader()
    writer.writerows(compare_rows)

print()
print("Saved:")
print(OUT_INPUT)
print(OUT_RAW)
print(OUT_AGG)
print(OUT_COMPARE)

print()
print("===== CLEAN SAFETY BASELINE AGGREGATE =====")
for r in agg_rows:
    print(r)

print()
print("===== PROPOSED VS CLEAN SAFETY BASELINE =====")
for r in compare_rows:
    print(r)
