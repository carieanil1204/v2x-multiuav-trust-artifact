import csv
import re
import math
import statistics as st
from pathlib import Path
from collections import defaultdict, deque

BASE = Path("results/final_locked_csv")
B = BASE / "baseline_veremi"

INPUT = B / "baseline_input_packet_loss_log_paths.csv"
PROPOSED_AGG = BASE / "packet_loss_robustness_aggregate_summary.csv"
CLEAN_AGG = B / "veremi_clean_safety_k123_aggregate_summary.csv"

OUT_RAW = B / "veremi_segment_reset_packet_loss_k123_per_seed_raw.csv"
OUT_AGG = B / "veremi_segment_reset_packet_loss_k123_aggregate_summary.csv"
OUT_FAIR = B / "proposed_vs_best_clean_safe_segment_reset_veremi_packet_loss.csv"
OUT_THRESHOLD = B / "segment_reset_veremi_threshold_selection_summary.csv"

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

def detect_segment_reset(beacons, K):
    detected = set()

    for cid, seg_id, rxuav, rows in make_contiguous_rxuav_segments(beacons):
        rows.sort(key=lambda r: (r["simnow"], r["ts"]))
        q = deque()
        prev = None

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

raw_rows = []

for r in csv.DictReader(INPUT.open()):
    condition = r["condition"]
    seed = int(r["seed"])
    log_path = Path(r["log_path"])

    beacons = parse_beacons(log_path)
    malicious, honest = parse_truth(log_path)

    for K in CFG["K_values"]:
        detected = detect_segment_reset(beacons, K)

        tp_ids = sorted(detected & malicious)
        fp_ids = sorted(detected & honest)
        fn_ids = sorted(malicious - detected)

        tp, fp, fn = len(tp_ids), len(fp_ids), len(fn_ids)

        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

        raw_rows.append({
            "condition": condition,
            "baseline_variant": f"Local_CID_RXUAV_SEGMENT_RESET_OBS_K{K}_W{CFG['W']}",
            "K": K,
            "W": CFG["W"],
            "seed": seed,
            "beacon_count": len(beacons),
            "malicious": len(malicious),
            "honest": len(honest),
            "detected": tp,
            "false_positive": fp,
            "missed": fn,
            "DR_percent": pct(tp, len(malicious)),
            "FPR_percent": pct(fp, len(honest)),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "F1": round(f1, 4),
            "detected_ids": ";".join(map(str, tp_ids)),
            "missed_ids": ";".join(map(str, fn_ids)),
            "false_positive_ids": ";".join(map(str, fp_ids)),
            "source_log_path": str(log_path.resolve()),
        })

raw_rows = sorted(
    raw_rows,
    key=lambda x: (int(re.search(r"\d+", x["condition"]).group()), int(x["K"]), int(x["seed"]))
)

with OUT_RAW.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
    writer.writeheader()
    writer.writerows(raw_rows)

agg_rows = []

conditions = sorted(set(r["condition"] for r in raw_rows), key=lambda x: int(re.search(r"\d+", x).group()))

for condition in conditions:
    for K in CFG["K_values"]:
        cr = [r for r in raw_rows if r["condition"] == condition and int(r["K"]) == K]

        total_det = sum(int(r["detected"]) for r in cr)
        total_mal = sum(int(r["malicious"]) for r in cr)
        total_fp = sum(int(r["false_positive"]) for r in cr)
        total_hon = sum(int(r["honest"]) for r in cr)

        dr_vals = [float(r["DR_percent"]) for r in cr]
        fpr_vals = [float(r["FPR_percent"]) for r in cr]
        f1_vals = [float(r["F1"]) for r in cr]

        agg_rows.append({
            "condition": condition,
            "baseline_variant": f"Local_CID_RXUAV_SEGMENT_RESET_OBS_K{K}_W{CFG['W']}",
            "K": K,
            "W": CFG["W"],
            "valid_seeds": len(cr),
            "caught": f"{total_det}/{total_mal}",
            "pooled_DR_percent": pct(total_det, total_mal),
            "DR_mean_percent": mean(dr_vals),
            "DR_std": sd(dr_vals),
            "false_positive": f"{total_fp}/{total_hon}",
            "pooled_FPR_percent": pct(total_fp, total_hon),
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

# Clean-safe threshold selection
clean_rows = list(csv.DictReader(CLEAN_AGG.open()))
clean_safe_K = []
threshold_rows = []

for r in clean_rows:
    m = re.search(r"_K(\d+)_W", r["baseline_variant"])
    if not m:
        continue
    K = int(m.group(1))
    fpr = float(r["overall_FPR_percent"])
    is_clean_safe = fpr == 0.0
    if is_clean_safe:
        clean_safe_K.append(K)

    threshold_rows.append({
        "K": K,
        "clean_false_positive": r["false_positive"],
        "clean_FPR_percent": fpr,
        "clean_safe": "YES" if is_clean_safe else "NO",
        "decision": "eligible_for_fair_attack_comparison" if is_clean_safe else "excluded_due_to_clean_false_positives",
    })

with OUT_THRESHOLD.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(threshold_rows[0].keys()))
    writer.writeheader()
    writer.writerows(threshold_rows)

# Fair comparison: choose best DR among clean-safe K values for each packet-loss condition.
proposed_rows = list(csv.DictReader(PROPOSED_AGG.open()))
fair_rows = []

for p in proposed_rows:
    cond = p["condition"]

    fair_rows.append({
        "condition": cond,
        "method": "Proposed_UAV_Edge_Trust_Framework",
        "threshold_policy": "internal_guarded_trust_decision",
        "state_model": "trust_state_transferred_across_handover_with_HTD",
        "caught": p["caught"],
        "pooled_DR_percent": p["pooled_DR_percent"],
        "DR_mean_percent": p["DR_mean_percent"],
        "DR_std": p["DR_std"],
        "false_positive": p["false_positive"],
        "pooled_FPR_percent": p["pooled_FPR_percent"],
        "FPR_mean_percent": p["FPR_mean_percent"],
        "FPR_std": p["FPR_std"],
        "F1_mean": "",
        "note": "proposed complete system",
    })

    candidates = [
        a for a in agg_rows
        if a["condition"] == cond and int(a["K"]) in clean_safe_K
    ]

    best = sorted(
        candidates,
        key=lambda x: (float(x["pooled_DR_percent"]), -int(x["K"])),
        reverse=True
    )[0]

    gain = round(float(p["pooled_DR_percent"]) - float(best["pooled_DR_percent"]), 2)

    fair_rows.append({
        "condition": cond,
        "method": "Best_Clean_Safe_Local_Segment_Reset_VeReMi",
        "threshold_policy": f"best_clean_safe_K={best['K']}_W={best['W']}",
        "state_model": "memory_resets_at_each_contiguous_RXUAV_segment",
        "caught": best["caught"],
        "pooled_DR_percent": best["pooled_DR_percent"],
        "DR_mean_percent": best["DR_mean_percent"],
        "DR_std": best["DR_std"],
        "false_positive": best["false_positive"],
        "pooled_FPR_percent": best["pooled_FPR_percent"],
        "FPR_mean_percent": best["FPR_mean_percent"],
        "FPR_std": best["FPR_std"],
        "F1_mean": best["F1_mean"],
        "note": f"proposed_DR_minus_baseline_DR={gain}_percentage_points",
    })

with OUT_FAIR.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(fair_rows[0].keys()))
    writer.writeheader()
    writer.writerows(fair_rows)

print("Saved:")
print(OUT_RAW)
print(OUT_AGG)
print(OUT_THRESHOLD)
print(OUT_FAIR)

print()
print("===== THRESHOLD SELECTION =====")
for r in threshold_rows:
    print(r)

print()
print("===== K1/K2/K3 SEGMENT-RESET PACKET LOSS AGGREGATE =====")
for r in agg_rows:
    print(r)

print()
print("===== FAIR COMPARISON: PROPOSED VS BEST CLEAN-SAFE SEGMENT-RESET VEREMI =====")
for r in fair_rows:
    print(r)
