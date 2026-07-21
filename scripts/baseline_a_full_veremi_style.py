#!/usr/bin/env python3
import argparse
import math
import os
import re
from collections import defaultdict, Counter
from dataclasses import dataclass
from pathlib import Path

PASSIVE_RE = re.compile(r"\[PASSIVE-BEACON\](.*)")
PAYOFF_RE = re.compile(
    r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)"
)

@dataclass
class Packet:
    simnow: float
    cid: int
    zone: int
    rxuav: int
    edgeport: int
    ts: float
    spd: float
    hdg: float
    px: float
    py: float
    lan: int
    brk: int
    rx_x: float
    rx_y: float
    rx_z: float

@dataclass
class Decision:
    banned: bool
    first_ts: float | None
    first_reason: str
    violations: int
    packet_count: int
    reason_counts: Counter

def parse_kv_tail(tail: str):
    kv = {}
    for tok in tail.strip().split():
        if ":" not in tok:
            continue
        k, v = tok.split(":", 1)
        kv[k] = v
    return kv

def get_float(kv, key, default=0.0):
    try:
        return float(kv.get(key, default))
    except Exception:
        return default

def get_int(kv, key, default=0):
    try:
        return int(float(kv.get(key, default)))
    except Exception:
        return default

def parse_log(path: Path):
    packets = defaultdict(list)
    payoff = {}

    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = PASSIVE_RE.search(line)
            if m:
                kv = parse_kv_tail(m.group(1))
                cid = get_int(kv, "CID", -1)
                if cid < 0:
                    continue

                pkt = Packet(
                    simnow=get_float(kv, "SIMNOW"),
                    cid=cid,
                    zone=get_int(kv, "ZONE", 1),
                    rxuav=get_int(kv, "RXUAV", 1),
                    edgeport=get_int(kv, "EDGEPORT", 0),
                    ts=get_float(kv, "TS"),
                    spd=get_float(kv, "SPD"),
                    hdg=get_float(kv, "HDG"),
                    px=get_float(kv, "PX"),
                    py=get_float(kv, "PY"),
                    lan=get_int(kv, "LAN", -1),
                    brk=get_int(kv, "BRK", -1),
                    rx_x=get_float(kv, "RX_X"),
                    rx_y=get_float(kv, "RX_Y"),
                    rx_z=get_float(kv, "RX_Z"),
                )
                packets[cid].append(pkt)
                continue

            p = PAYOFF_RE.search(line)
            if p:
                cid = int(p.group(1))
                payoff[cid] = {
                    "demoted": p.group(2) == "YES",
                    "malicious": p.group(3) == "YES",
                }

    return packets, payoff

def hypot2(dx, dy):
    return math.sqrt(dx * dx + dy * dy)

def heading_predict(prev: Packet, dt: float):
    theta = math.radians(prev.hdg)
    pred_x = prev.px + abs(prev.spd) * dt * math.cos(theta)
    pred_y = prev.py + abs(prev.spd) * dt * math.sin(theta)
    return pred_x, pred_y

def packet_reasons(prev: Packet | None, pkt: Packet, args, max_ts_seen=None):
    reasons = []

    # C0: Simple Speed Check
    if abs(pkt.spd) > args.max_speed:
        reasons.append(f"simple_speed({pkt.spd:.2f}>{args.max_speed:.2f})")

    # C1: Trusted receiver-time lag / replay check
    lag = pkt.simnow - pkt.ts
    if abs(lag) > args.max_ts_lag:
        reasons.append(f"ts_lag(simnow-ts={lag:.3f})")

    # C2-C5 require previous packet in arrival order
    if prev is not None:
        # C2: claimed timestamp replay / monotonicity.
        # If max_ts_seen is available, use per-CID high-water-mark logic so
        # exact repeats/ties are treated as replay, not only strict decreases.
        # This catches ATK_ADAPTIVE timestamp replay where TS_OFFSET_ATTACK
        # equals the 0.5s beacon interval.
        if max_ts_seen is not None:
            if pkt.ts <= max_ts_seen + args.ts_monotonic_slack:
                reasons.append(
                    f"ts_nonmonotonic(max_seen={max_ts_seen:.3f},now={pkt.ts:.3f})"
                )
        else:
            if pkt.ts + args.ts_monotonic_slack < prev.ts:
                reasons.append(f"ts_nonmonotonic(prev={prev.ts:.3f},now={pkt.ts:.3f})")

        dx = pkt.px - prev.px
        dy = pkt.py - prev.py
        dist = hypot2(dx, dy)

        # C3: position prediction using claimed timestamp delta
        dt_claim = pkt.ts - prev.ts
        if 1e-6 < dt_claim <= args.max_gap:
            pred_x, pred_y = heading_predict(prev, dt_claim)
            pos_err = hypot2(pkt.px - pred_x, pkt.py - pred_y)
            if pos_err > args.pos_tolerance:
                reasons.append(f"pos_pred_claimed(err={pos_err:.2f})")

            derived_speed = dist / dt_claim
            mismatch = abs(derived_speed - abs(pkt.spd))
            if mismatch > args.speed_tolerance:
                reasons.append(
                    f"speed_pos_claimed(derived={derived_speed:.2f},spd={pkt.spd:.2f},mis={mismatch:.2f})"
                )

        # C4: receiver-time speed-position mismatch
        dt_rx = pkt.simnow - prev.simnow
        if 1e-6 < dt_rx <= args.max_gap:
            derived_rx = dist / dt_rx
            mismatch_rx = abs(derived_rx - abs(pkt.spd))
            if mismatch_rx > args.rx_speed_tolerance:
                reasons.append(
                    f"speed_pos_rx(derived={derived_rx:.2f},spd={pkt.spd:.2f},mis={mismatch_rx:.2f})"
                )

    # C5: Acceptance Range Threshold, optional
    if args.comm_range > 0:
        rx_dist = hypot2(pkt.px - pkt.rx_x, pkt.py - pkt.rx_y)
        if rx_dist > args.comm_range + args.art_margin:
            reasons.append(f"acceptance_range(dist={rx_dist:.2f})")

    return reasons

def detector(stream, args, enabled_prefixes):
    consecutive = 0
    first_ts = None
    first_reason = "none"
    reason_counts = Counter()
    prev = None
    max_ts_seen = None

    for pkt in stream:
        all_reasons = packet_reasons(prev, pkt, args, max_ts_seen)
        active = []
        for r in all_reasons:
            if any(r.startswith(prefix) for prefix in enabled_prefixes):
                active.append(r)

        if active:
            consecutive += 1
            for r in active:
                reason_counts[r.split("(")[0]] += 1
            if first_ts is None:
                first_ts = pkt.simnow
                first_reason = ";".join(active)
            if consecutive >= args.min_violations:
                return Decision(True, first_ts, first_reason, consecutive, len(stream), reason_counts)
        else:
            consecutive = 0

        if max_ts_seen is None or pkt.ts > max_ts_seen:
            max_ts_seen = pkt.ts

        prev = pkt

    return Decision(False, first_ts, first_reason, consecutive, len(stream), reason_counts)

DETECTORS = {
    "simple_speed": ["simple_speed"],
    "ts_lag": ["ts_lag"],
    "ts_monotonic": ["ts_nonmonotonic"],
    "pos_pred_claimed": ["pos_pred_claimed"],
    "speed_pos_claimed": ["speed_pos_claimed"],
    "speed_pos_rx": ["speed_pos_rx"],
    "acceptance_range": ["acceptance_range"],
    # Main paper baseline: full VeReMi-style core physical/timestamp consistency.
    # Excludes speed_pos_rx because receiver-time speed estimation is sensitive to
    # receive scheduling jitter and must be reported separately or calibrated.
    "combined_core": [
        "simple_speed",
        "ts_lag",
        "ts_nonmonotonic",
        "pos_pred_claimed",
        "speed_pos_claimed",
    ],

    # Aggressive receiver-time variant; useful for sensitivity analysis, not default.
    "combined_rx_augmented": [
        "simple_speed",
        "ts_lag",
        "ts_nonmonotonic",
        "pos_pred_claimed",
        "speed_pos_claimed",
        "speed_pos_rx",
    ],

    # Optional ART variant; use only when RX_X/RX_Y and comm range are verified.
    "combined_with_art": [
        "simple_speed",
        "ts_lag",
        "ts_nonmonotonic",
        "pos_pred_claimed",
        "speed_pos_claimed",
        "speed_pos_rx",
        "acceptance_range",
    ],
}

def evaluate_file(path: Path, args):
    packets, payoff = parse_log(path)

    results = {}
    for name, prefixes in DETECTORS.items():
        mal = caught = hon = fp = 0
        reason_counts = Counter()

        for cid, truth in payoff.items():
            stream = packets.get(cid, [])
            d = detector(stream, args, prefixes)
            reason_counts.update(d.reason_counts)

            if truth["malicious"]:
                mal += 1
                caught += int(d.banned)
            else:
                hon += 1
                fp += int(d.banned)

        results[name] = {
            "mal": mal,
            "caught": caught,
            "hon": hon,
            "fp": fp,
            "reason_counts": reason_counts,
        }

    return results, packets, payoff

def merge_results(total, one):
    for name, r in one.items():
        if name not in total:
            total[name] = {
                "mal": 0,
                "caught": 0,
                "hon": 0,
                "fp": 0,
                "reason_counts": Counter(),
            }
        total[name]["mal"] += r["mal"]
        total[name]["caught"] += r["caught"]
        total[name]["hon"] += r["hon"]
        total[name]["fp"] += r["fp"]
        total[name]["reason_counts"].update(r["reason_counts"])

def print_table(title, results):
    print()
    print("=" * 92)
    print(title)
    print("=" * 92)
    print(f"{'Detector':24s} {'Mal':>5s} {'Caught':>7s} {'DR%':>8s} {'Hon':>5s} {'FP':>5s} {'FPR%':>8s}  Main reasons")
    print("-" * 92)

    for name, r in results.items():
        mal = r["mal"]
        hon = r["hon"]
        dr = 100.0 * r["caught"] / mal if mal else 0.0
        fpr = 100.0 * r["fp"] / hon if hon else 0.0
        reasons = ", ".join(f"{k}:{v}" for k, v in r["reason_counts"].most_common(3))
        print(f"{name:24s} {mal:5d} {r['caught']:7d} {dr:8.1f} {hon:5d} {r['fp']:5d} {fpr:8.1f}  {reasons}")

def collect_logs(args):
    if args.log_file:
        return [Path(args.log_file)]

    if not args.results_dir:
        raise SystemExit("ERROR: provide either --log_file or --results_dir")

    base = Path(args.results_dir)
    if args.seeds:
        return [base / f"ns3_seed_{s}.log" for s in args.seeds]

    return sorted(base.glob("ns3_seed_*.log"))

def main():
    ap = argparse.ArgumentParser(
        description="Full VeReMi-style physical plausibility baseline over [PASSIVE-BEACON] logs."
    )
    ap.add_argument("--log_file", default=None)
    ap.add_argument("--results_dir", default=None)
    ap.add_argument("--seeds", nargs="*", type=int, default=[])

    ap.add_argument("--max_speed", type=float, default=35.0)
    ap.add_argument("--max_ts_lag", type=float, default=2.0)
    ap.add_argument("--ts_monotonic_slack", type=float, default=0.05)
    ap.add_argument("--pos_tolerance", type=float, default=15.0)
    ap.add_argument("--speed_tolerance", type=float, default=8.0)
    ap.add_argument("--rx_speed_tolerance", type=float, default=8.0)
    ap.add_argument("--max_gap", type=float, default=3.0)
    ap.add_argument("--min_violations", type=int, default=1)

    # Keep ART disabled unless receiver position and comm range are verified meaningful.
    ap.add_argument("--comm_range", type=float, default=0.0)
    ap.add_argument("--art_margin", type=float, default=0.0)

    args = ap.parse_args()

    logs = collect_logs(args)
    total = {}

    print("Full VeReMi-style baseline")
    print("Logs:")
    for p in logs:
        print(" ", p)

    for p in logs:
        if not p.exists():
            print(f"WARNING: missing log {p}")
            continue
        one, packets, payoff = evaluate_file(p, args)
        merge_results(total, one)
        n_passive = sum(len(v) for v in packets.values())
        print(f"\nParsed {p}: passive_packets={n_passive}, payoff_cars={len(payoff)}")
        print_table(f"Per-file result: {p.name}", one)

    print_table("TOTAL RESULT", total)

    if args.comm_range <= 0:
        print("\nNOTE: Acceptance Range Threshold is disabled because --comm_range <= 0.")
        print("      This is intentional until RX_X/RX_Y and communication range are verified meaningful.")

if __name__ == "__main__":
    main()
