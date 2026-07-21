#!/usr/bin/env python3
"""
Baseline A (corrected): VeReMi-style consistency/plausibility detector.

This baseline is intended for offline comparison against Paper 2 NS3 logs.
It is stronger and fairer than the earlier raw-threshold baseline because it
checks whether successive claimed states are physically consistent.

Implemented checks per vehicle:
  1. Raw speed plausibility:
       |SPD_t| > max_speed
  2. Position-rate plausibility:
       distance((PX_t,PY_t),(PX_t-1,PY_t-1)) / dt > max_position_rate
  3. Reported-speed consistency:
       |observed_position_rate - reported_speed| > speed_tolerance
  4. Optional timestamp-lag check if a receiver/simulation time is available
       receive_time - TS > max_ts_lag

The script uses PAYOFF lines as ground truth:
  [PAYOFF] CID:<id> ... demoted=YES/NO ... malicious=YES/NO

Example:
  python3 baseline_a_veremi_consistency.py \
    --results_dir ~/research/projects/v2x-multiuav-trust/results/clean_multiseed_v91_20260705_220415 \
    --seeds 1 2 3 4 5 \
    --max_speed 35.0 \
    --max_position_rate 40.0 \
    --speed_tolerance 12.0 \
    --min_violations 2
"""

from __future__ import annotations

import argparse
import math
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class Packet:
    cid: int
    ts: float
    spd: float
    px: float
    py: float
    rx_time: Optional[float]
    raw: str


@dataclass
class VerdictDetail:
    predicted_ban: bool
    first_reason: str
    first_ts: Optional[float]
    violation_count: int
    packet_count: int


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Corrected VeReMi-style consistency baseline for Paper 2 logs"
    )
    p.add_argument("--results_dir", required=True,
                   help="Directory containing ns3_seed_N.log files")
    p.add_argument("--seeds", nargs="+", type=int, default=[1, 2, 3, 4, 5])
    p.add_argument("--max_speed", type=float, default=35.0,
                   help="Maximum plausible reported speed in m/s")
    p.add_argument("--max_position_rate", type=float, default=40.0,
                   help="Maximum plausible position displacement rate in m/s")
    p.add_argument("--speed_tolerance", type=float, default=12.0,
                   help="Allowed mismatch between reported speed and position-derived speed")
    p.add_argument("--max_ts_lag", type=float, default=2.0,
                   help="Maximum allowed receive_time - TS if receive time is parsable")
    p.add_argument("--min_violations", type=int, default=2,
                   help="Consecutive violations required before BAN")
    p.add_argument("--debug", action="store_true",
                   help="Print per-CID first violation reason")
    return p.parse_args()


def extract_float(patterns: List[str], line: str) -> Optional[float]:
    for pat in patterns:
        m = re.search(pat, line)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
    return None


def parse_receive_time(line: str) -> Optional[float]:
    """Best-effort parser for receiver/simulation time.

    Many logs only include claimed TS. If no receiver time is present, timestamp-lag
    check is skipped without affecting other checks.
    """
    return extract_float([
        r"SIMNOW:([\d.]+)",
        r"RXTIME:([\d.]+)",
        r"RX_TS:([\d.]+)",
        r"NOW:([\d.]+)",
        r"\bNow=([\d.]+)",
        r"\bat\s+([\d.]+)s\b",
        r"^\s*\[?([\d.]+)s\]?",
    ], line)


def parse_ns3_log(log_path: str) -> Tuple[Dict[int, List[Packet]], Dict[int, Dict[str, bool]]]:
    packets: Dict[int, List[Packet]] = defaultdict(list)
    payoff: Dict[int, Dict[str, bool]] = {}

    pay_pat = re.compile(
        r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)"
    )

    with open(log_path, "r", errors="ignore") as f:
        for line in f:
            if "UAV->CLOUD" in line:
                cid_m = re.search(r"CID:(\d+)", line)
                ts_m = re.search(r"TS:([-\d.]+)", line)
                spd_m = re.search(r"SPD:([-\d.]+)", line)
                px_m = re.search(r"PX:([-\d.]+)", line)
                py_m = re.search(r"PY:([-\d.]+)", line)

                if cid_m and ts_m and spd_m and px_m:
                    cid = int(cid_m.group(1))
                    if cid == 8801:
                        continue
                    try:
                        packets[cid].append(Packet(
                            cid=cid,
                            ts=float(ts_m.group(1)),
                            spd=float(spd_m.group(1)),
                            px=float(px_m.group(1)),
                            py=float(py_m.group(1)) if py_m else 0.0,
                            rx_time=parse_receive_time(line),
                            raw=line.strip(),
                        ))
                    except ValueError:
                        continue

            pay_m = pay_pat.search(line)
            if pay_m:
                cid = int(pay_m.group(1))
                payoff[cid] = {
                    "malicious": pay_m.group(3) == "YES",
                    "demoted": pay_m.group(2) == "YES",
                }

    return packets, payoff


def consistency_detector(
    stream: List[Packet],
    max_speed: float,
    max_position_rate: float,
    speed_tolerance: float,
    max_ts_lag: float,
    min_violations: int,
) -> VerdictDetail:
    streak = 0
    total_viol = 0
    first_reason = ""
    first_ts: Optional[float] = None
    prev: Optional[Packet] = None

    for pkt in sorted(stream, key=lambda p: p.ts):
        violation = False
        reasons = []

        # 1. Raw speed plausibility.
        if abs(pkt.spd) > max_speed:
            violation = True
            reasons.append(f"raw_speed={pkt.spd:.2f}>{max_speed:.2f}")

        # 2. Timestamp lag, only if a receiver/simulation time exists.
        if pkt.rx_time is not None and (pkt.rx_time - pkt.ts) > max_ts_lag:
            violation = True
            reasons.append(f"timestamp_lag={pkt.rx_time - pkt.ts:.2f}>{max_ts_lag:.2f}")

        if prev is not None:
            dt = pkt.ts - prev.ts
            if dt > 1e-6:
                dx = pkt.px - prev.px
                dy = pkt.py - prev.py
                dist = math.hypot(dx, dy)
                observed_rate = dist / dt

                # 3. Position-rate plausibility.
                if observed_rate > max_position_rate:
                    violation = True
                    reasons.append(
                        f"position_rate={observed_rate:.2f}>{max_position_rate:.2f}"
                    )

                # 4. Consistency between reported speed and derived speed.
                if abs(observed_rate - abs(pkt.spd)) > speed_tolerance:
                    violation = True
                    reasons.append(
                        f"speed_mismatch=|{observed_rate:.2f}-{abs(pkt.spd):.2f}|>{speed_tolerance:.2f}"
                    )

        if violation:
            streak += 1
            total_viol += 1
            if not first_reason:
                first_reason = ";".join(reasons)
                first_ts = pkt.ts
            if streak >= min_violations:
                return VerdictDetail(True, first_reason, first_ts, total_viol, len(stream))
        else:
            streak = 0

        prev = pkt

    return VerdictDetail(False, first_reason or "none", first_ts, total_viol, len(stream))


def evaluate_seed(args: argparse.Namespace, seed: int) -> Optional[Dict[str, object]]:
    log_path = os.path.join(args.results_dir, f"ns3_seed_{seed}.log")
    if not os.path.exists(log_path):
        print(f"  [WARN] missing {log_path}")
        return None

    packets, payoff = parse_ns3_log(log_path)
    if not payoff:
        print(f"  [WARN] no PAYOFF lines in seed {seed}")
        return None

    total_mal = caught = total_hon = fp = 0
    details = {}

    for cid, truth in sorted(payoff.items()):
        detail = consistency_detector(
            packets.get(cid, []),
            args.max_speed,
            args.max_position_rate,
            args.speed_tolerance,
            args.max_ts_lag,
            args.min_violations,
        )
        details[cid] = detail

        if truth["malicious"]:
            total_mal += 1
            caught += int(detail.predicted_ban)
        else:
            total_hon += 1
            fp += int(detail.predicted_ban)

    dr = 100.0 * caught / total_mal if total_mal else 0.0
    fpr = 100.0 * fp / total_hon if total_hon else 0.0

    if args.debug:
        print(f"\n[DEBUG seed {seed}] first flagged CIDs")
        for cid, d in details.items():
            if d.predicted_ban:
                truth = "MAL" if payoff[cid]["malicious"] else "HON"
                print(f"  CID:{cid:<3} truth={truth} ts={d.first_ts} reason={d.first_reason}")

    return {
        "seed": seed,
        "total_mal": total_mal,
        "caught": caught,
        "total_hon": total_hon,
        "fp": fp,
        "dr": dr,
        "fpr": fpr,
    }


def main() -> None:
    args = parse_args()
    print("\n" + "=" * 78)
    print("  Baseline A corrected: VeReMi-style consistency/plausibility detector")
    print(f"  results_dir       : {args.results_dir}")
    print(f"  seeds             : {args.seeds}")
    print(f"  max_speed         : {args.max_speed}")
    print(f"  max_position_rate : {args.max_position_rate}")
    print(f"  speed_tolerance   : {args.speed_tolerance}")
    print(f"  max_ts_lag        : {args.max_ts_lag}")
    print(f"  min_violations    : {args.min_violations}")
    print("=" * 78 + "\n")

    totals = {"mal": 0, "caught": 0, "hon": 0, "fp": 0}
    rows = []

    print(f"{'Seed':<6} {'Mal':<5} {'Caught':<8} {'DR%':<8} {'Hon':<5} {'FP':<5} {'FPR%'}")
    print("-" * 54)
    for seed in args.seeds:
        r = evaluate_seed(args, seed)
        if r is None:
            continue
        rows.append(r)
        totals["mal"] += int(r["total_mal"])
        totals["caught"] += int(r["caught"])
        totals["hon"] += int(r["total_hon"])
        totals["fp"] += int(r["fp"])
        print(f"{r['seed']:<6} {r['total_mal']:<5} {r['caught']:<8} "
              f"{r['dr']:<7.1f}% {r['total_hon']:<5} {r['fp']:<5} {r['fpr']:.1f}%")

    if rows:
        overall_dr = 100.0 * totals["caught"] / totals["mal"] if totals["mal"] else 0.0
        overall_fpr = 100.0 * totals["fp"] / totals["hon"] if totals["hon"] else 0.0
        print("-" * 54)
        print(f"{'TOTAL':<6} {totals['mal']:<5} {totals['caught']:<8} "
              f"{overall_dr:<7.1f}% {totals['hon']:<5} {totals['fp']:<5} {overall_fpr:.1f}%")
        print("\nPaper-ready label: VeReMi-style consistency baseline")
        print(f"Overall: DR={overall_dr:.1f}%, FPR={overall_fpr:.1f}%")


if __name__ == "__main__":
    main()
