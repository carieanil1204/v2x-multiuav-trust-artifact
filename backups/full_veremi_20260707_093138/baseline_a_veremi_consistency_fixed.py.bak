#!/usr/bin/env python3
"""
Baseline A (corrected v2): VeReMi-style consistency/plausibility detector.

Implements the FOUR checks specified in PAPER2_STATUS Section 13 —
"What genuine VeReMi-style detection requires":

  C1 Position-consistency (prediction):
       PX_pred = PX[t-1] + SPD[t-1] * dt        (dt from SIMNOW if available)
       flag if |PX_actual - PX_pred| > pos_tolerance
  C2 Timestamp replay:
       (a) if SIMNOW present: flag if |SIMNOW - TS| > max_ts_lag
       (b) always: flag if claimed TS is non-monotonic in ARRIVAL order
           (replayed/reordered beacons)
  C3 Speed consistency:
       flag if | |dPX/dt| - reported SPD | > speed_tolerance
       (skipped when dt > max_gap, to avoid packet-loss false positives)
  C4 Raw speed plausibility (kept from naive baseline as sanity check):
       flag if |SPD| > max_speed

Design decisions that differ from the flawed versions:
  * Packets are processed in ARRIVAL (file) order, never sorted by claimed
    TS — sorting by an attacker-controlled field hides replay attacks.
  * dt is derived from SIMNOW (receiver time) when available; claimed TS is
    used only as a fallback and only when monotonic.
  * SIMNOW is parsed ONLY from an explicit "SIMNOW:<float>" token. No
    loose regex guessing (which produced spurious violations).
  * Verdict = BAN after min_violations CONSECUTIVE violating beacons.

Ground truth from PAYOFF lines:
  [PAYOFF] CID:<id> ... demoted=YES/NO ... malicious=YES/NO

Example:
  python3 baseline_a_veremi_consistency_fixed.py \
    --results_dir ~/research/projects/v2x-multiuav-trust/results/clean_multiseed_v91_20260705_220415 \
    --seeds 1 2 3 4 5 \
    --pos_tolerance 15.0 --speed_tolerance 8.0 \
    --max_ts_lag 2.0 --min_violations 2 --debug
"""

from __future__ import annotations

import argparse
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

HEALTH_CHECK_CID = 8801


@dataclass
class Packet:
    cid: int
    ts: float          # claimed timestamp (attacker-controlled)
    spd: float         # claimed speed
    px: float          # claimed x position
    simnow: Optional[float]  # receiver/sim time, trusted, if logged


@dataclass
class VerdictDetail:
    predicted_ban: bool
    first_reason: str
    first_ts: Optional[float]
    violation_count: int
    packet_count: int
    reason_counts: Dict[str, int]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Corrected VeReMi-style consistency baseline (Section 13 spec)")
    p.add_argument("--results_dir", required=True)
    p.add_argument("--seeds", nargs="+", type=int, default=[1, 2, 3, 4, 5])
    p.add_argument("--pos_tolerance", type=float, default=15.0,
                   help="C1: allowed |PX_actual - PX_pred| in meters")
    p.add_argument("--speed_tolerance", type=float, default=8.0,
                   help="C3: allowed | |dPX/dt| - SPD | in m/s")
    p.add_argument("--max_speed", type=float, default=35.0,
                   help="C4: max plausible reported speed in m/s")
    p.add_argument("--max_ts_lag", type=float, default=2.0,
                   help="C2a: max |SIMNOW - TS| in seconds (needs SIMNOW in log)")
    p.add_argument("--ts_monotonic_slack", type=float, default=0.0,
                   help="C2b: allowed backward TS step before flagging replay")
    p.add_argument("--max_gap", type=float, default=3.0,
                   help="Skip C1/C3 across gaps larger than this (packet loss)")
    p.add_argument("--min_violations", type=int, default=2,
                   help="Consecutive violating beacons required before BAN")
    p.add_argument("--tune_seed", type=int, default=None,
                   help="Report this seed separately for tuning; exclude from totals")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def parse_ns3_log(log_path: str) -> Tuple[Dict[int, List[Packet]], Dict[int, Dict[str, bool]]]:
    """Parse in file order — arrival order is part of the signal."""
    packets: Dict[int, List[Packet]] = defaultdict(list)
    payoff: Dict[int, Dict[str, bool]] = {}

    cid_pat = re.compile(r"CID:(\d+)")
    ts_pat = re.compile(r"TS:([-\d.]+)")
    spd_pat = re.compile(r"SPD:([-\d.]+)")
    px_pat = re.compile(r"PX:([-\d.]+)")
    simnow_pat = re.compile(r"SIMNOW:([-\d.]+)")   # explicit token ONLY
    pay_pat = re.compile(
        r"\[PAYOFF\]\s+CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)")

    with open(log_path, "r", errors="ignore") as f:
        for line in f:
            if "UAV->CLOUD" in line:
                cid_m = cid_pat.search(line)
                ts_m = ts_pat.search(line)
                spd_m = spd_pat.search(line)
                px_m = px_pat.search(line)
                if cid_m and ts_m and spd_m and px_m:
                    cid = int(cid_m.group(1))
                    if cid == HEALTH_CHECK_CID:
                        continue
                    sn_m = simnow_pat.search(line)
                    try:
                        packets[cid].append(Packet(
                            cid=cid,
                            ts=float(ts_m.group(1)),
                            spd=float(spd_m.group(1)),
                            px=float(px_m.group(1)),
                            simnow=float(sn_m.group(1)) if sn_m else None,
                        ))
                    except ValueError:
                        continue
            pay_m = pay_pat.search(line)
            if pay_m:
                payoff[int(pay_m.group(1))] = {
                    "malicious": pay_m.group(3) == "YES",
                    "demoted": pay_m.group(2) == "YES",
                }
    return packets, payoff


def consistency_detector(stream: List[Packet], a: argparse.Namespace) -> VerdictDetail:
    streak = 0
    total_viol = 0
    first_reason = ""
    first_ts: Optional[float] = None
    reason_counts: Dict[str, int] = defaultdict(int)
    prev: Optional[Packet] = None
    banned = False

    for pkt in stream:  # ARRIVAL order — do NOT sort by claimed TS
        reasons: List[str] = []

        # C4: raw speed plausibility
        if abs(pkt.spd) > a.max_speed:
            reasons.append(f"raw_speed({pkt.spd:.1f}>{a.max_speed:.1f})")

        # C2a: timestamp lag vs trusted receiver time
        if pkt.simnow is not None and abs(pkt.simnow - pkt.ts) > a.max_ts_lag:
            reasons.append(f"ts_lag({pkt.simnow - pkt.ts:+.2f})")

        if prev is not None:
            # C2b: replay / non-monotonic claimed TS in arrival order
            if pkt.ts < prev.ts - a.ts_monotonic_slack:
                reasons.append(f"ts_replay({pkt.ts:.2f}<{prev.ts:.2f})")

            # trusted dt if both packets carry SIMNOW, else claimed dt
            if pkt.simnow is not None and prev.simnow is not None:
                dt = pkt.simnow - prev.simnow
            else:
                dt = pkt.ts - prev.ts

            if 1e-6 < dt <= a.max_gap:
                # C1: position-consistency vs prediction from PREVIOUS state
                px_pred = prev.px + prev.spd * dt
                err = abs(pkt.px - px_pred)
                # motion may be toward -x; accept either sign of prev.spd
                px_pred_neg = prev.px - prev.spd * dt
                err = min(err, abs(pkt.px - px_pred_neg))
                if err > a.pos_tolerance:
                    reasons.append(f"pos_pred_err({err:.1f}>{a.pos_tolerance:.1f})")

                # C3: reported speed vs position-derived speed
                observed = abs(pkt.px - prev.px) / dt
                mism = abs(observed - abs(pkt.spd))
                if mism > a.speed_tolerance:
                    reasons.append(f"spd_mismatch({observed:.1f}vs{abs(pkt.spd):.1f})")

        if reasons:
            streak += 1
            total_viol += 1
            if not first_reason:
                first_reason = ";".join(reasons)
                first_ts = pkt.ts
            for r in reasons:
                reason_counts[r.split("(")[0]] += 1
            if streak >= a.min_violations:
                banned = True   # keep scanning stats? no — early exit is fine
                break
        else:
            streak = 0

        prev = pkt

    return VerdictDetail(banned, first_reason or "none", first_ts,
                         total_viol, len(stream), dict(reason_counts))


def evaluate_seed(a: argparse.Namespace, seed: int):
    log_path = os.path.join(a.results_dir, f"ns3_seed_{seed}.log")
    if not os.path.exists(log_path):
        print(f"  [WARN] missing {log_path}")
        return None
    packets, payoff = parse_ns3_log(log_path)
    if not payoff:
        print(f"  [WARN] no PAYOFF lines in seed {seed}")
        return None

    simnow_available = any(p.simnow is not None
                           for pkts in packets.values() for p in pkts[:5])

    total_mal = caught = total_hon = fp = 0
    details = {}
    for cid, truth in sorted(payoff.items()):
        d = consistency_detector(packets.get(cid, []), a)
        details[cid] = d
        if truth["malicious"]:
            total_mal += 1
            caught += int(d.predicted_ban)
        else:
            total_hon += 1
            fp += int(d.predicted_ban)

    if a.debug:
        print(f"\n[DEBUG seed {seed}] SIMNOW available: {simnow_available}"
              + ("" if simnow_available else "  (C2a lag check inactive; dt falls back to claimed TS)"))
        for cid, d in details.items():
            tag = "MAL" if payoff[cid]["malicious"] else "HON"
            mark = "BAN" if d.predicted_ban else "   "
            if d.predicted_ban or (tag == "MAL"):
                print(f"  CID:{cid:<4} {tag} {mark} pkts={d.packet_count:<4} "
                      f"viol={d.violation_count:<3} first@{d.first_ts} {d.first_reason}")

    return {"seed": seed, "total_mal": total_mal, "caught": caught,
            "total_hon": total_hon, "fp": fp,
            "dr": 100.0 * caught / total_mal if total_mal else 0.0,
            "fpr": 100.0 * fp / total_hon if total_hon else 0.0}


def main() -> None:
    a = parse_args()
    print("\n" + "=" * 78)
    print("  Baseline A corrected v2: VeReMi-style consistency detector (Sec-13 spec)")
    for k in ("results_dir", "seeds", "pos_tolerance", "speed_tolerance",
              "max_speed", "max_ts_lag", "max_gap", "min_violations", "tune_seed"):
        print(f"  {k:<16}: {getattr(a, k)}")
    print("=" * 78 + "\n")

    if a.tune_seed is not None:
        print(f"[TUNING] seed {a.tune_seed} (excluded from totals)")
        r = evaluate_seed(a, a.tune_seed)
        if r:
            print(f"  Seed {r['seed']}: DR={r['dr']:.1f}%  FPR={r['fpr']:.1f}%\n")

    eval_seeds = [s for s in a.seeds if s != a.tune_seed]
    totals = {"mal": 0, "caught": 0, "hon": 0, "fp": 0}
    rows = []
    print(f"{'Seed':<6} {'Mal':<5} {'Caught':<8} {'DR%':<8} {'Hon':<5} {'FP':<5} {'FPR%'}")
    print("-" * 54)
    for seed in eval_seeds:
        r = evaluate_seed(a, seed)
        if r is None:
            continue
        rows.append(r)
        totals["mal"] += r["total_mal"]; totals["caught"] += r["caught"]
        totals["hon"] += r["total_hon"]; totals["fp"] += r["fp"]
        print(f"{r['seed']:<6} {r['total_mal']:<5} {r['caught']:<8} "
              f"{r['dr']:<7.1f}% {r['total_hon']:<5} {r['fp']:<5} {r['fpr']:.1f}%")

    if rows:
        odr = 100.0 * totals["caught"] / totals["mal"] if totals["mal"] else 0.0
        ofpr = 100.0 * totals["fp"] / totals["hon"] if totals["hon"] else 0.0
        print("-" * 54)
        print(f"{'TOTAL':<6} {totals['mal']:<5} {totals['caught']:<8} "
              f"{odr:<7.1f}% {totals['hon']:<5} {totals['fp']:<5} {ofpr:.1f}%")
        print("\nPaper-ready label: VeReMi-style consistency baseline")
        print(f"Overall: DR={odr:.1f}%, FPR={ofpr:.1f}%   "
              f"(Paper 2 system: DR=96.9%, FPR=0.0%)")


if __name__ == "__main__":
    main()
