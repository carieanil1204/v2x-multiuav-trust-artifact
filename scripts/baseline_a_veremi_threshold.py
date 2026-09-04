#!/usr/bin/env python3
"""
Baseline A: VeReMi-style Threshold Detector for Paper 2 comparison.

Implements:
  1. Simple Speed Check (SSC)  — flag if |speed| > MAX_SPEED
  2. Acceptance Range Threshold (ART) — flag if position jump/second > MAX_SPEED

Runs offline against existing edge + NS3 logs.
No new NS3 runs needed.

Usage:
  python3 baseline_a_veremi_threshold.py \
    --results_dir ~/research/projects/v2x-multiuav-trust/results/clean_multiseed_v91_20260705_220415 \
    --seeds 1 2 3 4 5 \
    --max_speed 35.0 \
    --max_jump 40.0 \
    --min_violations 2

Author: Paper 2 baseline experiment
Date: 2026-07-06
"""

import argparse
import os
import re
from collections import defaultdict

# ── Argument parsing ────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="VeReMi-style threshold baseline scorer")
    p.add_argument("--results_dir", required=True,
                   help="Path to results directory containing ns3_seed_N.log files")
    p.add_argument("--seeds", nargs="+", type=int, default=[1,2,3,4,5],
                   help="Seed numbers to evaluate")
    p.add_argument("--max_speed", type=float, default=35.0,
                   help="Max plausible speed (m/s). Cars exceeding this are flagged.")
    p.add_argument("--max_jump", type=float, default=40.0,
                   help="Max plausible position change/sec (m/s). Jumps exceeding this are flagged.")
    p.add_argument("--min_violations", type=int, default=2,
                   help="Min consecutive violations before issuing a BAN verdict.")
    p.add_argument("--tune_seed", type=int, default=None,
                   help="If set, report only this seed's results as tuning output (don't count toward metrics).")
    return p.parse_args()

# ── Log parsing ─────────────────────────────────────────────────────────────

def parse_ns3_log(log_path):
    """
    Parse NS3 log to extract per-packet telemetry and ground-truth payoff.
    Returns:
      packets: {cid: [(sim_ts, spd, px), ...]}
      payoff:  {cid: {'malicious': bool, 'demoted': bool}}
    """
    packets = defaultdict(list)
    payoff  = {}

    ts_pat  = re.compile(r'TS:([\d.]+)')
    spd_pat = re.compile(r'SPD:([\d.]+)')
    px_pat  = re.compile(r'PX:([-\d.]+)')
    cid_pat = re.compile(r'CID:(\d+)')

    pay_pat = re.compile(
        r'\[PAYOFF\] CID:(\d+).*?demoted=(YES|NO).*?malicious=(YES|NO)')

    with open(log_path, 'r', errors='ignore') as f:
        for line in f:
            # Telemetry lines
            if 'UAV->CLOUD' in line:
                # Handle pipe-delimited format:
                # >>> [UAV->CLOUD] BLK:...|TX:...|CID:N|TS:N|SPD:N|HDG:N|PX:N|...
                # Patterns already handle both space and pipe-delimited
                cid_m = re.search(r'CID:(\d+)', line)
                ts_m  = re.search(r'TS:([\d.]+)', line)
                spd_m = re.search(r'SPD:([\d.]+)', line)
                px_m  = re.search(r'PX:([-\d.]+)', line)
                if cid_m and ts_m and spd_m and px_m:
                    cid = int(cid_m.group(1))
                    if cid == 8801:  # health-check CID, skip
                        continue
                    ts  = float(ts_m.group(1))
                    spd = float(spd_m.group(1))
                    px  = float(px_m.group(1))
                    packets[cid].append((ts, spd, px))
            # Payoff lines
            pay_m = pay_pat.search(line)
            if pay_m:
                cid = int(pay_m.group(1))
                payoff[cid] = {
                    'malicious': pay_m.group(3) == 'YES',
                    'demoted':   pay_m.group(2) == 'YES',
                }

    return packets, payoff

# ── VeReMi detector ─────────────────────────────────────────────────────────

def veremi_detector(packets_for_cid, max_speed, max_jump, min_violations):
    """
    Apply Simple Speed Check + Acceptance Range Threshold to packet stream.
    Returns True (BAN) if min_violations consecutive violations are detected.
    """
    streak = 0
    prev_ts = None
    prev_px = None

    for (ts, spd, px) in sorted(packets_for_cid, key=lambda x: x[0]):
        violation = False

        # Simple Speed Check
        if abs(spd) > max_speed:
            violation = True

        # Acceptance Range Threshold (position jump rate)
        if prev_ts is not None and prev_px is not None:
            dt = ts - prev_ts
            if dt > 0:
                jump_rate = abs(px - prev_px) / dt
                if jump_rate > max_jump:
                    violation = True

        if violation:
            streak += 1
            if streak >= min_violations:
                return True   # BAN
        else:
            streak = 0        # reset on clean packet

        prev_ts = ts
        prev_px = px

    return False  # TRUST

# ── Evaluation ───────────────────────────────────────────────────────────────

def evaluate_seed(results_dir, seed, max_speed, max_jump, min_violations):
    log_path = os.path.join(results_dir, f"ns3_seed_{seed}.log")
    if not os.path.exists(log_path):
        print(f"  [WARN] {log_path} not found, skipping")
        return None

    packets, payoff = parse_ns3_log(log_path)

    if not payoff:
        print(f"  [WARN] No PAYOFF lines found in seed {seed}")
        return None

    total_mal = caught = total_hon = fp = 0

    for cid, truth in payoff.items():
        pkt_stream = packets.get(cid, [])
        predicted_ban = veremi_detector(pkt_stream, max_speed, max_jump, min_violations)

        if truth['malicious']:
            total_mal += 1
            if predicted_ban:
                caught += 1
        else:
            total_hon += 1
            if predicted_ban:
                fp += 1

    dr  = caught / total_mal * 100 if total_mal else 0
    fpr = fp     / total_hon * 100 if total_hon else 0

    return {
        'seed': seed,
        'total_mal': total_mal,
        'caught': caught,
        'total_hon': total_hon,
        'fp': fp,
        'dr': dr,
        'fpr': fpr,
    }

# ── Main ────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    print()
    print("=" * 65)
    print("  Baseline A: VeReMi-style Threshold Detector")
    print(f"  Results dir : {args.results_dir}")
    print(f"  Seeds       : {args.seeds}")
    print(f"  max_speed   : {args.max_speed} m/s")
    print(f"  max_jump    : {args.max_jump} m/s")
    print(f"  min_viol    : {args.min_violations} consecutive")
    if args.tune_seed:
        print(f"  TUNING MODE : seed {args.tune_seed} used for tuning only")
    print("=" * 65)
    print()

    results = []
    eval_seeds = [s for s in args.seeds if s != args.tune_seed]

    # Tuning seed report
    if args.tune_seed:
        print(f"[TUNING] Evaluating seed {args.tune_seed} to set thresholds...")
        r = evaluate_seed(args.results_dir, args.tune_seed,
                          args.max_speed, args.max_jump, args.min_violations)
        if r:
            print(f"  Seed {r['seed']}: DR={r['caught']}/{r['total_mal']}={r['dr']:.1f}%  "
                  f"FPR={r['fp']}/{r['total_hon']}={r['fpr']:.1f}%")
        print(f"[TUNING] Thresholds locked: max_speed={args.max_speed}, "
              f"max_jump={args.max_jump}, min_violations={args.min_violations}")
        print()

    # Evaluation seeds
    print(f"{'Seed':<6} {'Mal':<5} {'Caught':<8} {'DR%':<8} "
          f"{'Hon':<5} {'FP':<5} {'FPR%'}")
    print("-" * 50)

    total_mal = total_caught = total_hon = total_fp = 0

    for seed in eval_seeds:
        r = evaluate_seed(args.results_dir, seed,
                          args.max_speed, args.max_jump, args.min_violations)
        if r is None:
            continue
        results.append(r)
        total_mal     += r['total_mal']
        total_caught  += r['caught']
        total_hon     += r['total_hon']
        total_fp      += r['fp']
        print(f"{r['seed']:<6} {r['total_mal']:<5} {r['caught']:<8} "
              f"{r['dr']:<7.1f}% {r['total_hon']:<5} {r['fp']:<5} {r['fpr']:.1f}%")

    if results:
        print("-" * 50)
        overall_dr  = total_caught / total_mal  * 100 if total_mal  else 0
        overall_fpr = total_fp     / total_hon  * 100 if total_hon  else 0
        print(f"{'TOTAL':<6} {total_mal:<5} {total_caught:<8} "
              f"{overall_dr:<7.1f}% {total_hon:<5} {total_fp:<5} {overall_fpr:.1f}%")

        print()
        print("=" * 65)
        print("  COMPARISON vs Paper 2 main result (N=30, 5 seeds)")
        print("=" * 65)
        print(f"  Baseline A (VeReMi threshold) : "
              f"DR={overall_dr:.1f}%  FPR={overall_fpr:.1f}%")
        print(f"  Paper 2   (Bayesian+CUSUM+HTD): "
              f"DR=96.9%         FPR=0.0%")
        print(f"  Improvement in DR : +{96.9 - overall_dr:.1f} points")
        print(f"  Improvement in FPR: {overall_fpr - 0.0:.1f} points "
              f"({'better' if overall_fpr > 0 else 'same'})")
        print()

if __name__ == "__main__":
    main()
