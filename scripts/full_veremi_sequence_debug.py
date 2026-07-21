#!/usr/bin/env python3
import sys
import importlib.util
from pathlib import Path
from argparse import Namespace

BASE = Path.home() / "research/projects/v2x-multiuav-trust"
SCRIPT = BASE / "scripts/baseline_a_full_veremi_style.py"
LOG = Path("/tmp/full_veremi_seed1_test.log")

spec = importlib.util.spec_from_file_location("fullv", SCRIPT)
fullv = importlib.util.module_from_spec(spec)
sys.modules["fullv"] = fullv
spec.loader.exec_module(fullv)

args = Namespace(
    max_speed=35.0,
    max_ts_lag=2.0,
    ts_monotonic_slack=0.05,
    pos_tolerance=15.0,
    speed_tolerance=8.0,
    rx_speed_tolerance=999.0,
    max_gap=3.0,
    min_violations=2,
    comm_range=0.0,
    art_margin=0.0,
)

CORE = {
    "simple_speed",
    "ts_lag",
    "ts_nonmonotonic",
    "pos_pred_claimed",
    "speed_pos_claimed",
}

def rname(r):
    return r.split("(", 1)[0]

packets, payoff = fullv.parse_log(LOG)

# Debug two representative malicious CIDs:
# CID 1 = early repeated-replay behavior
# CID 0 = late t≈77s behavior
for cid in [1, 0]:
    stream = packets.get(cid, [])
    truth = "MAL" if payoff.get(cid, {}).get("malicious", False) else "HON"

    print("\n" + "=" * 120)
    print(f"CID {cid} truth={truth} packets={len(stream)}")
    print("=" * 120)
    print("idx  SIMNOW      TS       PX       SPD    CORE?  reasons")
    print("-" * 120)

    prev = None
    max_ts_seen = None
    streak_any = 0
    last_printed = -99

    rows = []
    for i, pkt in enumerate(stream):
        reasons = fullv.packet_reasons(prev, pkt, args, max_ts_seen)
        core = [r for r in reasons if rname(r) in CORE]

        if core:
            streak_any += 1
        else:
            streak_any = 0

        # Print violation packets plus nearby context
        if core or (i - last_printed <= 2):
            rows.append((i, pkt, core, streak_any))
            last_printed = i

        if max_ts_seen is None or pkt.ts > max_ts_seen:
            max_ts_seen = pkt.ts
        prev = pkt

    for i, pkt, core, streak_any in rows[:160]:
        flag = "YES" if core else "no"
        rs = "; ".join(core)
        print(f"{i:3d}  {pkt.simnow:8.3f}  {pkt.ts:8.3f}  {pkt.px:8.2f}  {pkt.spd:6.2f}  {flag:5s}  streak={streak_any:<2d}  {rs}")

    if len(rows) > 160:
        print(f"... truncated {len(rows)-160} more printed rows ...")
