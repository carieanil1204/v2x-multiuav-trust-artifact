#!/usr/bin/env python3
import re
import sys
import importlib.util
from pathlib import Path
from argparse import Namespace
from collections import Counter

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
    rx_speed_tolerance=8.0,
    max_gap=3.0,
    min_violations=1,
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

def reason_name(r):
    return r.split("(", 1)[0]

def cid_from_line(line):
    m = re.search(r"CID:(\d+)", line)
    return int(m.group(1)) if m else None

packets, payoff = fullv.parse_log(LOG)

passive_counts = Counter()
cloud_counts = Counter()
sample_cloud = []

with open(LOG, "r", errors="ignore") as f:
    for line in f:
        if "[PASSIVE-BEACON]" in line:
            cid = cid_from_line(line)
            if cid is not None:
                passive_counts[cid] += 1
        if ">>> [UAV->CLOUD]" in line:
            cid = cid_from_line(line)
            if cid is not None:
                cloud_counts[cid] += 1
            elif len(sample_cloud) < 3:
                sample_cloud.append(line.strip())

print("\n" + "="*100)
print("A) PASSIVE vs UAV->CLOUD PACKET COUNTS")
print("="*100)
print(f"{'CID':>4s} {'Truth':>5s} {'Passive':>8s} {'UAVCloud':>8s} {'ExtraPassive':>12s}")
for cid in sorted(set(passive_counts) | set(cloud_counts) | set(payoff)):
    truth = "MAL" if payoff.get(cid, {}).get("malicious", False) else "HON"
    p = passive_counts[cid]
    c = cloud_counts[cid]
    print(f"{cid:4d} {truth:>5s} {p:8d} {c:8d} {p-c:12d}")

if sum(cloud_counts.values()) == 0:
    print("\nWARNING: Could not parse CID from >>> [UAV->CLOUD] lines.")
    print("Sample UAV->CLOUD lines:")
    for s in sample_cloud:
        print(" ", s)

print("\n" + "="*100)
print("B) PER-CID, PER-CHECK FIRST FIRING")
print("="*100)

for cid in sorted(set(packets) | set(payoff)):
    truth = "MAL" if payoff.get(cid, {}).get("malicious", False) else "HON"
    demoted = "YES" if payoff.get(cid, {}).get("demoted", False) else "NO"
    stream = packets.get(cid, [])

    first = {}
    counts = Counter()

    prev = None
    for pkt in stream:
        reasons = fullv.packet_reasons(prev, pkt, args)
        for r in reasons:
            rn = reason_name(r)
            counts[rn] += 1
            if rn not in first:
                first[rn] = (pkt.simnow, pkt.ts, r)
        prev = pkt

    core_reasons = [k for k in counts if k in CORE]
    pos_first = first.get("pos_pred_claimed")
    spd_first = first.get("speed_pos_claimed")
    same_pkt = "NA"
    if pos_first and spd_first:
        same_pkt = "YES" if abs(pos_first[0] - spd_first[0]) < 1e-6 else "NO"

    print("\n" + "-"*100)
    print(f"CID:{cid} truth={truth} demoted={demoted} passive_pkts={len(stream)} core_checks={core_reasons} pos_speed_same_first_pkt={same_pkt}")

    if not counts:
        print("  no violations under current thresholds")
        continue

    for rn, cnt in counts.most_common():
        t = first[rn]
        print(f"  {rn:22s} count={cnt:4d} first_SIMNOW={t[0]:8.3f} first_TS={t[1]:8.3f} reason={t[2]}")

print("\n" + "="*100)
print("C) FIRST-FIRING TIME CLUSTER")
print("="*100)

cluster = []
for cid in sorted(packets):
    truth = "MAL" if payoff.get(cid, {}).get("malicious", False) else "HON"
    stream = packets[cid]
    prev = None
    for pkt in stream:
        reasons = fullv.packet_reasons(prev, pkt, args)
        core = [r for r in reasons if reason_name(r) in CORE]
        if core:
            cluster.append((pkt.simnow, cid, truth, ";".join(core)))
            break
        prev = pkt

for simnow, cid, truth, rs in sorted(cluster):
    print(f"SIMNOW={simnow:8.3f} CID={cid:3d} truth={truth} reasons={rs}")
