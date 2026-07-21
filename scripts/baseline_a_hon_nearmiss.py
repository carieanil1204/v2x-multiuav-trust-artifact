#!/usr/bin/env python3
import os, importlib.util
from collections import Counter

BASE = os.path.expanduser("~/research/projects/v2x-multiuav-trust")
SCRIPT = os.path.join(BASE, "scripts", "baseline_a_veremi_consistency_fixed.py")
RESULTS = os.path.join(BASE, "results", "clean_multiseed_v91_20260705_220415")

spec = importlib.util.spec_from_file_location("base", SCRIPT)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

SEEDS = [1,2,3,4,5]
MAX_GAP = 3.0

def bucket(n):
    if n <= 2: return "<=2"
    if n <= 10: return "3-10"
    if n <= 50: return "11-50"
    return ">50"

def metrics(stream):
    max_pos = 0.0
    max_mism = 0.0
    eligible = 0
    prev = None

    for pkt in stream:
        if prev is not None:
            dt = pkt.ts - prev.ts
            if 1e-6 < dt <= MAX_GAP:
                eligible += 1
                pred_pos = prev.px + prev.spd * dt
                pred_neg = prev.px - prev.spd * dt
                pos_err = min(abs(pkt.px - pred_pos), abs(pkt.px - pred_neg))
                observed = abs(pkt.px - prev.px) / dt
                spd_mism = abs(observed - abs(pkt.spd))
                max_pos = max(max_pos, pos_err)
                max_mism = max(max_mism, spd_mism)
        prev = pkt

    return max_pos, max_mism, eligible

pkt_dist = {"MAL": Counter(), "HON": Counter()}
rows = []

for seed in SEEDS:
    log_path = os.path.join(RESULTS, f"ns3_seed_{seed}.log")
    packets, payoff = base.parse_ns3_log(log_path)

    for cid, truth in sorted(payoff.items()):
        tag = "MAL" if truth["malicious"] else "HON"
        stream = packets.get(cid, [])
        max_pos, max_mism, eligible = metrics(stream)
        pkt_dist[tag][bucket(len(stream))] += 1
        rows.append((seed, cid, tag, len(stream), eligible, max_pos, max_mism))

print("\nPACKET COUNT DISTRIBUTION")
print("MAL:", dict(pkt_dist["MAL"]))
print("HON:", dict(pkt_dist["HON"]))

print("\nHONEST VEHICLES SORTED BY MAX SPEED-MISMATCH")
print("seed cid pkts eligible max_pos_err max_spd_mismatch")
hon = [r for r in rows if r[2] == "HON"]
for seed, cid, tag, pkts, eligible, max_pos, max_mism in sorted(hon, key=lambda x: x[6], reverse=True):
    print(f"{seed:4d} {cid:3d} {pkts:4d} {eligible:4d} {max_pos:10.2f} {max_mism:10.2f}")

print("\nMALICIOUS VEHICLES SORTED BY MAX SPEED-MISMATCH, TOP 30")
print("seed cid pkts eligible max_pos_err max_spd_mismatch")
mal = [r for r in rows if r[2] == "MAL"]
for seed, cid, tag, pkts, eligible, max_pos, max_mism in sorted(mal, key=lambda x: x[6], reverse=True)[:30]:
    print(f"{seed:4d} {cid:3d} {pkts:4d} {eligible:4d} {max_pos:10.2f} {max_mism:10.2f}")
