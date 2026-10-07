#!/usr/bin/env python3
"""
[OPTION-C] Parse results/crossing_relative_15seed/{MODE}_seed{N}_crossrel.log
into per-car, per-seed, per-mode records, then report:
  - mid-detection-fraction: at the moment THIS car crossed, was there
    non-trivial pending evidence (banStreak_at_crossing >= 1) that had not
    yet been confirmed as a BAN?
  - received_reset_at_crossing: did this car get the OFF-mode-only
    ACT:RESET control message at its crossing? (tracked explicitly per car,
    not folded into the aggregate, per instruction.)
  - final_demoted: from the [PAYOFF] line (ground truth for DR).
Ground truth for "is this car malicious" is the [ATTACK-CROSSING-RELATIVE]
setup line (fires only for cars in the real malSet), NOT the [PAYOFF]
malicious= field, which is known to mislabel some honest cars (see
CLAUDE.md note on CID:0/2).
"""
import re, sys, glob, os
from collections import defaultdict

OUTDIR = sys.argv[1] if len(sys.argv) > 1 else "results/crossing_relative_15seed"

RE_MAL      = re.compile(r"\[ATTACK-CROSSING-RELATIVE\] CID:(\d+)")
RE_HTD      = re.compile(r"\[HTD\] CID:(\d+).*banStreak_at_crossing=(\d+)")
RE_COLDSTART= re.compile(r"\[NO-HANDOVER-COLDSTART\] CID:(\d+).*banStreak_at_crossing=(\d+)")
RE_PAYOFF   = re.compile(r"\[PAYOFF\] CID:(\d+).*demoted=(YES|NO)")

records = []  # list of dicts: mode, seed, cid, malicious, mid_detection, received_reset, demoted

for mode in ("ON", "OFF"):
    for seed in range(1, 16):
        path = os.path.join(OUTDIR, f"{mode}_seed{seed}_crossrel.log")
        if not os.path.exists(path):
            print(f"MISSING: {path}", file=sys.stderr)
            continue
        text = open(path, encoding="utf-8", errors="replace").read()

        malicious_cids = set(int(m.group(1)) for m in RE_MAL.finditer(text))

        mid_detect = {}   # cid -> bool
        received_reset = {}  # cid -> bool
        for m in RE_HTD.finditer(text):
            cid, bs = int(m.group(1)), int(m.group(2))
            mid_detect[cid] = (bs >= 1)
            received_reset[cid] = False  # HTD branch = ON = never sends RESET
        for m in RE_COLDSTART.finditer(text):
            cid, bs = int(m.group(1)), int(m.group(2))
            mid_detect[cid] = (bs >= 1)
            received_reset[cid] = True   # COLDSTART branch = OFF = always sends RESET

        demoted = {}
        for m in RE_PAYOFF.finditer(text):
            cid = int(m.group(1))
            demoted[cid] = (m.group(2) == "YES")

        for cid in sorted(malicious_cids):
            records.append({
                "mode": mode, "seed": seed, "cid": cid,
                "crossed": cid in mid_detect,
                "mid_detection": mid_detect.get(cid, False),
                "received_reset": received_reset.get(cid, False),
                "demoted": demoted.get(cid, False),
            })

# ---- per-seed table ----
print(f"{'mode':4} {'seed':4} {'n_mal':6} {'DR%':6} {'mid_det_frac':13} {'reset_frac':11}")
per_seed = defaultdict(list)
for r in records:
    per_seed[(r["mode"], r["seed"])].append(r)

for mode in ("ON", "OFF"):
    for seed in range(1, 16):
        rows = per_seed.get((mode, seed), [])
        if not rows:
            continue
        n = len(rows)
        dr = 100.0 * sum(r["demoted"] for r in rows) / n
        midf = 100.0 * sum(r["mid_detection"] for r in rows) / n
        rstf = 100.0 * sum(r["received_reset"] for r in rows) / n
        print(f"{mode:4} {seed:<4} {n:<6} {dr:<6.1f} {midf:<13.1f} {rstf:<11.1f}")

# ---- pooled ----
print()
print(f"{'mode':4} {'n_mal':6} {'DR%':6} {'mid_det_frac':13} {'reset_frac':11}")
for mode in ("ON", "OFF"):
    rows = [r for r in records if r["mode"] == mode]
    n = len(rows)
    if n == 0:
        print(f"{mode:4} NO DATA")
        continue
    dr = 100.0 * sum(r["demoted"] for r in rows) / n
    midf = 100.0 * sum(r["mid_detection"] for r in rows) / n
    rstf = 100.0 * sum(r["received_reset"] for r in rows) / n
    print(f"{mode:4} {n:<6} {dr:<6.1f} {midf:<13.1f} {rstf:<11.1f}")

# ---- paired per-seed DR gap (ON - OFF) ----
print()
print("Per-seed DR gap (ON% - OFF%):")
gaps = []
for seed in range(1, 16):
    on_rows = per_seed.get(("ON", seed), [])
    off_rows = per_seed.get(("OFF", seed), [])
    if not on_rows or not off_rows:
        continue
    dr_on = 100.0 * sum(r["demoted"] for r in on_rows) / len(on_rows)
    dr_off = 100.0 * sum(r["demoted"] for r in off_rows) / len(off_rows)
    gap = dr_on - dr_off
    gaps.append(gap)
    print(f"  seed {seed:<3} ON={dr_on:.1f}%  OFF={dr_off:.1f}%  gap={gap:+.1f}")

if gaps:
    mean_gap = sum(gaps) / len(gaps)
    n_positive = sum(1 for g in gaps if g > 0)
    n_negative = sum(1 for g in gaps if g < 0)
    n_zero = sum(1 for g in gaps if g == 0)
    print()
    print(f"mean gap = {mean_gap:+.2f} pts over {len(gaps)} seeds")
    print(f"gap sign: {n_positive} seeds ON>OFF, {n_negative} seeds OFF>ON, {n_zero} seeds tied")

# ---- RESET-correlation check: among OFF cars that received a reset, ----
# ---- does demoted rate differ from OFF cars that were already-banned  ----
# ---- (never got the crossing line, so no reset recorded at all)?     ----
print()
off_rows = [r for r in records if r["mode"] == "OFF"]
off_crossed = [r for r in off_rows if r["crossed"]]
off_not_crossed = [r for r in off_rows if not r["crossed"]]
def rate(rows):
    return 100.0 * sum(r["demoted"] for r in rows) / len(rows) if rows else float("nan")
print(f"OFF: cars that reached crossing & got RESET: n={len(off_crossed)}, demoted%={rate(off_crossed):.1f}")
print(f"OFF: cars that never reached crossing in log (already banned pre-crossing or no crossing recorded): n={len(off_not_crossed)}, demoted%={rate(off_not_crossed):.1f}")
