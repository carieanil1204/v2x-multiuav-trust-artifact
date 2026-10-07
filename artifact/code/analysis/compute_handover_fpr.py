#!/usr/bin/env python3
"""Compute honest-car FPR for the crossing-relative handover sweep, for the
new Table~\\ref{tab:handover} runway curve (tau = 1.0..1.5s, ON/OFF).

Ground truth for "is this car malicious" is the [ATTACK-CROSSING-RELATIVE]
setup line (fires only for cars in the real malSet), NOT the [PAYOFF]
malicious= field, which is known to mislabel CID:0/2 (see CLAUDE.md).
Honest = nCars(10) minus that real malSet. FPR = honest cars with
demoted=YES / total honest cars.
"""
import re, sys, os

NCARS = 10

RE_MAL = re.compile(r"\[ATTACK-CROSSING-RELATIVE\] CID:(\d+)")
RE_PAYOFF = re.compile(r"\[PAYOFF\] CID:(\d+).*demoted=(YES|NO)")

def compute(outdir, mode):
    honest_total = 0
    honest_demoted = 0
    for seed in range(1, 16):
        path = os.path.join(outdir, f"{mode}_seed{seed}_crossrel.log")
        if not os.path.exists(path):
            print(f"MISSING: {path}", file=sys.stderr)
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        malicious_cids = set(int(m.group(1)) for m in RE_MAL.finditer(text))
        honest_cids = set(range(NCARS)) - malicious_cids
        demoted = {}
        for m in RE_PAYOFF.finditer(text):
            cid = int(m.group(1))
            demoted[cid] = (m.group(2) == "YES")
        for cid in honest_cids:
            honest_total += 1
            if demoted.get(cid, False):
                honest_demoted += 1
    fpr = 100.0 * honest_demoted / honest_total if honest_total else float("nan")
    return honest_demoted, honest_total, fpr

if __name__ == "__main__":
    outdir = sys.argv[1]
    for mode in ("ON", "OFF"):
        d, t, fpr = compute(outdir, mode)
        print(f"{mode}: honest_demoted={d}/{t} FPR={fpr:.2f}%")
