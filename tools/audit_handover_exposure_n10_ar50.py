import csv
import re
from pathlib import Path
from collections import defaultdict, Counter

BASE_DIR = Path("results/final_locked_csv/baseline_veremi")
INPUT_CSV = BASE_DIR / "baseline_input_n10_ar50_drop0_log_paths.csv"
OUT = BASE_DIR / "handover_exposure_audit_n10_ar50_drop0.csv"

def parse_kv(line):
    out = {}
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_\-]*)\s*:\s*([^,\s\]]+)", line):
        key = m.group(1)
        val = m.group(2)
        try:
            if "." in val or "e" in val.lower():
                out[key] = float(val)
            else:
                out[key] = int(val)
        except ValueError:
            out[key] = val
    return out

def parse_truth(log_path):
    malicious = set()
    honest = set()
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

rows_out = []

for row in csv.DictReader(INPUT_CSV.open()):
    seed = int(row["seed"])
    log_path = Path(row["log_path"])
    malicious, honest = parse_truth(log_path)

    by_cid = defaultdict(list)

    for line in log_path.read_text(errors="ignore").splitlines():
        if "[PASSIVE-BEACON]" not in line:
            continue

        kv = parse_kv(line)
        if not all(k in kv for k in ["SIMNOW", "CID", "ZONE", "RXUAV"]):
            continue

        cid = int(kv["CID"])
        by_cid[cid].append({
            "simnow": float(kv["SIMNOW"]),
            "zone": int(kv["ZONE"]),
            "rxuav": int(kv["RXUAV"]),
        })

    for cid, events in sorted(by_cid.items()):
        events.sort(key=lambda x: x["simnow"])

        zones = [e["zone"] for e in events]
        rxuavs = [e["rxuav"] for e in events]

        zone_changes = sum(1 for a, b in zip(zones, zones[1:]) if a != b)
        rxuav_changes = sum(1 for a, b in zip(rxuavs, rxuavs[1:]) if a != b)

        rows_out.append({
            "seed": seed,
            "cid": cid,
            "malicious": "YES" if cid in malicious else "NO",
            "beacons": len(events),
            "unique_zones": len(set(zones)),
            "unique_rxuavs": len(set(rxuavs)),
            "zone_changes": zone_changes,
            "rxuav_changes": rxuav_changes,
            "first_time": events[0]["simnow"] if events else "",
            "last_time": events[-1]["simnow"] if events else "",
            "source_log_path": str(log_path.resolve()),
        })

with OUT.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
    writer.writeheader()
    writer.writerows(rows_out)

print("Saved:", OUT)

# Compact summary
print()
print("===== HANDOVER EXPOSURE SUMMARY =====")
all_rows = rows_out
for label, subset in [
    ("ALL", all_rows),
    ("MALICIOUS", [r for r in all_rows if r["malicious"] == "YES"]),
    ("HONEST", [r for r in all_rows if r["malicious"] == "NO"]),
]:
    total = len(subset)
    z_move = sum(1 for r in subset if int(r["unique_zones"]) > 1)
    u_move = sum(1 for r in subset if int(r["unique_rxuavs"]) > 1)
    print(f"{label}: vehicles={total}, zone_movers={z_move}, rxuav_movers={u_move}")

print()
print("===== TOP MOVERS =====")
for r in sorted(all_rows, key=lambda x: (int(x["rxuav_changes"]), int(x["zone_changes"])), reverse=True)[:20]:
    print(
        f"seed={r['seed']} cid={r['cid']} mal={r['malicious']} "
        f"beacons={r['beacons']} zones={r['unique_zones']} rxuavs={r['unique_rxuavs']} "
        f"zone_changes={r['zone_changes']} rxuav_changes={r['rxuav_changes']}"
    )
