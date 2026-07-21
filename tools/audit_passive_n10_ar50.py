import csv
import re
from pathlib import Path
from collections import Counter, defaultdict

input_csv = Path("results/final_locked_csv/baseline_veremi/baseline_input_n10_ar50_drop0_log_paths.csv")

patterns = [
    "[PASSIVE-BEACON]",
    "PASSIVE-BEACON",
    "[PASSIVE]",
    "PASSIVE",
    "[BEACON]",
    "BEACON",
    "[RX]",
    "RX",
]

def kv_keys(line):
    keys = []
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_\-]*)\s*[=:]\s*([^,\s\]]+)", line):
        keys.append(m.group(1))
    return keys

rows = list(csv.DictReader(input_csv.open()))

print("Input logs:", len(rows))
print("=" * 90)

total_passive = 0
global_keys = Counter()
sample_lines = []

for r in rows:
    seed = r["seed"]
    p = Path(r["log_path"])
    if not p.exists():
        print(f"seed={seed} MISSING_LOG {p}")
        continue

    text = p.read_text(errors="ignore").splitlines()

    counts = Counter()
    key_counter = Counter()

    for line in text:
        for pat in patterns:
            if pat in line:
                counts[pat] += 1

        if "PASSIVE" in line or "BEACON" in line or "[RX]" in line:
            for k in kv_keys(line):
                key_counter[k] += 1
                global_keys[k] += 1

            if len(sample_lines) < 20:
                sample_lines.append((seed, line[:500]))

    passive_count = counts["[PASSIVE-BEACON]"] + counts["PASSIVE-BEACON"] + counts["[PASSIVE]"] + counts["PASSIVE"]
    total_passive += passive_count

    print(f"seed={seed} passive_like={passive_count} beacon_like={counts['[BEACON]'] + counts['BEACON']} rx_like={counts['[RX]'] + counts['RX']} keys={dict(key_counter.most_common(20))}")

print("=" * 90)
print("TOTAL_PASSIVE_LIKE:", total_passive)
print("GLOBAL_KEYS_TOP_50:")
for k, v in global_keys.most_common(50):
    print(f"{k}: {v}")

print("=" * 90)
print("SAMPLE_LINES:")
for seed, line in sample_lines:
    print(f"\n--- seed {seed} ---")
    print(line)
