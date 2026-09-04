#!/usr/bin/env python3
"""fig3: experimental validation coverage matrix, matching the caption
verbatim ("component ablations, attack robustness analysis, communication
degradation scenarios, scalability assessment, and baseline comparison")
and paper_artifact_v1.0/paper_mapping/table_csv_mapping.csv (Tables VII-XV).
No results data plotted -- this is a qualitative coverage checklist, built
from the paper's own already-verified experiment list."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

rows = [
    "Handover Ablation (Table VII)",
    "HTD Sensitivity (Table VIII)",
    "Guarded CUSUM Ablation (Table IX)",
    "Attack Variant Robustness (Table X)",
    "Beacon Falsification Probability (Table XI)",
    "Packet-Loss Robustness (Table XII)",
    "Baseline Comparison (Table XIII)",
    "Scalability (Table XIV)",
    "Overlap Guard (Table XV)",
]

cols = [
    "Component\nAblation",
    "Attack\nRobustness",
    "Communication\nDegradation",
    "Scalability",
    "Baseline\nComparison",
]

# 1 = covered, 0 = not covered, per experiment (rows) x category (cols)
cov = np.array([
    [1, 0, 0, 0, 0],  # Handover Ablation
    [1, 0, 0, 0, 0],  # HTD Sensitivity
    [1, 0, 0, 0, 0],  # CUSUM Ablation
    [0, 1, 1, 0, 0],  # Attack Variant Robustness (evaluated across packet loss too)
    [0, 1, 0, 0, 0],  # Beacon Falsification Probability
    [0, 0, 1, 0, 0],  # Packet-Loss Robustness
    [0, 0, 1, 0, 1],  # Baseline Comparison
    [0, 0, 0, 1, 0],  # Scalability
    [1, 0, 0, 0, 0],  # Overlap Guard
])

fig, ax = plt.subplots(figsize=(6.6, 4.0))
ax.imshow(cov, cmap="Blues", vmin=0, vmax=1.6, aspect="auto")

for i in range(cov.shape[0]):
    for j in range(cov.shape[1]):
        if cov[i, j]:
            ax.text(j, i, "✓", ha="center", va="center",
                    fontsize=11, color="#0b3d91", fontweight="bold")

ax.set_xticks(range(len(cols)))
ax.set_xticklabels(cols, fontsize=7.5)
ax.set_yticks(range(len(rows)))
ax.set_yticklabels(rows, fontsize=8)

ax.set_xticks(np.arange(-0.5, len(cols), 1), minor=True)
ax.set_yticks(np.arange(-0.5, len(rows), 1), minor=True)
ax.grid(which="minor", color="white", linewidth=1.5)
ax.tick_params(which="minor", bottom=False, left=False)
for spine in ax.spines.values():
    spine.set_visible(False)

ax.set_title("Experimental validation coverage", fontsize=10)
fig.tight_layout()
fig.savefig("figures/fig3_experimental_validation_matrix.pdf")
print("saved figures/fig3_experimental_validation_matrix.pdf")
