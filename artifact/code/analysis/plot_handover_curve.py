#!/usr/bin/env python3
"""Regenerate figures/fig4_handover_continuity.pdf: DR vs post-crossing
runway tau, continuity ON vs OFF. Data from
results/crossing_sweep_pass2/tail_{1.0,1.5} and
results/crossing_sweep_bisect2_15seed/tail_{1.1,1.2,1.3,1.4}
(scripts/parse_crossing_relative_results.py pooled DR, n=75/cell)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

tau = [1.0, 1.1, 1.2, 1.3, 1.4, 1.5]
on_dr = [94.7, 94.7, 94.7, 94.7, 94.7, 97.3]
off_dr = [0.0, 24.0, 32.0, 48.0, 69.3, 97.3]

fig, ax = plt.subplots(figsize=(4.2, 3.0))
ax.plot(tau, on_dr, marker="o", linewidth=2, label="Continuity ON", color="#1f77b4")
ax.plot(tau, off_dr, marker="s", linewidth=2, label="Continuity OFF (cold-start)", color="#d62728")
ax.set_xlabel(r"Post-crossing observation runway $\tau$ (s)")
ax.set_ylabel("Detection rate (%)")
ax.set_ylim(-5, 105)
ax.set_xlim(0.95, 1.55)
ax.grid(True, linewidth=0.4, alpha=0.6)
ax.legend(loc="lower right", fontsize=8, frameon=False)
ax.set_title("Detection rate vs. runway $\\tau$", fontsize=10)
fig.tight_layout()
fig.savefig("figures/fig4_handover_continuity.pdf")
print("saved figures/fig4_handover_continuity.pdf")
