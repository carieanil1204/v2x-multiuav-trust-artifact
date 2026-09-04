#!/usr/bin/env python3
"""Regenerate fig6/fig7/fig8 PDFs from the paper's own already-verified
table data (Table XI attack-rate robustness, Table XIII baseline
comparison, Table XIV scalability). Same style as fig4's regenerated plot.
fig1 (architecture), fig3 (validation-coverage matrix), and fig5 (conceptual
CUSUM schematic) are NOT regenerated here -- none of the three has numeric
CSV/table data behind it (fig1/fig3 are diagrams, fig5's own caption calls
it a "conceptual representation")."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---- fig6: attack-rate robustness (Table XI) ----
rate = [20, 50, 70, 80]
dr = [95.56, 96.19, 96.30, 96.67]

fig, ax = plt.subplots(figsize=(4.2, 3.0))
ax.plot(rate, dr, marker="o", linewidth=2, color="#1f77b4")
ax.set_xlabel("Beacon falsification probability (%)")
ax.set_ylabel("Detection rate (%)")
ax.set_ylim(90, 100)
ax.grid(True, linewidth=0.4, alpha=0.6)
ax.set_title("Detection rate vs. falsification probability", fontsize=10)
fig.tight_layout()
fig.savefig("figures/fig6_attack_rate_robustness.pdf")
print("saved figures/fig6_attack_rate_robustness.pdf")

# ---- fig7: baseline comparison under packet loss (Table XIII) ----
loss = [0, 5, 10, 20]
proposed_dr = [96.19, 94.29, 91.43, 91.43]
baseline_dr = [96.19, 89.52, 84.76, 79.05]

fig, ax = plt.subplots(figsize=(4.2, 3.0))
ax.plot(loss, proposed_dr, marker="o", linewidth=2, label="Proposed", color="#1f77b4")
ax.plot(loss, baseline_dr, marker="s", linewidth=2, label="VeReMi local segment-reset baseline", color="#d62728")
ax.set_xlabel("Packet loss (%)")
ax.set_ylabel("Detection rate (%)")
ax.set_ylim(70, 100)
ax.grid(True, linewidth=0.4, alpha=0.6)
ax.legend(loc="lower left", fontsize=7.5, frameon=False)
ax.set_title("Detection rate vs. packet loss", fontsize=10)
fig.tight_layout()
fig.savefig("figures/fig7_packet_loss_baseline.pdf")
print("saved figures/fig7_packet_loss_baseline.pdf")

# ---- fig8: scalability (Table XIV), dual axis DR + runtime ----
n_vehicles = [10, 20, 30, 50]
dr8 = [96.19, 83.08, 72.28, 52.29]
runtime = [86.73, 218.53, 438.60, 1189.40]

fig, ax1 = plt.subplots(figsize=(4.4, 3.1))
l1, = ax1.plot(n_vehicles, dr8, marker="o", linewidth=2, color="#1f77b4", label="Detection rate")
ax1.set_xlabel("Number of vehicles")
ax1.set_ylabel("Detection rate (%)", color="#1f77b4")
ax1.tick_params(axis="y", labelcolor="#1f77b4")
ax1.set_ylim(0, 100)

ax2 = ax1.twinx()
l2, = ax2.plot(n_vehicles, runtime, marker="s", linewidth=2, color="#ff7f0e", label="Runtime")
ax2.set_ylabel("Runtime (s)", color="#ff7f0e")
ax2.tick_params(axis="y", labelcolor="#ff7f0e")

ax1.grid(True, linewidth=0.4, alpha=0.6)
ax1.legend(handles=[l1, l2], loc="center left", fontsize=7.5, frameon=False)
ax1.set_title("Detection rate and runtime vs. vehicle count", fontsize=10)
fig.tight_layout()
fig.savefig("figures/fig8_scalability_runtime.pdf")
print("saved figures/fig8_scalability_runtime.pdf")
