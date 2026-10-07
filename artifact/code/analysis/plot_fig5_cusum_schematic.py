#!/usr/bin/env python3
"""Illustrative (non-experimental) schematic for fig5, matching the paper's
own caption ("Conceptual representation... explains how consecutive
suspicious observations increase cumulative suspicion until the adaptive
decision threshold is reached") and the guarded-CUSUM equations in
Section IV-C: C_i(t) = max(0, C_i(t-1) + q_i(t) - nu), alert when
C_i(t) >= H, final BAN additionally gated by n_i(t)>=n_min, w_i(t)>=w_min,
h_i(t)=1 (Eq. conservative_confirmation / confirmation_gate).
H=2.5 is the framework's actual default CUSUM threshold
(scripts/run_crossing_relative_stress.sh: CUSUM_H default 2.5).
This is a synthetic trajectory for illustration only, not a plot of any
experimental results CSV -- labeled as such on the figure itself."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

H = 2.5

t = list(range(0, 19))
# Honest-looking baseline (t=0..8): small drift-canceling fluctuations, never
# sustained, consistent with Eq. cusum_update's -nu drift term pulling it
# back toward 0.
# Suspicious streak begins at t=9: consecutive q_i(t) pushes C_i(t) up.
c = [0.0, 0.3, 0.0, 0.5, 0.1, 0.0, 0.4, 0.0, 0.2,
     0.6, 1.1, 1.6, 2.0, 2.4, 2.8, 3.1, 3.4, 3.6, 3.7]

alert_t = next(i for i, v in enumerate(c) if v >= H)   # t=14
confirm_t = alert_t + 3                                 # guard delay before BAN

fig, ax = plt.subplots(figsize=(4.6, 3.1))
ax.step(t, c, where="post", linewidth=2, color="#1f77b4")
ax.axhline(H, color="#555555", linestyle="--", linewidth=1.2)
ax.text(0.2, H + 0.12, r"Threshold $H=2.5$", fontsize=8, color="#555555")

ax.axvline(alert_t, color="#d62728", linestyle=":", linewidth=1.2)
ax.annotate("CUSUM alert\n" + r"$C_i(t)\geq H$",
            xy=(alert_t, H), xytext=(alert_t - 6.3, H + 1.3),
            fontsize=7.5, color="#d62728",
            arrowprops=dict(arrowstyle="->", color="#d62728", lw=1))

ax.axvline(confirm_t, color="#2ca02c", linestyle=":", linewidth=1.2)
ax.annotate("BAN confirmed\n" + r"($n_i{\geq}n_{\min}$, $w_i{\geq}w_{\min}$, $h_i{=}1$)",
            xy=(confirm_t, c[confirm_t]), xytext=(confirm_t - 5.7, 0.3),
            fontsize=7.5, color="#2ca02c",
            arrowprops=dict(arrowstyle="->", color="#2ca02c", lw=1))

ax.set_xlabel("Observation index $t$")
ax.set_ylabel(r"CUSUM score $C_i(t)$")
ax.set_xlim(0, 18)
ax.set_ylim(0, 4.3)
ax.grid(True, linewidth=0.4, alpha=0.5)
ax.set_title("Guarded CUSUM accumulation (illustrative)", fontsize=9.5)
ax.text(0.98, 0.03, "illustrative schematic, not experimental data",
        transform=ax.transAxes, ha="right", va="bottom",
        fontsize=6.5, style="italic", color="#777777")

fig.tight_layout()
fig.savefig("figures/fig5_cusum_ablation.pdf")
print("saved figures/fig5_cusum_ablation.pdf")
