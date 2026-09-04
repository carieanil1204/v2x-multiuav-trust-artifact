#!/usr/bin/env python3
"""fig1: system architecture diagram, matching the paper's own System Model
(Sec III) and Framework (Sec IV) vocabulary exactly -- vehicles V, UAV edge
nodes U={u_a,u_b} (2-zone default), per-edge pipeline (5 operations per
Sec IV-A: evidence extraction, Bayesian trust update, guarded CUSUM,
confirmation gate, handover-aware transfer -- compressed to 3 boxes here to
avoid clutter), cross-UAV trust-state coordinator (Eq. handover_discount:
T_i^{u_b}(t+) = D_delta(T_i^{u_a}(t-))), and a passive cloud layer (caption:
"cloud layer passively aggregates ... for long-term analysis and model
updates; active per-vehicle trust decisions are handled by edge and
coordinator layers" -- drawn with dashed arrows, NOT in the active decision
path). Standard 4-layer vehicle/edge/coordinator/cloud V2X diagram, no
external image assets, matplotlib only."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(7.0, 5.6))
ax.set_xlim(0, 10)
ax.set_ylim(0, 10)
ax.axis("off")

def box(x, y, w, h, text, fc="#eaf1fb", ec="#1f4e8c", fontsize=8.2, lw=1.3, weight="normal"):
    b = FancyBboxPatch((x, y), w, h,
                        boxstyle="round,pad=0.04,rounding_size=0.08",
                        linewidth=lw, edgecolor=ec, facecolor=fc)
    ax.add_patch(b)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fontsize, color="#0b2545", weight=weight, linespacing=1.3)
    return (x, y, w, h)

def arrow(p_from, p_to, style="-|>", color="#1f4e8c", lw=1.3, ls="solid", connectionstyle="arc3,rad=0.0"):
    a = FancyArrowPatch(p_from, p_to, arrowstyle=style, mutation_scale=11,
                         linewidth=lw, color=color, linestyle=ls,
                         connectionstyle=connectionstyle)
    ax.add_patch(a)

def top(b):
    x, y, w, h = b
    return (x + w / 2, y + h)

def bottom(b):
    x, y, w, h = b
    return (x + w / 2, y)

def side(b, which):
    x, y, w, h = b
    return (x + w, y + h / 2) if which == "r" else (x, y + h / 2)

# ---- Layer 1: Cloud (passive) ----
cloud = box(2.3, 8.5, 5.4, 1.1,
            "Cloud Layer\n(passive aggregation, long-term analysis,\nmodel updates -- not in active decision path)",
            fc="#f3f3f3", ec="#8a8a8a", fontsize=7.6)

# ---- Layer 2: Coordinator ----
coord = box(3.1, 6.7, 3.8, 1.0,
            "Cross-UAV Trust-State Coordinator\n$T_i^{u_b}(t^+)=\\mathcal{D}_{\\delta}\\!\\left(T_i^{u_a}(t^-)\\right)$",
            fc="#eaf1fb", ec="#1f4e8c", fontsize=7.8)

# ---- Layer 3: two UAV edge zones ----
def edge_zone(x, label):
    outer = box(x, 3.7, 3.4, 2.6, "", fc="#ffffff", ec="#1f4e8c", lw=1.6)
    ox, oy, ow, oh = outer
    ax.text(ox + ow / 2, oy + oh - 0.28, label, ha="center", va="center",
            fontsize=8.6, color="#0b2545", weight="bold")
    steps = [
        "Physical-consistency\nevidence extraction",
        "Bayesian trust update +\nguarded CUSUM accumulation",
        "Confirmation gate\n$a_i(t)\\in\\{$SAFE, WARN, BAN$\\}$",
    ]
    sub_boxes = []
    sy = oy + oh - 0.62
    sh = 0.62
    for s in steps:
        sb = box(ox + 0.18, sy - sh, ow - 0.36, sh - 0.08, s,
                  fc="#eaf1fb", ec="#5b8ac6", fontsize=6.6, lw=0.9)
        sub_boxes.append(sb)
        sy -= sh
    for a_, b_ in zip(sub_boxes, sub_boxes[1:]):
        arrow(bottom(a_), top(b_), lw=1.0)
    return outer, sub_boxes

zone1, zone1_steps = edge_zone(0.6, "UAV Edge Zone 1 ($u_a$)")
zone2, zone2_steps = edge_zone(6.0, "UAV Edge Zone 2 ($u_b$)")

# ---- Layer 4: vehicles ----
veh_y = 0.5
veh_w, veh_h = 0.62, 0.42
def vehicle(x, label):
    return box(x, veh_y, veh_w, veh_h, label, fc="#fff2e0", ec="#b5651d", fontsize=6.8)

v_positions = [1.0, 1.9, 2.8, 6.9, 7.8, 8.7]
v_labels = ["$v_1$", "$v_2$", "$v_3$", "$v_{N-2}$", "$v_{N-1}$", "$v_N$"]
vboxes = [vehicle(x, lab) for x, lab in zip(v_positions, v_labels)]

ax.text(4.55, veh_y + veh_h / 2, "$\\cdots$", ha="center", va="center", fontsize=11, color="#0b2545")

# beacon arrows: vehicles -> their zone
for vb in vboxes[:3]:
    arrow(top(vb), (top(vb)[0], zone1[1]), lw=0.9, color="#b5651d")
for vb in vboxes[3:]:
    arrow(top(vb), (top(vb)[0], zone2[1]), lw=0.9, color="#b5651d")
ax.text(2.3, 3.35, "beacons $\\mathcal{B}_i(t)$", fontsize=6.8, color="#b5651d", ha="center")

# handover arrow: a vehicle moving from zone1 coverage to zone2 coverage
arrow((2.3, veh_y + veh_h + 0.28), (7.3, veh_y + veh_h + 0.28), lw=1.4,
      color="#2ca02c", ls="dashed", connectionstyle="arc3,rad=-0.15")
ax.text(4.8, veh_y + veh_h + 0.55, "handover $h_i: u_a \\rightarrow u_b$",
        fontsize=7.2, color="#1a7a1a", ha="center")

# edge zone -> coordinator (bidirectional trust-state transfer)
arrow(top(zone1), side(coord, "l"), lw=1.3, connectionstyle="arc3,rad=0.15")
arrow(side(coord, "l"), top(zone1), lw=1.3, ls="dashed", color="#5b8ac6", connectionstyle="arc3,rad=-0.15")
arrow(top(zone2), side(coord, "r"), lw=1.3, connectionstyle="arc3,rad=-0.15")
arrow(side(coord, "r"), top(zone2), lw=1.3, ls="dashed", color="#5b8ac6", connectionstyle="arc3,rad=0.15")

# coordinator -> cloud, and edges -> cloud (passive, dashed, thin)
arrow(top(coord), bottom(cloud), lw=1.0, ls="dotted", color="#8a8a8a")
arrow((zone1[0] + zone1[2] - 0.3, zone1[1] + zone1[3]), (cloud[0] + 0.4, cloud[1]),
      lw=0.8, ls="dotted", color="#aaaaaa", connectionstyle="arc3,rad=0.25")
arrow((zone2[0] + 0.3, zone2[1] + zone2[3]), (cloud[0] + cloud[2] - 0.4, cloud[1]),
      lw=0.8, ls="dotted", color="#aaaaaa", connectionstyle="arc3,rad=-0.25")

fig.tight_layout()
fig.savefig("figures/fig1_architecture.png", dpi=220)
print("saved figures/fig1_architecture.png")
