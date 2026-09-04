#!/usr/bin/env python3
"""
apply_fix.py — single surgical fix

Remove RREQ score-based suppression (lines 1545-1591).
Replace with standard AODV IsDuplicate.
Reason: suppression uses last-hop centrality only. Without tag
propagation through wireless hops, this data is incomplete and
causes PDR crashes on certain random seeds.

Centrality routing is preserved via RREP tiebreak in RecvReply:
all RREQs flood normally, multiple paths discovered, best selected.
"""

path = "src/slic-aodv2/model/slic2-aodv-routing-protocol.cc"
with open(path) as f:
    lines = f.readlines()

# Lines 1545-1591 (1-indexed) = indices 1544-1590 (0-indexed)
# Find by content to be robust
start = next(i for i, l in enumerate(lines)
             if "Paper Algorithm 1: score-based RREQ suppression" in l)
end   = next(i for i, l in enumerate(lines)
             if i > start and "// Increment RREQ hop count" in l)

print(f"Replacing lines {start+1}–{end} ({end-start} lines)")

replacement = [
    "    // Standard AODV duplicate detection (RREQ score suppression removed).\n",
    "    // Score-based suppression relied on last-hop centrality only — without\n",
    "    // tag propagation through wireless hops the data is incomplete and causes\n",
    "    // PDR crashes on sparse topologies. Centrality routing is handled by the\n",
    "    // RREP tiebreak in RecvReply: all paths discovered, best selected.\n",
    "    if (m_rreqIdCache.IsDuplicate(origin, id))\n",
    "    {\n",
    "        return;\n",
    "    }\n",
    "\n",
]

lines[start:end] = replacement
with open(path, 'w') as f:
    f.writelines(lines)

print("Done")
