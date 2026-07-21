#!/bin/bash
#
# stage45_rreq_observation.sh
#
# Enables centrality observation from RREQ flood (primary) with SLIC
# HELLO as cold-start/silence fallback (secondary).
#
# Changes:
#   1. RecvRequest: observe sender → add to graph, mark fresh
#   2. RecvReply:   observe sender → add to graph, mark fresh
#   3. SLIC HELLO interval: 1s → 3s (reduced overhead; HELLO now fallback)
#   4. Neighbor expiry: 5s → 30s (RREQs refresh naturally in busy network)
#
# Does NOT change:
#   - SLIC HELLO channel still exists (cold start + silence fallback)
#   - Stage 4's RREP tiebreak (centrality still influences route choice)
#   - Centrality computation timer (Stage 2, every 10s)
#
set -e

CC="src/slic-aodv2/model/slic2-aodv-routing-protocol.cc"

if [ ! -f "$CC" ]; then
  echo "ERROR: $CC not found" >&2
  exit 1
fi

if grep -q "SlicObserveFromRreq" "$CC"; then
  echo "Stage 4.5 already applied."
  exit 0
fi

echo "[1/4] Adding SlicObserveFromRreq helper method..."

python3 <<'PYEOF'
import re
path_h = "src/slic-aodv2/model/slic2-aodv-routing-protocol.h"
path_cc = "src/slic-aodv2/model/slic2-aodv-routing-protocol.cc"

# --- Header: declare helper method ---
with open(path_h) as f:
    h = f.read()

if 'SlicObserveFromRreq' not in h:
    marker = "double SlicComputeRouteScore(uint8_t hops, float minCentrality) const;"
    addition = marker + '''
    /// Stage 4.5: observe sender from control packet reception
    /// Called from RecvRequest/RecvReply to build topology from observed traffic.
    /// senderCentrality is the tag-carried value (0 if no tag).
    void SlicObserveFromTraffic(Ipv4Address sender, float senderCentrality);'''
    h = h.replace(marker, addition, 1)
    with open(path_h, 'w') as f:
        f.write(h)
    print("  Header: SlicObserveFromTraffic declared")

# --- .cc: add method body ---
with open(path_cc) as f:
    content = f.read()

if 'SlicObserveFromTraffic' not in content:
    method = '''

void
SlicAodvRoutingProtocol::SlicObserveFromTraffic(Ipv4Address sender, float senderCentrality)
{
    // Stage 4.5: called from RecvRequest/RecvReply when a control packet arrives.
    // The sender is our 1-hop neighbor (we received directly over wireless).
    // If the tag carries a centrality value, use it; otherwise leave existing.
    if (senderCentrality > 0.0f)
    {
        m_slicNeighborCentrality[sender] = senderCentrality;
    }
    else if (m_slicNeighborCentrality.find(sender) == m_slicNeighborCentrality.end())
    {
        // First time seeing this neighbor, no tag info yet — default
        m_slicNeighborCentrality[sender] = 0.5f;
    }
    // Refresh expiry regardless
    m_slicNeighborExpiry[sender] = Simulator::Now() + m_slicNeighborLifetime;
}
'''
    idx = content.rfind("} // namespace slic_aodv2")
    content = content[:idx] + method + "\n" + content[idx:]
    with open(path_cc, 'w') as f:
        f.write(content)
    print("  .cc: SlicObserveFromTraffic defined")
PYEOF

echo "[2/4] Adding RREQ-observation call in RecvRequest..."

python3 <<'PYEOF'
import re
path = "src/slic-aodv2/model/slic2-aodv-routing-protocol.cc"
with open(path) as f:
    content = f.read()

if 'SlicObserveFromTraffic(src' in content:
    print("  RecvRequest already patched")
else:
    # Inject observation call right after the RREQ header is extracted,
    # before any logic that depends on neighbor knowledge.
    # Anchor: "p->RemoveHeader(rreqHeader);" — first line of RecvRequest body
    anchor_re = re.compile(
        r'(SlicAodvRoutingProtocol::RecvRequest[^{]*\{\s*NS_LOG_FUNCTION\(this\);\s*RreqHeader rreqHeader;\s*p->RemoveHeader\(rreqHeader\);)'
    )
    m = anchor_re.search(content)
    if not m:
        print("ERROR: RecvRequest anchor not found")
        raise SystemExit(1)

    addition = m.group(1) + '''

    // Stage 4.5: observe this RREQ reception — src is our 1-hop neighbor.
    // Extract centrality from SlicRouteTag if attached by the sender.
    {
        SlicRouteTag slicRreqTag;
        float advertisedCent = 0.0f;
        if (p->PeekPacketTag(slicRreqTag))
            advertisedCent = slicRreqTag.GetPathMinCent();
        SlicObserveFromTraffic(src, advertisedCent);
    }
'''
    content = content.replace(m.group(1), addition, 1)
    with open(path, 'w') as f:
        f.write(content)
    print("  RecvRequest: RREQ observation injected")
PYEOF

echo "[3/4] Adding RREP-observation call in RecvReply..."

python3 <<'PYEOF'
import re
path = "src/slic-aodv2/model/slic2-aodv-routing-protocol.cc"
with open(path) as f:
    content = f.read()

if 'SlicObserveFromTraffic(sender' in content:
    print("  RecvReply already patched")
else:
    # Anchor: first few lines of RecvReply
    anchor_re = re.compile(
        r'(SlicAodvRoutingProtocol::RecvReply[^{]*\{\s*NS_LOG_FUNCTION\(this << " src " << sender\);\s*RrepHeader rrepHeader;\s*p->RemoveHeader\(rrepHeader\);)'
    )
    m = anchor_re.search(content)
    if not m:
        print("ERROR: RecvReply anchor not found")
        raise SystemExit(1)

    addition = m.group(1) + '''

    // Stage 4.5: observe this RREP reception — sender is our 1-hop neighbor.
    {
        SlicRouteTag slicRrepTag;
        float advertisedCent = 0.0f;
        if (p->PeekPacketTag(slicRrepTag))
            advertisedCent = slicRrepTag.GetPathMinCent();
        SlicObserveFromTraffic(sender, advertisedCent);
    }
'''
    content = content.replace(m.group(1), addition, 1)
    with open(path, 'w') as f:
        f.write(content)
    print("  RecvReply: RREP observation injected")
PYEOF

echo "[4/4] Reducing SLIC HELLO overhead (1s→3s) and extending neighbor lifetime (5s→30s)..."

python3 <<'PYEOF'
path = "src/slic-aodv2/model/slic2-aodv-routing-protocol.cc"
with open(path) as f:
    content = f.read()

# Change m_slicHelloInterval default
old = 'm_slicHelloInterval(Seconds(1.0))'
new = 'm_slicHelloInterval(Seconds(3.0))'
if old in content:
    content = content.replace(old, new, 1)
    print("  HELLO interval: 1s → 3s")

# Change neighbor lifetime default  
old = 'm_slicNeighborLifetime(Seconds(5.0))'
new = 'm_slicNeighborLifetime(Seconds(30.0))'
if old in content:
    content = content.replace(old, new, 1)
    print("  Neighbor lifetime: 5s → 30s")

with open(path, 'w') as f:
    f.write(content)
PYEOF

echo ""
echo "========================================"
echo "Stage 4.5 complete."
echo "========================================"
echo ""
echo "Centrality now observes the RREQ/RREP flood (primary) with SLIC"
echo "HELLO as cold-start/silence fallback at reduced 3s interval."
echo ""
echo "Rebuild and test:"
echo "  ./ns3 build 2>&1 | tail -10"
