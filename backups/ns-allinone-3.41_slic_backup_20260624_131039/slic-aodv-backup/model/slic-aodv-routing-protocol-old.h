/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-aodv-routing-protocol.h
 *
 * SLIC-AODV: AODV routing protocol modified with Semi-Local Influence-based
 * Centrality for route selection in MANETs.
 *
 * Key modifications from standard AODV (RFC 3561):
 *   1. HELLO messages carry centrality + 1-hop neighbor list
 *   2. RREQ packets include centrality fields for path quality assessment
 *   3. Route selection uses composite score (hop count + centrality)
 *   4. Periodic centrality recomputation on local topology graph
 *   5. Staleness handling with graceful degradation to standard AODV
 */

#ifndef SLIC_AODV_ROUTING_PROTOCOL_H
#define SLIC_AODV_ROUTING_PROTOCOL_H

#include "slic-local-graph.h"
#include "slic-centrality.h"
#include "slic-aodv-packet.h"

#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ip-l4-protocol.h"
#include "ns3/ipv4-route.h"
#include "ns3/node.h"
#include "ns3/timer.h"
#include "ns3/random-variable-stream.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/socket.h"
#include "ns3/udp-socket-factory.h"

#include <map>
#include <set>
#include <vector>
#include <queue>

namespace ns3 {
namespace slic {

// ─── Neighbor Entry ──────────────────────────────────────────

struct NeighborEntry
{
  Ipv4Address address;
  Time expireTime;               ///< When this neighbor entry expires
  float centrality;              ///< Neighbor's reported centrality
  Time centralityTimestamp;      ///< When neighbor last computed centrality
  std::vector<Ipv4Address> twoHopNeighbors; ///< Neighbor's own 1-hop neighbors
  bool isValid;

  NeighborEntry ()
    : centrality (0.0f),
      isValid (false)
  {
  }
};

// ─── Route Table Entry ───────────────────────────────────────

struct RouteEntry
{
  Ipv4Address destination;
  uint32_t destSeqNo;
  bool validSeqNo;
  uint16_t hopCount;
  Ipv4Address nextHop;
  Time lifeTime;
  Ipv4Address interface;

  // SLIC extension
  float pathMinCentrality;   ///< Minimum centrality on route
  float pathSumCentrality;   ///< Sum of centrality along route
  double routeScore;         ///< Composite score (lower = better)

  RouteEntry ()
    : destSeqNo (0),
      validSeqNo (false),
      hopCount (0),
      pathMinCentrality (0.0f),
      pathSumCentrality (0.0f),
      routeScore (1e9)
  {
  }
};

// ─── RREQ ID Cache ──────────────────────────────────────────

struct RreqCacheEntry
{
  Ipv4Address origin;
  uint32_t rreqId;
  Time expireTime;
  double bestScore;   ///< Best composite score seen for this RREQ
};

/**
 * \brief SLIC-AODV Routing Protocol.
 *
 * Integrates SLIC centrality computation into AODV route discovery
 * and selection. Operates as a complete replacement for standard AODV.
 */
class SlicAodvRoutingProtocol : public Ipv4RoutingProtocol
{
public:
  static TypeId GetTypeId ();

  SlicAodvRoutingProtocol ();
  ~SlicAodvRoutingProtocol () override;

  // --- Ipv4RoutingProtocol interface ---
  Ptr<Ipv4Route> RouteOutput (Ptr<Packet> p, const Ipv4Header& header,
                              Ptr<NetDevice> oif,
                              Socket::SocketErrno& sockerr) override;
  bool RouteInput (Ptr<const Packet> p, const Ipv4Header& header,
                   Ptr<const NetDevice> idev,
                   const UnicastForwardCallback& ucb,
                   const MulticastForwardCallback& mcb,
                   const LocalDeliverCallback& lcb,
                   const ErrorCallback& ecb) override;
  void NotifyInterfaceUp (uint32_t interface) override;
  void NotifyInterfaceDown (uint32_t interface) override;
  void NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address) override;
  void NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address) override;
  void SetIpv4 (Ptr<Ipv4> ipv4) override;
  void PrintRoutingTable (Ptr<OutputStreamWrapper> stream,
                          Time::Unit unit = Time::S) const override;

  // --- SLIC-specific API ---

  /**
   * \brief Get this node's current SLIC Total Influence value.
   */
  double GetMyCentrality () const { return m_myCentrality; }

  /**
   * \brief Force immediate centrality recomputation.
   */
  void TriggerCentralityUpdate ();

  /**
   * \brief Get the centrality of a known neighbor.
   * \return Centrality value, or 0 if neighbor unknown.
   */
  float GetNeighborCentrality (Ipv4Address neighbor) const;

protected:
  void DoInitialize () override;
  void DoDispose () override;

private:
  // ─── Constants ─────────────────────────────────────────────

  static constexpr uint16_t AODV_PORT = 654;
  static constexpr double W_HOP = 0.6;         ///< Hop count weight in composite score
  static constexpr double W_CENT = 0.4;         ///< Centrality weight in composite score
  static constexpr float STALE_THRESHOLD = 120.0f; ///< Seconds before centrality is stale
  static constexpr float AGING_THRESHOLD = 30.0f;  ///< Seconds before discount applied
  static constexpr float AGING_DISCOUNT = 0.8f;    ///< Discount factor for aging centrality
  static constexpr uint32_t CHANGE_THRESHOLD = 3;  ///< Topology changes before forced update

  // ─── AODV Timers and Parameters ────────────────────────────

  Time m_helloInterval;        ///< HELLO broadcast interval (default 1s)
  Time m_activeRouteTimeout;   ///< Route lifetime (default 3s)
  Time m_myRouteTimeout;       ///< Route timeout for this node
  Time m_netTraversalTime;     ///< Estimated network traversal time
  Time m_pathDiscoveryTime;    ///< Maximum time for route discovery
  Time m_deletePeriod;         ///< Delete period for stale routes
  uint32_t m_rreqRetries;      ///< Max RREQ retry count
  uint32_t m_rreqRateLimit;    ///< Max RREQs per second
  uint32_t m_netDiameter;      ///< Estimated network diameter (hops)
  uint32_t m_allowedHelloLoss; ///< Max missed HELLOs before neighbor down
  bool m_enableHello;          ///< Send periodic HELLOs
  bool m_destinationOnly;      ///< Only destination can reply to RREQ

  // ─── SLIC Parameters ──────────────────────────────────────

  Time m_centralityUpdateInterval;  ///< How often to recompute centrality (default 30s)
  double m_alpha1, m_alpha2, m_alpha3; ///< SLIC weights
  double m_beta;                       ///< Semi-Local decay factor

  // ─── State ─────────────────────────────────────────────────

  Ptr<Ipv4> m_ipv4;
  std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_socketAddresses;
  Ptr<Socket> m_recvSocket;

  // Sequence numbers
  uint32_t m_seqNo;
  uint32_t m_rreqId;

  // Neighbor table (extended with centrality)
  std::map<Ipv4Address, NeighborEntry> m_neighbors;

  // Route table
  std::map<Ipv4Address, RouteEntry> m_routeTable;

  // RREQ ID cache (duplicate suppression)
  std::vector<RreqCacheEntry> m_rreqIdCache;
  Time m_rreqIdCacheTimeout;

  // Packet queue (packets waiting for route)
  struct QueueEntry
  {
    Ptr<const Packet> packet;
    Ipv4Header header;
    UnicastForwardCallback ucb;
    ErrorCallback ecb;
    Time expireTime;
  };
  std::deque<QueueEntry> m_queue;
  uint32_t m_maxQueueLen;
  Time m_maxQueueTime;

  // SLIC state
  SLICCentrality m_centralityEngine;
  LocalGraph m_localGraph;
  double m_myCentrality;
  Time m_lastCentralityUpdate;
  uint32_t m_topologyChangeCount;

  // Timers
  Timer m_helloTimer;
  Timer m_centralityTimer;
  Ptr<UniformRandomVariable> m_uniformRandom;

  // ─── RREQ Processing ──────────────────────────────────────

  void SendRequest (Ipv4Address dst);
  void RecvRequest (Ptr<Packet> p, Ipv4Address receiver,
                    Ipv4Address sender);
  void SendReply (SlicRreqHeader const& rreqHeader,
                  RouteEntry const& toOrigin);
  void RecvReply (Ptr<Packet> p, Ipv4Address receiver,
                  Ipv4Address sender);
  void SendReplyByIntermediateNode (RouteEntry const& toDst,
                                   SlicRreqHeader const& rreqHeader);

  // ─── RERR ──────────────────────────────────────────────────

  void SendRerrWhenBreaksLinkToNextHop (Ipv4Address unreachable);

  // ─── HELLO ─────────────────────────────────────────────────

  void SendHello ();
  void RecvHello (Ptr<Packet> p, Ipv4Address sender);
  void HelloTimerExpire ();
  void ProcessNeighborTimeout (Ipv4Address neighbor);

  // ─── Route Management ─────────────────────────────────────

  bool LookupRoute (Ipv4Address dst, RouteEntry& rt) const;
  bool UpdateRoute (Ipv4Address dst, const RouteEntry& rt);
  void InvalidateRoute (Ipv4Address dst);
  bool IsRouteValid (const RouteEntry& rt) const;

  // ─── RREQ Cache ───────────────────────────────────────────

  bool IsRreqDuplicate (Ipv4Address origin, uint32_t rreqId,
                        double newScore);
  void InsertRreqCache (Ipv4Address origin, uint32_t rreqId,
                        double score);
  void PurgeRreqCache ();

  // ─── Packet Queue ─────────────────────────────────────────

  void EnqueuePacket (Ptr<const Packet> p, const Ipv4Header& header,
                      UnicastForwardCallback ucb, ErrorCallback ecb);
  void DequeueAndSend (Ipv4Address dst);
  void PurgeQueue ();

  // ─── Centrality ────────────────────────────────────────────

  void ScheduleCentralityUpdate ();
  void PerformCentralityUpdate ();
  void BuildLocalGraph ();

  /**
   * \brief Compute composite route score. Lower = better.
   *
   * score = W_HOP * hopCount + W_CENT * (1 / minCentrality)
   *
   * When minCentrality is 0 or unknown, uses a large penalty
   * to fall back to hop-count-dominated routing.
   */
  double ComputeRouteScore (uint16_t hopCount, float minCentrality) const;

  /**
   * \brief Apply staleness discount to a centrality value.
   */
  float DiscountCentrality (float centrality, Time timestamp) const;

  // ─── Socket Handling ───────────────────────────────────────

  void RecvAodv (Ptr<Socket> socket);
  Ptr<Socket> FindSocketForInterface (uint32_t iface) const;
  Ipv4Address GetMyAddress () const;

  // ─── Logging ───────────────────────────────────────────────

  void LogCentralityUpdate () const;
};

} // namespace slic
} // namespace ns3

#endif /* SLIC_AODV_ROUTING_PROTOCOL_H */
