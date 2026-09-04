/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
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

struct NeighborEntry
{
  Ipv4Address address;
  Time expireTime;
  float centrality;
  Time centralityTimestamp;
  std::vector<Ipv4Address> twoHopNeighbors;
  bool isValid;
  NeighborEntry () : centrality (0.0f), isValid (false) {}
};

struct RouteEntry
{
  Ipv4Address destination;
  uint32_t destSeqNo;
  bool validSeqNo;
  uint16_t hopCount;
  Ipv4Address nextHop;
  Time lifeTime;
  Ipv4Address interface;
  float pathMinCentrality;
  float pathSumCentrality;
  double routeScore;
  RouteEntry () : destSeqNo (0), validSeqNo (false), hopCount (0),
                  pathMinCentrality (0.0f), pathSumCentrality (0.0f), routeScore (1e9) {}
};

struct RreqCacheEntry
{
  Ipv4Address origin;
  uint32_t rreqId;
  Time expireTime;
  double bestScore;
};

class SlicAodvRoutingProtocol : public Ipv4RoutingProtocol
{
public:
  static TypeId GetTypeId ();
  SlicAodvRoutingProtocol ();
  ~SlicAodvRoutingProtocol () override;

  // Ipv4RoutingProtocol interface
  Ptr<Ipv4Route> RouteOutput (Ptr<Packet> p, const Ipv4Header& header,
                              Ptr<NetDevice> oif, Socket::SocketErrno& sockerr) override;
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
  void PrintRoutingTable (Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const override;

  // SLIC API
  double GetMyCentrality () const { return m_myCentrality; }
  void TriggerCentralityUpdate ();
  float GetNeighborCentrality (Ipv4Address neighbor) const;
  void SetRouteWeights (double wHop, double wCent);
  bool LookupRoute (Ipv4Address dst, RouteEntry& rt) const;

protected:
  void DoInitialize () override;
  void DoDispose () override;

private:
  static constexpr uint16_t AODV_PORT = 654;
  static constexpr uint32_t CHANGE_THRESHOLD = 3;

  // AODV parameters
  Time m_helloInterval;
  Time m_activeRouteTimeout;
  Time m_myRouteTimeout;
  Time m_netTraversalTime;
  Time m_pathDiscoveryTime;
  Time m_deletePeriod;
  uint32_t m_rreqRetries;
  uint32_t m_rreqRateLimit;
  uint32_t m_netDiameter;
  uint32_t m_allowedHelloLoss;
  bool m_enableHello;
  bool m_destinationOnly;

  // SLIC parameters
  Time m_centralityUpdateInterval;
  double m_alpha1, m_alpha2, m_alpha3;
  double m_beta;
  double m_wHop;
  double m_wCent;
  double m_staleThreshold;
  double m_agingThreshold;
  double m_agingDiscount;

  // Scalability improvements
  uint32_t m_maxLocalNodes;                // max nodes in local graph
  double m_rreqSuppressionThreshold;       // duplicate RREQ threshold (0.95)
  Time m_adaptiveHelloMinInterval;         // min hello interval (1s)
  Time m_adaptiveHelloMaxInterval;         // max hello interval (5s)
  uint32_t m_maxNeighborsInHello;          // max neighbors to include in HELLO

  // State
  Ptr<Ipv4> m_ipv4;
  std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_socketAddresses;
  Ptr<Socket> m_recvSocket;
  uint32_t m_seqNo;
  uint32_t m_rreqId;
  std::map<Ipv4Address, NeighborEntry> m_neighbors;
  std::map<Ipv4Address, RouteEntry> m_routeTable;
  std::vector<RreqCacheEntry> m_rreqIdCache;
  Time m_rreqIdCacheTimeout;

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

  SLICCentrality m_centralityEngine;
  LocalGraph m_localGraph;
  double m_myCentrality;
  double m_lastCentrality;
  Time m_lastCentralityUpdate;
  uint32_t m_topologyChangeCount;

  double m_currentM, m_currentD, m_currentR;
  bool m_adaptiveWeights;

  Timer m_helloTimer;
  Timer m_centralityTimer;
  Ptr<UniformRandomVariable> m_uniformRandom;

  // Methods
  void SendRequest (Ipv4Address dst);
  void RecvRequest (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender);
  void SendReply (SlicRreqHeader const& rreqHeader, RouteEntry const& toOrigin);
  void RecvReply (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender);
  void SendReplyByIntermediateNode (RouteEntry const& toDst, SlicRreqHeader const& rreqHeader);
  void SendRerrWhenBreaksLinkToNextHop (Ipv4Address unreachable);
  void SendHello ();
  void RecvHello (Ptr<Packet> p, Ipv4Address sender);
  void HelloTimerExpire ();
  void ProcessNeighborTimeout (Ipv4Address neighbor);
  bool UpdateRoute (Ipv4Address dst, const RouteEntry& rt);
  void InvalidateRoute (Ipv4Address dst);
  bool IsRouteValid (const RouteEntry& rt) const;
  bool IsRreqDuplicate (Ipv4Address origin, uint32_t rreqId, double newScore);
  void InsertRreqCache (Ipv4Address origin, uint32_t rreqId, double score);
  void PurgeRreqCache ();
  void EnqueuePacket (Ptr<const Packet> p, const Ipv4Header& header,
                      UnicastForwardCallback ucb, ErrorCallback ecb);
  void DequeueAndSend (Ipv4Address dst);
  void PurgeQueue ();
  void ScheduleCentralityUpdate ();
  void PerformCentralityUpdate ();
  void BuildLocalGraph ();
  void ComputeDynamicWeights ();
  double ComputeRouteScore (uint16_t hopCount, float minCentrality) const;
  float DiscountCentrality (float centrality, Time timestamp) const;
  Time GetAdaptiveHelloInterval ();
  void RecvAodv (Ptr<Socket> socket);
  Ipv4Address GetMyAddress () const;
  void LogCentralityUpdate () const;
};

} // namespace slic
} // namespace ns3

#endif
