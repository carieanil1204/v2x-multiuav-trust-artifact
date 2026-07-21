/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-aodv-routing-protocol.cc
 *
 * Complete SLIC-AODV routing protocol implementation.
 * [DIAG] Added configurable route weights and detailed logging.
 * [TUNING] Added PathDiscoveryTime, NetTraversalTime, and aging thresholds.
 */

#include "slic-aodv-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"
#include "ns3/inet-socket-address.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/wifi-net-device.h"
#include "ns3/adhoc-wifi-mac.h"
#include "ns3/simulator.h"
#include <algorithm>
#include <cmath>
#include <limits>
#include <iomanip>
#include <numeric>

namespace ns3 {
namespace slic {

NS_LOG_COMPONENT_DEFINE ("SlicAodvRoutingProtocol");
NS_OBJECT_ENSURE_REGISTERED (SlicAodvRoutingProtocol);

enum SlicMsgType : uint8_t { SLIC_MSG_RREQ=1, SLIC_MSG_RREP=2, SLIC_MSG_RERR=3, SLIC_MSG_HELLO=4 };

class SlicTypeHeader : public Header
{
public:
  SlicTypeHeader (uint8_t t = 0) : m_type (t) {}
  uint8_t GetMsgType () const { return m_type; }
  static TypeId GetTypeId ()
  {
    static TypeId tid = TypeId ("ns3::slic::SlicTypeHeader")
      .SetParent<Header> ().SetGroupName ("SlicAodv")
      .AddConstructor<SlicTypeHeader> ();
    return tid;
  }
  TypeId GetInstanceTypeId () const override { return GetTypeId (); }
  uint32_t GetSerializedSize () const override { return 1; }
  void Serialize (Buffer::Iterator start) const override { start.WriteU8 (m_type); }
  uint32_t Deserialize (Buffer::Iterator start) override { m_type = start.ReadU8 (); return 1; }
  void Print (std::ostream &os) const override { os << "slic-type=" << (int)m_type; }
private:
  uint8_t m_type;
};

TypeId
SlicAodvRoutingProtocol::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::slic::SlicAodvRoutingProtocol")
    .SetParent<Ipv4RoutingProtocol> ()
    .SetGroupName ("SlicAodv")
    .AddConstructor<SlicAodvRoutingProtocol> ()
    .AddAttribute ("HelloInterval",
                   "Interval between HELLO broadcasts.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&SlicAodvRoutingProtocol::m_helloInterval),
                   MakeTimeChecker ())
    .AddAttribute ("ActiveRouteTimeout",
                   "Period of time after which a valid route entry is expired.",
                   TimeValue (Seconds (10)),
                   MakeTimeAccessor (&SlicAodvRoutingProtocol::m_activeRouteTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("CentralityUpdateInterval",
                   "Interval between SLIC centrality recomputations.",
                   TimeValue (Seconds (30)),
                   MakeTimeAccessor (&SlicAodvRoutingProtocol::m_centralityUpdateInterval),
                   MakeTimeChecker ())
    .AddAttribute ("PathDiscoveryTime",
                   "Maximum time for route discovery.",
                   TimeValue (Seconds (5.6)),
                   MakeTimeAccessor (&SlicAodvRoutingProtocol::m_pathDiscoveryTime),
                   MakeTimeChecker ())
    .AddAttribute ("NetTraversalTime",
                   "Estimated network traversal time.",
                   TimeValue (Seconds (2.8)),
                   MakeTimeAccessor (&SlicAodvRoutingProtocol::m_netTraversalTime),
                   MakeTimeChecker ())
    .AddAttribute ("Alpha1",
                   "SLIC weight for ISC sub-metric.",
                   DoubleValue (0.33),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_alpha1),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("Alpha2",
                   "SLIC weight for Semi-Local Influence sub-metric.",
                   DoubleValue (0.34),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_alpha2),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("Alpha3",
                   "SLIC weight for LASP sub-metric.",
                   DoubleValue (0.33),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_alpha3),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("Beta",
                   "Distance decay factor for Semi-Local Influence.",
                   DoubleValue (0.5),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_beta),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("WHop",
                   "Weight for hop count in route score (lower = more centrality influence).",
                   DoubleValue (0.6),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_wHop),
                   MakeDoubleChecker<double> (0.0, 10.0))
    .AddAttribute ("WCent",
                   "Weight for centrality term in route score.",
                   DoubleValue (0.4),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_wCent),
                   MakeDoubleChecker<double> (0.0, 10.0))
    .AddAttribute ("StaleThreshold",
                   "Seconds after which centrality is considered completely stale.",
                   DoubleValue (120.0),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_staleThreshold),
                   MakeDoubleChecker<double> (0.0, 1000.0))
    .AddAttribute ("AgingThreshold",
                   "Seconds after which discount starts to apply.",
                   DoubleValue (30.0),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_agingThreshold),
                   MakeDoubleChecker<double> (0.0, 1000.0))
    .AddAttribute ("AgingDiscount",
                   "Multiplicative discount factor for aging.",
                   DoubleValue (0.8),
                   MakeDoubleAccessor (&SlicAodvRoutingProtocol::m_agingDiscount),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("EnableHello",
                   "Enable periodic HELLO broadcasts.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&SlicAodvRoutingProtocol::m_enableHello),
                   MakeBooleanChecker ())
    .AddAttribute ("RreqRetries",
                   "Maximum number of RREQ retransmissions.",
                   UintegerValue (5),
                   MakeUintegerAccessor (&SlicAodvRoutingProtocol::m_rreqRetries),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NetDiameter",
                   "Estimated network diameter in hops.",
                   UintegerValue (35),
                   MakeUintegerAccessor (&SlicAodvRoutingProtocol::m_netDiameter),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("AllowedHelloLoss",
                   "Number of missed HELLOs before neighbor is considered down.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&SlicAodvRoutingProtocol::m_allowedHelloLoss),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxQueueLen",
                   "Maximum number of packets in the route request queue.",
                   UintegerValue (64),
                   MakeUintegerAccessor (&SlicAodvRoutingProtocol::m_maxQueueLen),
                   MakeUintegerChecker<uint32_t> ())
    ;
  return tid;
}

SlicAodvRoutingProtocol::SlicAodvRoutingProtocol ()
  : m_helloInterval (Seconds (1)),
    m_activeRouteTimeout (Seconds (10)),
    m_netTraversalTime (Seconds (2.8)),
    m_pathDiscoveryTime (Seconds (5.6)),
    m_deletePeriod (Seconds (15)),
    m_rreqRetries (5),
    m_rreqRateLimit (10),
    m_netDiameter (35),
    m_allowedHelloLoss (2),
    m_enableHello (true),
    m_destinationOnly (false),
    m_centralityUpdateInterval (Seconds (30)),
    m_alpha1 (0.33),
    m_alpha2 (0.34),
    m_alpha3 (0.33),
    m_beta (0.5),
    m_wHop (0.6),
    m_wCent (0.4),
    m_staleThreshold (120.0),
    m_agingThreshold (30.0),
    m_agingDiscount (0.8),
    m_seqNo (0),
    m_rreqId (0),
    m_rreqIdCacheTimeout (Seconds (6)),
    m_maxQueueLen (64),
    m_maxQueueTime (Seconds (30)),
    m_centralityEngine (0.33, 0.34, 0.33, 0.5, 3, 2, 1),
    m_myCentrality (1.0),
    m_lastCentrality (0.5),
    m_topologyChangeCount (0),
    m_currentM (0.0),
    m_currentD (0.0),
    m_currentR (1.0),
    m_adaptiveWeights (false)
{
  m_uniformRandom = CreateObject<UniformRandomVariable> ();
}

SlicAodvRoutingProtocol::~SlicAodvRoutingProtocol ()
{
}

void
SlicAodvRoutingProtocol::SetRouteWeights (double wHop, double wCent)
{
  m_wHop = wHop;
  m_wCent = wCent;
  NS_LOG_INFO ("SLIC-AODV: Route weights set to wHop=" << wHop << " wCent=" << wCent);
}

void
SlicAodvRoutingProtocol::DoInitialize ()
{
  NS_LOG_FUNCTION (this);

  m_centralityEngine.SetWeights (m_alpha1, m_alpha2, m_alpha3);
  m_centralityEngine.SetBeta (m_beta);

  m_lastCentralityUpdate = Seconds (0);
  Simulator::Schedule (Seconds (5.0) + MilliSeconds (m_uniformRandom->GetInteger (0, 1000)),
                       &SlicAodvRoutingProtocol::PerformCentralityUpdate, this);

  if (m_enableHello)
    {
      m_helloTimer.SetFunction (&SlicAodvRoutingProtocol::HelloTimerExpire, this);
      m_helloTimer.Schedule (m_helloInterval
                             + MilliSeconds (m_uniformRandom->GetInteger (0, 100)));
    }

  Ipv4RoutingProtocol::DoInitialize ();
}

void
SlicAodvRoutingProtocol::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_helloTimer.Cancel ();
  m_centralityTimer.Cancel ();
  m_neighbors.clear ();
  m_routeTable.clear ();
  m_rreqIdCache.clear ();
  m_queue.clear ();

  for (auto& kv : m_socketAddresses)
    {
      kv.first->Close ();
    }
  m_socketAddresses.clear ();
  m_ipv4 = nullptr;

  Ipv4RoutingProtocol::DoDispose ();
}

void
SlicAodvRoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  NS_LOG_FUNCTION (this << ipv4);
  m_ipv4 = ipv4;
}

// ═══════════════════════════════════════════════════════════════
// Routing Interface Methods
// ═══════════════════════════════════════════════════════════════

Ptr<Ipv4Route>
SlicAodvRoutingProtocol::RouteOutput (Ptr<Packet> p, const Ipv4Header& header,
                                      Ptr<NetDevice> oif,
                                      Socket::SocketErrno& sockerr)
{
  NS_LOG_FUNCTION (this << header.GetDestination ());

  if (header.GetDestination ().IsMulticast ())
    {
      sockerr = Socket::ERROR_NOROUTETOHOST;
      return nullptr;
    }

  RouteEntry rt;
  if (LookupRoute (header.GetDestination (), rt) && IsRouteValid (rt))
    {
      Ptr<Ipv4Route> route = Create<Ipv4Route> ();
      route->SetDestination (header.GetDestination ());
      route->SetGateway (rt.nextHop);
      route->SetSource (GetMyAddress ());
      route->SetOutputDevice (m_ipv4->GetNetDevice (
        m_ipv4->GetInterfaceForAddress (GetMyAddress ())));
      sockerr = Socket::ERROR_NOTERROR;
      return route;
    }

  Ipv4Address dst = header.GetDestination ();
  if (p)
    {
      QueueEntry q;
      q.packet = p->Copy ();
      q.header = header;
      q.ucb = UnicastForwardCallback ();
      q.ecb = ErrorCallback ();
      q.expireTime = Simulator::Now () + m_maxQueueTime;
      if (m_queue.size () >= m_maxQueueLen)
        m_queue.pop_front ();
      m_queue.push_back (q);
    }
  bool pending = false;
  for (size_t qi = 0; qi + 1 < m_queue.size (); ++qi)
    {
      if (m_queue[qi].header.GetDestination () == dst)
        { pending = true; break; }
    }
  if (!pending)
    {
      SendRequest (dst);
      Ipv4Address dst_r = dst;
      Simulator::Schedule (m_pathDiscoveryTime,
        [this, dst_r] () {
          RouteEntry rt_r;
          if (!LookupRoute (dst_r, rt_r) || !IsRouteValid (rt_r))
            {
              NS_LOG_DEBUG ("SLIC-AODV: RREQ retry for " << dst_r);
              SendRequest (dst_r);
            }
        });
    }
  sockerr = Socket::ERROR_NOROUTETOHOST;
  return nullptr;
}

bool
SlicAodvRoutingProtocol::RouteInput (Ptr<const Packet> p,
                                     const Ipv4Header& header,
                                     Ptr<const NetDevice> idev,
                                     const UnicastForwardCallback& ucb,
                                     const MulticastForwardCallback& mcb,
                                     const LocalDeliverCallback& lcb,
                                     const ErrorCallback& ecb)
{
  NS_LOG_FUNCTION (this << p->GetUid () << header.GetDestination ());

  Ipv4Address dst = header.GetDestination ();
  Ipv4Address myAddr = GetMyAddress ();

  if (m_ipv4->IsDestinationAddress (dst, m_ipv4->GetInterfaceForDevice (idev)))
    {
      if (lcb.IsNull ())
        return false;
      lcb (p, header, m_ipv4->GetInterfaceForDevice (idev));
      return true;
    }

  RouteEntry rt;
  if (LookupRoute (dst, rt) && IsRouteValid (rt))
    {
      Ptr<Ipv4Route> route = Create<Ipv4Route> ();
      route->SetDestination (dst);
      route->SetGateway (rt.nextHop);
      route->SetSource (header.GetSource ());
      route->SetOutputDevice (m_ipv4->GetNetDevice (
        m_ipv4->GetInterfaceForAddress (myAddr)));
      rt.lifeTime = std::max (rt.lifeTime, Simulator::Now () + m_activeRouteTimeout);
      m_routeTable[header.GetDestination ()] = rt;
      ucb (route, p, header);
      return true;
    }

  EnqueuePacket (p, header, ucb, ecb);
  SendRequest (dst);
  return true;
}

// ═══════════════════════════════════════════════════════════════
// RREQ Processing
// ═══════════════════════════════════════════════════════════════

void
SlicAodvRoutingProtocol::SendRequest (Ipv4Address dst)
{
  NS_LOG_FUNCTION (this << dst);

  m_rreqId++;
  m_seqNo++;

  SlicRreqHeader rreq;
  rreq.SetId (m_rreqId);
  rreq.SetDst (dst);
  rreq.SetDstSeqno (0);
  rreq.SetUnknownSeqno (true);
  rreq.SetOrigin (GetMyAddress ());
  rreq.SetOriginSeqno (m_seqNo);
  rreq.SetHopCount (0);

  rreq.SetSenderCentrality (static_cast<float> (m_myCentrality));
  rreq.SetPathMinCentrality (static_cast<float> (m_myCentrality));
  rreq.SetPathSumCentrality (static_cast<float> (m_myCentrality));
  rreq.SetCentralityTimestamp (
    static_cast<uint32_t> (m_lastCentralityUpdate.GetSeconds ()));

  InsertRreqCache (GetMyAddress (), m_rreqId, 0.0);

  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (rreq);
  packet->AddHeader (SlicTypeHeader (SLIC_MSG_RREQ));

  for (auto& kv : m_socketAddresses)
    {
      Ptr<Socket> socket = kv.first;
      socket->SendTo (packet, 0,
                      InetSocketAddress (Ipv4Address ("255.255.255.255"),
                                         AODV_PORT));
    }

  NS_LOG_INFO ("SLIC-AODV: Node " << GetMyAddress ()
               << " broadcasts RREQ for " << dst
               << " with centrality=" << m_myCentrality);
}

void
SlicAodvRoutingProtocol::RecvRequest (Ptr<Packet> p, Ipv4Address receiver,
                                      Ipv4Address sender)
{
  NS_LOG_FUNCTION (this << receiver << sender);

  SlicRreqHeader rreq;
  p->RemoveHeader (rreq);

  Ipv4Address origin = rreq.GetOrigin ();
  uint32_t rreqId = rreq.GetId ();

  float myEffectiveCentrality = DiscountCentrality (
    static_cast<float> (m_myCentrality),
    m_lastCentralityUpdate);

  float newMinCent = std::min (rreq.GetPathMinCentrality (),
                               myEffectiveCentrality);
  float newSumCent = rreq.GetPathSumCentrality () + myEffectiveCentrality;
  uint8_t newHopCount = rreq.GetHopCount () + 1;
  double newScore = ComputeRouteScore (newHopCount, newMinCent);

  if (IsRreqDuplicate (origin, rreqId, newScore))
    {
      NS_LOG_DEBUG ("SLIC-AODV: Dropping duplicate RREQ " << rreqId
                    << " from " << origin << " (score not better)");
      return;
    }

  InsertRreqCache (origin, rreqId, newScore);

  if (origin == GetMyAddress ())
    return;

  RouteEntry reverseRoute;
  reverseRoute.destination = origin;
  reverseRoute.destSeqNo = rreq.GetOriginSeqno ();
  reverseRoute.validSeqNo = true;
  reverseRoute.hopCount = newHopCount;
  reverseRoute.nextHop = sender;
  reverseRoute.lifeTime = Simulator::Now () + m_activeRouteTimeout;
  reverseRoute.interface = receiver;
  reverseRoute.pathMinCentrality = newMinCent;
  reverseRoute.pathSumCentrality = newSumCent;
  reverseRoute.routeScore = newScore;

  UpdateRoute (origin, reverseRoute);

  if (rreq.GetDst () == GetMyAddress ())
    {
      m_seqNo++;
      SendReply (rreq, reverseRoute);
      return;
    }

  if (!m_destinationOnly)
    {
      RouteEntry toDst;
      if (LookupRoute (rreq.GetDst (), toDst) && IsRouteValid (toDst)
          && toDst.validSeqNo
          && (int32_t)(toDst.destSeqNo - rreq.GetDstSeqno ()) >= 0)
        {
          SendReplyByIntermediateNode (toDst, rreq);
          return;
        }
    }

  rreq.SetHopCount (newHopCount);
  rreq.SetSenderCentrality (static_cast<float> (m_myCentrality));
  rreq.SetPathMinCentrality (newMinCent);
  rreq.SetPathSumCentrality (newSumCent);
  rreq.SetCentralityTimestamp (
    static_cast<uint32_t> (m_lastCentralityUpdate.GetSeconds ()));

  Ptr<Packet> fwdPacket = Create<Packet> ();
  fwdPacket->AddHeader (rreq);
  fwdPacket->AddHeader (SlicTypeHeader (SLIC_MSG_RREQ));

  for (auto& kv : m_socketAddresses)
    {
      Ptr<Socket> socket = kv.first;
      Time jitter = MilliSeconds (m_uniformRandom->GetInteger (0, 10));
      Simulator::Schedule (jitter, [socket, fwdPacket]() {
        socket->SendTo (fwdPacket, 0,
                        InetSocketAddress (
                          Ipv4Address ("255.255.255.255"), 654));
      });
    }
}

void
SlicAodvRoutingProtocol::SendReply (SlicRreqHeader const& rreqHeader,
                                    RouteEntry const& toOrigin)
{
  NS_LOG_FUNCTION (this);

  SlicRrepHeader rrep;
  rrep.SetDst (GetMyAddress ());
  rrep.SetDstSeqno (m_seqNo);
  rrep.SetOrigin (rreqHeader.GetOrigin ());
  rrep.SetHopCount (0);
  rrep.SetLifeTime (static_cast<uint32_t> (m_activeRouteTimeout.GetSeconds ()));

  float dstEffC = DiscountCentrality (static_cast<float> (m_myCentrality),
                                       m_lastCentralityUpdate);
  rrep.SetPathMinCentrality (std::min (rreqHeader.GetPathMinCentrality (), dstEffC));
  rrep.SetPathSumCentrality (rreqHeader.GetPathSumCentrality () + dstEffC);

  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (rrep);
  packet->AddHeader (SlicTypeHeader (SLIC_MSG_RREP));

  for (auto& kv : m_socketAddresses)
    {
      kv.first->SendTo (packet, 0,
                        InetSocketAddress (toOrigin.nextHop, AODV_PORT));
    }

  NS_LOG_INFO ("SLIC-AODV: " << GetMyAddress ()
               << " sends RREP to " << rreqHeader.GetOrigin ()
               << " via " << toOrigin.nextHop
               << " pathMin=" << rrep.GetPathMinCentrality ());
}

void
SlicAodvRoutingProtocol::SendReplyByIntermediateNode (
  RouteEntry const& toDst, SlicRreqHeader const& rreqHeader)
{
  NS_LOG_FUNCTION (this);

  SlicRrepHeader rrep;
  rrep.SetDst (rreqHeader.GetDst ());
  rrep.SetDstSeqno (toDst.destSeqNo);
  rrep.SetOrigin (rreqHeader.GetOrigin ());
  rrep.SetHopCount (toDst.hopCount);
  rrep.SetLifeTime (static_cast<uint32_t> (
    (toDst.lifeTime - Simulator::Now ()).GetSeconds ()));

  float combinedMin = std::min (rreqHeader.GetPathMinCentrality (),
                                toDst.pathMinCentrality);
  float combinedSum = rreqHeader.GetPathSumCentrality ()
                      + toDst.pathSumCentrality;
  rrep.SetPathMinCentrality (combinedMin);
  rrep.SetPathSumCentrality (combinedSum);

  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (rrep);
  packet->AddHeader (SlicTypeHeader (SLIC_MSG_RREP));

  RouteEntry toOrigin;
  LookupRoute (rreqHeader.GetOrigin (), toOrigin);

  for (auto& kv : m_socketAddresses)
    {
      kv.first->SendTo (packet, 0,
                        InetSocketAddress (toOrigin.nextHop, AODV_PORT));
    }
}

// ═══════════════════════════════════════════════════════════════
// RecvReply (with detailed logging)
// ═══════════════════════════════════════════════════════════════

void
SlicAodvRoutingProtocol::RecvReply (Ptr<Packet> p, Ipv4Address receiver,
                                    Ipv4Address sender)
{
  NS_LOG_FUNCTION (this << receiver << sender);

  SlicRrepHeader rrep;
  p->RemoveHeader (rrep);

  Ipv4Address dst = rrep.GetDst ();
  uint8_t hopCount = rrep.GetHopCount () + 1;

  double newScore = ComputeRouteScore (hopCount, rrep.GetPathMinCentrality ());

  RouteEntry existing;
  bool hasExisting = LookupRoute (dst, existing);

  bool shouldUpdate = false;
  std::string reason;

  if (!hasExisting || !IsRouteValid (existing))
    {
      shouldUpdate = true;
      reason = "no existing valid route";
    }
  else if (rrep.GetDstSeqno () > existing.destSeqNo)
    {
      shouldUpdate = true;
      reason = "newer sequence number";
    }
  else if (rrep.GetDstSeqno () == existing.destSeqNo && newScore < existing.routeScore)
    {
      shouldUpdate = true;
      reason = "better composite score";
    }
  else if (rrep.GetDstSeqno () == existing.destSeqNo
         && std::abs (newScore - existing.routeScore) < 0.01)
    {
      // First tie‑break by higher min centrality
      if (rrep.GetPathMinCentrality () > existing.pathMinCentrality + 1e-9)
        {
          shouldUpdate = true;
          reason = "tie-break by higher min centrality";
        }
      // Then by lower hop count
      else if (std::abs(rrep.GetPathMinCentrality () - existing.pathMinCentrality) < 1e-9
               && hopCount < existing.hopCount)
        {
          shouldUpdate = true;
          reason = "tie-break by lower hop count";
        }
    }

  NS_LOG_INFO ("[ROUTE COMPARE] Node " << GetMyAddress()
              << " dst=" << dst
              << " oldScore=" << existing.routeScore
              << " newScore=" << newScore
              << " oldMinCent=" << existing.pathMinCentrality
              << " newMinCent=" << rrep.GetPathMinCentrality()
              << " oldHops=" << (int)existing.hopCount
              << " newHops=" << (int)hopCount
              << " oldSeq=" << existing.destSeqNo
              << " newSeq=" << rrep.GetDstSeqno()
              << " update=" << shouldUpdate
              << " reason=" << reason);

  if (shouldUpdate)
    {
      RouteEntry newRoute;
      newRoute.destination = dst;
      newRoute.destSeqNo = rrep.GetDstSeqno ();
      newRoute.validSeqNo = true;
      newRoute.hopCount = hopCount;
      newRoute.nextHop = sender;
      newRoute.lifeTime = Simulator::Now () + Seconds (rrep.GetLifeTime ());
      newRoute.interface = receiver;
      newRoute.pathMinCentrality = rrep.GetPathMinCentrality ();
      newRoute.pathSumCentrality = rrep.GetPathSumCentrality ();
      newRoute.routeScore = newScore;

      UpdateRoute (dst, newRoute);
    }

  if (rrep.GetOrigin () != GetMyAddress ())
    {
      RouteEntry toOrigin;
      if (LookupRoute (rrep.GetOrigin (), toOrigin) && IsRouteValid (toOrigin))
        {
          rrep.SetHopCount (hopCount);
          float fwdEffC = DiscountCentrality (
            static_cast<float> (m_myCentrality), m_lastCentralityUpdate);
          rrep.SetPathMinCentrality (
            std::min (rrep.GetPathMinCentrality (), fwdEffC));
          rrep.SetPathSumCentrality (
            rrep.GetPathSumCentrality () + fwdEffC);
          Ptr<Packet> fwdPacket = Create<Packet> ();
          fwdPacket->AddHeader (rrep);
          fwdPacket->AddHeader (SlicTypeHeader (SLIC_MSG_RREP));
          for (auto& kv : m_socketAddresses)
            {
              kv.first->SendTo (fwdPacket, 0,
                                InetSocketAddress (toOrigin.nextHop, AODV_PORT));
            }
        }
    }
  else
    {
      DequeueAndSend (dst);
    }
}

// ═══════════════════════════════════════════════════════════════
// RERR
// ═══════════════════════════════════════════════════════════════

void
SlicAodvRoutingProtocol::SendRerrWhenBreaksLinkToNextHop (Ipv4Address unreachable)
{
  NS_LOG_FUNCTION (this << unreachable);

  std::vector<std::pair<Ipv4Address, uint32_t>> affected;
  for (auto& kv : m_routeTable)
    {
      if (kv.second.nextHop == unreachable && IsRouteValid (kv.second))
        {
          affected.push_back ({kv.first, kv.second.destSeqNo});
          InvalidateRoute (kv.first);
        }
    }

  if (affected.empty ())
    return;

  NS_LOG_INFO ("SLIC-AODV: " << GetMyAddress ()
               << " link break to " << unreachable
               << ", " << affected.size () << " routes invalidated — broadcasting poison RREPs");

  for (const auto& dest : affected)
    {
      SlicRrepHeader poisonRrep;
      poisonRrep.SetDst (dest.first);
      poisonRrep.SetDstSeqno (dest.second + 1);
      poisonRrep.SetOrigin (Ipv4Address ("255.255.255.255"));
      poisonRrep.SetHopCount (255);
      poisonRrep.SetLifeTime (0);
      poisonRrep.SetPathMinCentrality (0.0f);
      poisonRrep.SetPathSumCentrality (0.0f);

      Ptr<Packet> pkt = Create<Packet> ();
      pkt->AddHeader (poisonRrep);
      pkt->AddHeader (SlicTypeHeader (SLIC_MSG_RREP));
      for (auto& kv : m_socketAddresses)
        {
          kv.first->SendTo (pkt, 0,
            InetSocketAddress (Ipv4Address ("255.255.255.255"), AODV_PORT));
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// HELLO
// ═══════════════════════════════════════════════════════════════

void
SlicAodvRoutingProtocol::SendHello ()
{
  NS_LOG_FUNCTION (this);

  SlicRrepHeader hello;
  hello.SetDst (GetMyAddress ());
  hello.SetDstSeqno (m_seqNo);
  hello.SetOrigin (GetMyAddress ());
  hello.SetHopCount (0);
  hello.SetLifeTime (static_cast<uint32_t> (
    (m_allowedHelloLoss * m_helloInterval).GetSeconds ()));
  hello.SetPathMinCentrality (static_cast<float> (m_myCentrality));
  hello.SetPathSumCentrality (static_cast<float> (m_myCentrality));

  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (hello);

  SlicHelloHeader slicHello;
  slicHello.SetSenderCentrality (static_cast<float> (m_myCentrality));

  std::vector<Ipv4Address> myNeighbors;
  for (const auto& kv : m_neighbors)
    {
      if (kv.second.isValid)
        myNeighbors.push_back (kv.first);
    }
  slicHello.SetNeighborList (myNeighbors);
  packet->AddHeader (slicHello);
  packet->AddHeader (SlicTypeHeader (SLIC_MSG_HELLO));

  for (auto& kv : m_socketAddresses)
    {
      kv.first->SendTo (packet, 0,
                        InetSocketAddress (
                          Ipv4Address ("255.255.255.255"), AODV_PORT));
    }
}

void
SlicAodvRoutingProtocol::RecvHello (Ptr<Packet> p, Ipv4Address sender)
{
  NS_LOG_FUNCTION (this << sender);

  SlicHelloHeader slicHello;
  p->RemoveHeader (slicHello);

  SlicRrepHeader hello;
  p->RemoveHeader (hello);

  NeighborEntry& ne = m_neighbors[sender];
  bool wasNew = !ne.isValid;
  ne.address = sender;
  ne.isValid = true;
  ne.expireTime = Simulator::Now ()
                  + m_allowedHelloLoss * m_helloInterval;
  ne.centrality = slicHello.GetSenderCentrality ();
  ne.centralityTimestamp = Simulator::Now ();
  ne.twoHopNeighbors = slicHello.GetNeighborList ();

  if (wasNew)
    {
      m_topologyChangeCount++;
      if (m_topologyChangeCount >= CHANGE_THRESHOLD)
        {
          TriggerCentralityUpdate ();
          m_topologyChangeCount = 0;
        }
    }

  RouteEntry rt;
  rt.destination = sender;
  rt.destSeqNo = hello.GetDstSeqno ();
  rt.validSeqNo = true;
  rt.hopCount = 1;
  rt.nextHop = sender;
  rt.lifeTime = Simulator::Now () + m_activeRouteTimeout;
  rt.interface = GetMyAddress ();
  rt.pathMinCentrality = slicHello.GetSenderCentrality ();
  rt.pathSumCentrality = slicHello.GetSenderCentrality ();
  rt.routeScore = ComputeRouteScore (1, slicHello.GetSenderCentrality ());
  UpdateRoute (sender, rt);
}

void
SlicAodvRoutingProtocol::HelloTimerExpire ()
{
  NS_LOG_FUNCTION (this);

  SendHello ();

  std::vector<Ipv4Address> expired;
  for (auto& kv : m_neighbors)
    {
      if (kv.second.isValid && kv.second.expireTime < Simulator::Now ())
        {
          expired.push_back (kv.first);
        }
    }
  for (Ipv4Address addr : expired)
    {
      ProcessNeighborTimeout (addr);
    }

  PurgeRreqCache ();
  PurgeQueue ();

  m_helloTimer.Cancel ();
  m_helloTimer.SetFunction (&SlicAodvRoutingProtocol::HelloTimerExpire, this);
  m_helloTimer.Schedule (m_helloInterval
                         + MilliSeconds (m_uniformRandom->GetInteger (0, 100)));
}

void
SlicAodvRoutingProtocol::ProcessNeighborTimeout (Ipv4Address neighbor)
{
  NS_LOG_FUNCTION (this << neighbor);

  m_neighbors[neighbor].isValid = false;
  m_topologyChangeCount++;

  SendRerrWhenBreaksLinkToNextHop (neighbor);

  if (m_topologyChangeCount >= CHANGE_THRESHOLD)
    {
      TriggerCentralityUpdate ();
      m_topologyChangeCount = 0;
    }
}

// ═══════════════════════════════════════════════════════════════
// Centrality Computation and Scheduling
// ═══════════════════════════════════════════════════════════════

void
SlicAodvRoutingProtocol::ScheduleCentralityUpdate ()
{
  Time jitter = MilliSeconds (m_uniformRandom->GetInteger (0,
    static_cast<int> (m_centralityUpdateInterval.GetMilliSeconds () * 0.1)));
  Simulator::Schedule (m_centralityUpdateInterval + jitter,
                       &SlicAodvRoutingProtocol::PerformCentralityUpdate, this);
}

void
SlicAodvRoutingProtocol::TriggerCentralityUpdate ()
{
  NS_LOG_FUNCTION (this);
  PerformCentralityUpdate ();
}

// ═══════════════════════════════════════════════════════════════
// Dynamic Weight Computation
// Derives alpha1/alpha2/alpha3 from three live network parameters:
//   M = mobility ratio  (how far node moves per update cycle)
//   D = local density   (fraction of possible edges that exist)
//   R = regularity      (how uniform the degree distribution is)
// ═══════════════════════════════════════════════════════════════

void
SlicAodvRoutingProtocol::ComputeDynamicWeights ()
{
  uint32_t N = m_localGraph.GetNodeCount ();
  uint32_t E = m_localGraph.GetEdgeCount ();

  // Need at least 3 nodes for meaningful weight computation
  if (N < 3)
    {
      NS_LOG_UNCOND ("[DYNAMIC WEIGHTS] Node " << GetMyAddress ()
                    << " graph too small (" << N
                    << " nodes), keeping weights unchanged");
      return;
    }

  // ─── Parameter 1: Mobility Ratio M ───────────────────────────
  // Estimate from how much centrality changed since last update.
  // Large change = topology changed a lot = high mobility.
  // M=0 → static, M=1 → crosses one range per interval, M≥3 → extreme
  double centralityChange = std::abs (m_myCentrality - m_lastCentrality);
  double updateSecs = m_centralityUpdateInterval.GetSeconds ();
  double changeRate = (updateSecs > 1e-9) ? centralityChange / updateSecs : 0.0;
  // Normalize: 0.1 centrality change/second corresponds to M=1.0
  double M = changeRate / 0.1;
  M = std::max (0.0, std::min (M, 3.0));
  m_currentM = M;

  // ─── Parameter 2: Local Density D ────────────────────────────
  // Fraction of possible edges that actually exist in local graph.
  // D=0 → completely sparse, D=1 → fully connected clique
  double maxEdges = static_cast<double> (N) * (N - 1) / 2.0;
  double D = (maxEdges > 0.0) ? static_cast<double> (E) / maxEdges : 0.0;
  D = std::max (0.0, std::min (D, 1.0));
  m_currentD = D;

  // ─── Parameter 3: Topology Regularity R ──────────────────────
  // Coefficient of variation of degree sequence, inverted.
  // R=1 → all nodes have identical degree (line/grid, centrality useless)
  // R=0 → high degree variation (clear hubs, centrality very informative)
  double meanDeg = (N > 0) ? 2.0 * static_cast<double> (E) / N : 0.0;
  double variance = 0.0;
  auto nodes = m_localGraph.GetNodes ();
  for (uint32_t v : nodes)
    {
      double diff = static_cast<double> (m_localGraph.GetDegree (v)) - meanDeg;
      variance += diff * diff;
    }
  variance /= static_cast<double> (N);
  double stdDev = std::sqrt (variance);
  // R = 1 - CV where CV = stdDev/mean. Clamp to [0,1].
  double R = (meanDeg > 1e-9) ? 1.0 - (stdDev / meanDeg) : 1.0;
  R = std::max (0.0, std::min (R, 1.0));
  m_currentR = R;

  // ─── Derive Weights ───────────────────────────────────────────
  //
  // alpha3 (LASP):
  //   - Rises with mobility: bridge nodes matter more when links change fast
  //   - Suppressed by regularity: if all nodes have equal degree (R→1),
  //     LASP scores are uniform and provide no routing information
  //
  double alpha3 = (M / (M + 1.0)) * (1.0 - R * R);

  // alpha2 (SemiLocal):
  //   - Rises with density: neighbourhood influence matters in connected areas
  //   - Gets share of what LASP doesn't claim
  //
  double alpha2 = (1.0 - alpha3) * D / (D + 0.3);

  // alpha1 (ISC): spreading capability gets the remainder
  double alpha1 = 1.0 - alpha2 - alpha3;

  // ─── Enforce Minimums ─────────────────────────────────────────
  // No metric should be completely ignored — each captures something unique
  alpha1 = std::max (alpha1, 0.05);
  alpha2 = std::max (alpha2, 0.10);
  alpha3 = std::max (alpha3, 0.10);

  // ─── Renormalize to Sum = 1.0 ─────────────────────────────────
  double total = alpha1 + alpha2 + alpha3;
  alpha1 /= total;
  alpha2 /= total;
  alpha3 /= total;

  // ─── Apply to Centrality Engine ──────────────────────────────
  m_centralityEngine.SetWeights (alpha1, alpha2, alpha3);

  // Update protocol-level alpha members for attribute reflection
  m_alpha1 = alpha1;
  m_alpha2 = alpha2;
  m_alpha3 = alpha3;

  NS_LOG_UNCOND ("[DYNAMIC WEIGHTS] Node " << GetMyAddress ()
                << " t=" << std::fixed << std::setprecision (2)
                << Simulator::Now ().GetSeconds () << "s"
                << " M=" << std::setprecision (3) << M
                << " D=" << D
                << " R=" << R
                << " -> alpha1=" << std::setprecision (3) << alpha1
                << " alpha2=" << alpha2
                << " alpha3=" << alpha3);
}

void
SlicAodvRoutingProtocol::PerformCentralityUpdate ()
{
  NS_LOG_FUNCTION (this);

  BuildLocalGraph ();

  // Save previous centrality before overwriting — needed by ComputeDynamicWeights()
  // to estimate how much the topology has changed (mobility proxy)
  m_lastCentrality = m_myCentrality;

  // Recompute weights from current network state (M, D, R)
  // Must happen BEFORE ComputeAllCentralities() so new weights are used
  if (m_adaptiveWeights)
    ComputeDynamicWeights ();

  if (m_localGraph.GetNodeCount () < 2)
    {
      m_myCentrality = 1.0;
      NS_LOG_INFO ("[CENTRALITY] Node " << GetMyAddress()
                  << " graph too small, centrality set to 1.0");
    }
  else
    {
      uint32_t myNodeId = GetMyAddress ().Get ();
      if (m_localGraph.HasNode (myNodeId))
        {
          auto results = m_centralityEngine.ComputeAllCentralities (m_localGraph);
          auto it = results.find (myNodeId);
          if (it != results.end ())
            {
              NS_LOG_INFO ("[CENTRALITY] Node " << GetMyAddress()
                          << " ISC_norm=" << it->second.isc
                          << " SemiLocal_norm=" << it->second.semiLocal
                          << " LASP_norm=" << it->second.lasp
                          << " total=" << it->second.totalInfluence);
              m_myCentrality = it->second.totalInfluence;
            }
          else
            {
              m_myCentrality = 1.0;
            }
        }
      else
        {
          m_myCentrality = 1.0;
        }
    }

  m_lastCentralityUpdate = Simulator::Now ();
  LogCentralityUpdate ();
  ScheduleCentralityUpdate ();
}

void
SlicAodvRoutingProtocol::BuildLocalGraph ()
{
  NS_LOG_FUNCTION (this);

  m_localGraph.Clear ();
  uint32_t myId = GetMyAddress ().Get ();
  m_localGraph.AddNode (myId);

  // Phase 1: add all 1-hop neighbors (always kept)
  for (const auto& kv : m_neighbors)
    {
      if (!kv.second.isValid)
        continue;

      uint32_t neighId = kv.first.Get ();
      m_localGraph.AddNode (neighId);
      m_localGraph.AddEdge (myId, neighId);
    }

  // Phase 2: add 2-hop neighbors (if room)
  static const uint32_t MAX_LOCAL_NODES = 40;

  for (const auto& kv : m_neighbors)
    {
      if (!kv.second.isValid)
        continue;
      uint32_t neighId = kv.first.Get ();

      for (const Ipv4Address& twoHopNeigh : kv.second.twoHopNeighbors)
        {
          if (m_localGraph.GetNodeCount () >= MAX_LOCAL_NODES)
            break;

          uint32_t thId = twoHopNeigh.Get ();
          if (thId == myId)
            continue;
          m_localGraph.AddNode (thId);
          m_localGraph.AddEdge (neighId, thId);
          auto it2 = m_neighbors.find (twoHopNeigh);
          if (it2 != m_neighbors.end () && it2->second.isValid)
            {
              m_localGraph.AddEdge (myId, thId);
            }
        }
      if (m_localGraph.GetNodeCount () >= MAX_LOCAL_NODES)
        break;
    }

  // Phase 3: infer edges between 1-hop neighbors
  for (const auto& kvA : m_neighbors)
    {
      if (!kvA.second.isValid)
        continue;
      for (const Ipv4Address& reported : kvA.second.twoHopNeighbors)
        {
          auto itB = m_neighbors.find (reported);
          if (itB != m_neighbors.end () && itB->second.isValid)
            {
              m_localGraph.AddEdge (kvA.first.Get (), reported.Get ());
            }
        }
    }

  NS_LOG_DEBUG ("SLIC-AODV: Local graph built with "
                << m_localGraph.GetNodeCount () << " nodes and "
                << m_localGraph.GetEdgeCount () << " edges");
}

// ═══════════════════════════════════════════════════════════════
// Route Score Computation (using configurable weights)
// ═══════════════════════════════════════════════════════════════

double
SlicAodvRoutingProtocol::ComputeRouteScore (uint16_t hopCount,
                                            float minCentrality) const
{
  float c = std::max (0.0f, std::min (1.0f, minCentrality));
  double centPenalty = 1.0 - static_cast<double> (c);
  return m_wHop * static_cast<double> (hopCount) + m_wCent * centPenalty;
}

// ═══════════════════════════════════════════════════════════════
// DiscountCentrality with configurable thresholds
// ═══════════════════════════════════════════════════════════════

float
SlicAodvRoutingProtocol::DiscountCentrality (float centrality,
                                             Time timestamp) const
{
  double age = (Simulator::Now () - timestamp).GetSeconds ();

  if (age > m_staleThreshold)
    {
      return 0.1f;  // completely stale
    }
  else if (age > m_agingThreshold)
    {
      return centrality * m_agingDiscount;
    }
  return centrality;
}

float
SlicAodvRoutingProtocol::GetNeighborCentrality (Ipv4Address neighbor) const
{
  auto it = m_neighbors.find (neighbor);
  if (it != m_neighbors.end () && it->second.isValid)
    return it->second.centrality;
  return 0.5f;
}

// ═══════════════════════════════════════════════════════════════
// Route Table Management
// ═══════════════════════════════════════════════════════════════

bool
SlicAodvRoutingProtocol::LookupRoute (Ipv4Address dst, RouteEntry& rt) const
{
  auto it = m_routeTable.find (dst);
  if (it == m_routeTable.end ())
    return false;
  rt = it->second;
  return true;
}

bool
SlicAodvRoutingProtocol::UpdateRoute (Ipv4Address dst, const RouteEntry& rt)
{
  auto it = m_routeTable.find (dst);
  if (it == m_routeTable.end ())
    {
      m_routeTable[dst] = rt;
      return true;
    }

  if (rt.destSeqNo > it->second.destSeqNo
    || (rt.destSeqNo == it->second.destSeqNo
        && (rt.routeScore < it->second.routeScore - 1e-9
            || (std::abs(rt.routeScore - it->second.routeScore) < 1e-9
                && rt.hopCount < it->second.hopCount))))
    {
      it->second = rt;
      return true;
    }
  return false;
}

void
SlicAodvRoutingProtocol::InvalidateRoute (Ipv4Address dst)
{
  auto it = m_routeTable.find (dst);
  if (it != m_routeTable.end ())
    {
      it->second.lifeTime = Simulator::Now ();
    }
}

bool
SlicAodvRoutingProtocol::IsRouteValid (const RouteEntry& rt) const
{
  return rt.lifeTime > Simulator::Now ();
}

// ═══════════════════════════════════════════════════════════════
// RREQ Cache
// ═══════════════════════════════════════════════════════════════

bool
SlicAodvRoutingProtocol::IsRreqDuplicate (Ipv4Address origin, uint32_t rreqId,
                                          double newScore)
{
  for (const auto& entry : m_rreqIdCache)
    {
      if (entry.origin == origin && entry.rreqId == rreqId)
        {
          if (newScore < entry.bestScore * 0.99)
            return false;
          return true;
        }
    }
  return false;
}

void
SlicAodvRoutingProtocol::InsertRreqCache (Ipv4Address origin, uint32_t rreqId,
                                          double score)
{
  for (auto& entry : m_rreqIdCache)
    {
      if (entry.origin == origin && entry.rreqId == rreqId)
        {
          if (score < entry.bestScore)
            entry.bestScore = score;
          return;
        }
    }

  RreqCacheEntry newEntry;
  newEntry.origin = origin;
  newEntry.rreqId = rreqId;
  newEntry.expireTime = Simulator::Now () + m_rreqIdCacheTimeout;
  newEntry.bestScore = score;
  m_rreqIdCache.push_back (newEntry);
}

void
SlicAodvRoutingProtocol::PurgeRreqCache ()
{
  m_rreqIdCache.erase (
    std::remove_if (m_rreqIdCache.begin (), m_rreqIdCache.end (),
                    [](const RreqCacheEntry& e) {
                      return e.expireTime < Simulator::Now ();
                    }),
    m_rreqIdCache.end ());
}

// ═══════════════════════════════════════════════════════════════
// Packet Queue
// ═══════════════════════════════════════════════════════════════

void
SlicAodvRoutingProtocol::EnqueuePacket (Ptr<const Packet> p,
                                        const Ipv4Header& header,
                                        UnicastForwardCallback ucb,
                                        ErrorCallback ecb)
{
  if (m_queue.size () >= m_maxQueueLen)
    m_queue.pop_front ();

  QueueEntry qe;
  qe.packet = p;
  qe.header = header;
  qe.ucb = ucb;
  qe.ecb = ecb;
  qe.expireTime = Simulator::Now () + m_maxQueueTime;
  m_queue.push_back (qe);
}

void
SlicAodvRoutingProtocol::DequeueAndSend (Ipv4Address dst)
{
  RouteEntry rt;
  if (!LookupRoute (dst, rt) || !IsRouteValid (rt))
    return;

  auto it = m_queue.begin ();
  while (it != m_queue.end ())
    {
      if (it->header.GetDestination () == dst && it->expireTime > Simulator::Now ())
        {
          Ptr<Ipv4Route> route = Create<Ipv4Route> ();
          route->SetDestination (dst);
          route->SetGateway (rt.nextHop);
          route->SetSource (it->header.GetSource ());
          route->SetOutputDevice (m_ipv4->GetNetDevice (
            m_ipv4->GetInterfaceForAddress (GetMyAddress ())));
          if (!it->ucb.IsNull ())
            {
              it->ucb (route, it->packet, it->header);
            }
          it = m_queue.erase (it);
        }
      else
        {
          ++it;
        }
    }
}

void
SlicAodvRoutingProtocol::PurgeQueue ()
{
  m_queue.erase (
    std::remove_if (m_queue.begin (), m_queue.end (),
                    [](const QueueEntry& q) {
                      return q.expireTime < Simulator::Now ();
                    }),
    m_queue.end ());
}

// ═══════════════════════════════════════════════════════════════
// Socket Handling
// ═══════════════════════════════════════════════════════════════

void
SlicAodvRoutingProtocol::RecvAodv (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);

  Address sourceAddress;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddress);
  InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom (sourceAddress);
  Ipv4Address sender = inetSourceAddr.GetIpv4 ();
  Ipv4Address receiver = m_socketAddresses[socket].GetLocal ();

  if (sender == receiver) return;
  SlicTypeHeader typeHdr;
  packet->RemoveHeader (typeHdr);
  switch (typeHdr.GetMsgType ())
    {
    case SLIC_MSG_RREQ:  RecvRequest (packet, receiver, sender); break;
    case SLIC_MSG_RREP:  RecvReply (packet, receiver, sender); break;
    case SLIC_MSG_HELLO: RecvHello (packet, sender); break;
    default: break;
    }
}

void
SlicAodvRoutingProtocol::NotifyInterfaceUp (uint32_t interface)
{
  NS_LOG_FUNCTION (this << interface);

  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  if (l3->GetNAddresses (interface) <= 0)
    return;

  Ipv4InterfaceAddress iface = l3->GetAddress (interface, 0);
  if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
    return;

  Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                             UdpSocketFactory::GetTypeId ());
  socket->SetAllowBroadcast (true);
  socket->BindToNetDevice (l3->GetNetDevice (interface));
  socket->Bind (InetSocketAddress (iface.GetLocal (), AODV_PORT));
  socket->SetRecvCallback (MakeCallback (&SlicAodvRoutingProtocol::RecvAodv, this));
  m_socketAddresses[socket] = iface;

  Ptr<Socket> recvSocket = Socket::CreateSocket (GetObject<Node> (),
                                                 UdpSocketFactory::GetTypeId ());
  recvSocket->SetAllowBroadcast (true);
  recvSocket->BindToNetDevice (l3->GetNetDevice (interface));
  recvSocket->Bind (InetSocketAddress (Ipv4Address::GetAny (), AODV_PORT));
  recvSocket->SetRecvCallback (MakeCallback (&SlicAodvRoutingProtocol::RecvAodv, this));
  m_socketAddresses[recvSocket] = iface;
}

void
SlicAodvRoutingProtocol::NotifyInterfaceDown (uint32_t interface)
{
  NS_LOG_FUNCTION (this << interface);
}

void
SlicAodvRoutingProtocol::NotifyAddAddress (uint32_t interface,
                                           Ipv4InterfaceAddress address)
{
  NS_LOG_FUNCTION (this << interface << address);
}

void
SlicAodvRoutingProtocol::NotifyRemoveAddress (uint32_t interface,
                                              Ipv4InterfaceAddress address)
{
  NS_LOG_FUNCTION (this << interface << address);
}

Ipv4Address
SlicAodvRoutingProtocol::GetMyAddress () const
{
  if (m_socketAddresses.empty ())
    return Ipv4Address ("0.0.0.0");
  return m_socketAddresses.begin ()->second.GetLocal ();
}

void
SlicAodvRoutingProtocol::PrintRoutingTable (Ptr<OutputStreamWrapper> stream,
                                            Time::Unit unit) const
{
  *stream->GetStream ()
    << "\n=== SLIC-AODV Routing Table for " << GetMyAddress ()
    << " (centrality=" << m_myCentrality << ") ===\n"
    << "Destination\tNextHop\t\tHops\tSeqNo\tScore\tPathMinCent\n";

  for (const auto& kv : m_routeTable)
    {
      const RouteEntry& rt = kv.second;
      if (IsRouteValid (rt))
        {
          *stream->GetStream ()
            << rt.destination << "\t" << rt.nextHop << "\t"
            << rt.hopCount << "\t" << rt.destSeqNo << "\t"
            << rt.routeScore << "\t" << rt.pathMinCentrality << "\n";
        }
    }
}

void
SlicAodvRoutingProtocol::LogCentralityUpdate () const
{
  NS_LOG_INFO ("SLIC-AODV: Node " << GetMyAddress ()
               << " centrality updated to " << m_myCentrality
               << " at t=" << Simulator::Now ().GetSeconds ()
               << "s, local graph: " << m_localGraph.GetNodeCount ()
               << " nodes, " << m_localGraph.GetEdgeCount () << " edges");
}

} // namespace slic
} // namespace ns3
