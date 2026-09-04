/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-aodv-packet.cc
 *
 * Serialization for extended AODV headers with SLIC centrality fields.
 */

#include "slic-aodv-packet.h"
#include "ns3/log.h"
#include "ns3/address-utils.h"
#include <cstring>

namespace ns3 {
namespace slic {

NS_LOG_COMPONENT_DEFINE ("SlicAodvPacket");

// ═══════════════════════════════════════════════════════════════
// SlicRreqHeader
// ═══════════════════════════════════════════════════════════════

NS_OBJECT_ENSURE_REGISTERED (SlicRreqHeader);

SlicRreqHeader::SlicRreqHeader ()
  : m_hopCount (0),
    m_requestId (0),
    m_dstSeqNo (0),
    m_originSeqNo (0),
    m_flagG (false),
    m_flagD (false),
    m_flagU (false),
    m_senderCentrality (0.0f),
    m_pathMinCentrality (0.0f),
    m_pathSumCentrality (0.0f),
    m_centralityTimestamp (0)
{
}

TypeId
SlicRreqHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::slic::SlicRreqHeader")
    .SetParent<Header> ()
    .SetGroupName ("SlicAodv")
    .AddConstructor<SlicRreqHeader> ();
  return tid;
}

TypeId
SlicRreqHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
SlicRreqHeader::GetSerializedSize () const
{
  // Standard RREQ: 1(type+flags) + 1(reserved) + 1(hopcount) + 4(rreqId)
  //   + 4(dstIp) + 4(dstSeq) + 4(origIp) + 4(origSeq) = 23 bytes
  // Padded to 24 bytes
  // SLIC extension: 4+4+4+4 = 16 bytes
  return 24 + 16; // 40 bytes total
}

void
SlicRreqHeader::Serialize (Buffer::Iterator start) const
{
  // Type byte with flags
  uint8_t typeFlags = 1; // type = 1 (RREQ)
  if (m_flagG) typeFlags |= (1 << 5);
  if (m_flagD) typeFlags |= (1 << 4);
  if (m_flagU) typeFlags |= (1 << 3);
  start.WriteU8 (typeFlags);
  start.WriteU8 (0); // reserved
  start.WriteU8 (m_hopCount);
  start.WriteHtonU32 (m_requestId);
  WriteTo (start, m_dst);
  start.WriteHtonU32 (m_dstSeqNo);
  WriteTo (start, m_origin);
  start.WriteHtonU32 (m_originSeqNo);
  start.WriteU8 (0); // padding to 24 bytes

  // SLIC extension fields
  uint32_t sc, pmin, psum;
  std::memcpy (&sc, &m_senderCentrality, 4);
  std::memcpy (&pmin, &m_pathMinCentrality, 4);
  std::memcpy (&psum, &m_pathSumCentrality, 4);
  start.WriteHtonU32 (sc);
  start.WriteHtonU32 (pmin);
  start.WriteHtonU32 (psum);
  start.WriteHtonU32 (m_centralityTimestamp);
}

uint32_t
SlicRreqHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t typeFlags = i.ReadU8 ();
  m_flagG = (typeFlags >> 5) & 1;
  m_flagD = (typeFlags >> 4) & 1;
  m_flagU = (typeFlags >> 3) & 1;
  i.ReadU8 (); // reserved
  m_hopCount = i.ReadU8 ();
  m_requestId = i.ReadNtohU32 ();
  ReadFrom (i, m_dst);
  m_dstSeqNo = i.ReadNtohU32 ();
  ReadFrom (i, m_origin);
  m_originSeqNo = i.ReadNtohU32 ();
  i.ReadU8 (); // padding

  // SLIC extension
  uint32_t sc = i.ReadNtohU32 ();
  uint32_t pmin = i.ReadNtohU32 ();
  uint32_t psum = i.ReadNtohU32 ();
  m_centralityTimestamp = i.ReadNtohU32 ();
  std::memcpy (&m_senderCentrality, &sc, 4);
  std::memcpy (&m_pathMinCentrality, &pmin, 4);
  std::memcpy (&m_pathSumCentrality, &psum, 4);

  uint32_t dist = i.GetDistanceFrom (start);
  return dist;
}

void
SlicRreqHeader::Print (std::ostream& os) const
{
  os << "SLIC-RREQ ID=" << m_requestId
     << " origin=" << m_origin
     << " dst=" << m_dst
     << " hops=" << (int)m_hopCount
     << " senderCent=" << m_senderCentrality
     << " pathMin=" << m_pathMinCentrality
     << " pathSum=" << m_pathSumCentrality;
}

// ═══════════════════════════════════════════════════════════════
// SlicRrepHeader
// ═══════════════════════════════════════════════════════════════

NS_OBJECT_ENSURE_REGISTERED (SlicRrepHeader);

SlicRrepHeader::SlicRrepHeader ()
  : m_hopCount (0),
    m_dstSeqNo (0),
    m_lifeTime (0),
    m_flagA (false),
    m_prefixSize (0),
    m_pathMinCentrality (0.0f),
    m_pathSumCentrality (0.0f)
{
}

TypeId
SlicRrepHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::slic::SlicRrepHeader")
    .SetParent<Header> ()
    .SetGroupName ("SlicAodv")
    .AddConstructor<SlicRrepHeader> ();
  return tid;
}

TypeId
SlicRrepHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
SlicRrepHeader::GetSerializedSize () const
{
  // Standard RREP: 20 bytes + SLIC extension: 8 bytes = 28 bytes
  return 20 + 8;
}

void
SlicRrepHeader::Serialize (Buffer::Iterator start) const
{
  uint8_t typeFlags = 2; // type = 2 (RREP)
  if (m_flagA) typeFlags |= (1 << 5);
  start.WriteU8 (typeFlags);
  start.WriteU8 (m_prefixSize);
  start.WriteU8 (m_hopCount);
  WriteTo (start, m_dst);
  start.WriteHtonU32 (m_dstSeqNo);
  WriteTo (start, m_origin);
  start.WriteHtonU32 (m_lifeTime);
  start.WriteU8 (0); // padding to 20 bytes

  // SLIC extension
  uint32_t pmin, psum;
  std::memcpy (&pmin, &m_pathMinCentrality, 4);
  std::memcpy (&psum, &m_pathSumCentrality, 4);
  start.WriteHtonU32 (pmin);
  start.WriteHtonU32 (psum);
}

uint32_t
SlicRrepHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint8_t typeFlags = i.ReadU8 ();
  m_flagA = (typeFlags >> 5) & 1;
  m_prefixSize = i.ReadU8 ();
  m_hopCount = i.ReadU8 ();
  ReadFrom (i, m_dst);
  m_dstSeqNo = i.ReadNtohU32 ();
  ReadFrom (i, m_origin);
  m_lifeTime = i.ReadNtohU32 ();
  i.ReadU8 (); // padding

  uint32_t pmin = i.ReadNtohU32 ();
  uint32_t psum = i.ReadNtohU32 ();
  std::memcpy (&m_pathMinCentrality, &pmin, 4);
  std::memcpy (&m_pathSumCentrality, &psum, 4);

  return i.GetDistanceFrom (start);
}

void
SlicRrepHeader::Print (std::ostream& os) const
{
  os << "SLIC-RREP dst=" << m_dst
     << " origin=" << m_origin
     << " hops=" << (int)m_hopCount
     << " pathMin=" << m_pathMinCentrality
     << " pathSum=" << m_pathSumCentrality;
}

// ═══════════════════════════════════════════════════════════════
// SlicHelloHeader
// ═══════════════════════════════════════════════════════════════

NS_OBJECT_ENSURE_REGISTERED (SlicHelloHeader);

SlicHelloHeader::SlicHelloHeader ()
  : m_senderCentrality (0.0f)
{
}

TypeId
SlicHelloHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::slic::SlicHelloHeader")
    .SetParent<Header> ()
    .SetGroupName ("SlicAodv")
    .AddConstructor<SlicHelloHeader> ();
  return tid;
}

TypeId
SlicHelloHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

void
SlicHelloHeader::SetNeighborList (const std::vector<Ipv4Address>& neighbors)
{
  m_neighbors = neighbors;
  // Cap at 255 for 1-byte count field
  if (m_neighbors.size () > 255)
    m_neighbors.resize (255);
}

uint32_t
SlicHelloHeader::GetSerializedSize () const
{
  // 4 bytes (centrality) + 1 byte (count) + 4 bytes per neighbor
  return 5 + 4 * static_cast<uint32_t> (m_neighbors.size ());
}

void
SlicHelloHeader::Serialize (Buffer::Iterator start) const
{
  uint32_t sc;
  std::memcpy (&sc, &m_senderCentrality, 4);
  start.WriteHtonU32 (sc);
  start.WriteU8 (static_cast<uint8_t> (m_neighbors.size ()));
  for (const auto& addr : m_neighbors)
    {
      WriteTo (start, addr);
    }
}

uint32_t
SlicHelloHeader::Deserialize (Buffer::Iterator start)
{
  Buffer::Iterator i = start;
  uint32_t sc = i.ReadNtohU32 ();
  std::memcpy (&m_senderCentrality, &sc, 4);
  uint8_t count = i.ReadU8 ();
  m_neighbors.clear ();
  m_neighbors.resize (count);
  for (uint8_t k = 0; k < count; ++k)
    {
      ReadFrom (i, m_neighbors[k]);
    }
  return i.GetDistanceFrom (start);
}

void
SlicHelloHeader::Print (std::ostream& os) const
{
  os << "SLIC-HELLO centrality=" << m_senderCentrality
     << " neighbors=" << m_neighbors.size ();
}

} // namespace slic
} // namespace ns3
