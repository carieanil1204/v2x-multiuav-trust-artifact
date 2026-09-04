/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-aodv-packet.h
 *
 * Extended AODV packet headers with SLIC centrality fields.
 * Adds 16 bytes to RREQ and 8 bytes to RREP.
 * HELLO extension carries centrality + neighbor list.
 */

#ifndef SLIC_AODV_PACKET_H
#define SLIC_AODV_PACKET_H

#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include <vector>

namespace ns3 {
namespace slic {

/**
 * \brief Extended RREQ header with centrality fields.
 *
 * Standard AODV RREQ fields (RFC 3561) plus:
 *   - SenderCentrality    (4 bytes) : forwarding node's Total Influence
 *   - PathMinCentrality   (4 bytes) : minimum centrality on path so far
 *   - PathSumCentrality   (4 bytes) : cumulative centrality sum along path
 *   - CentralityTimestamp (4 bytes) : sender's last centrality computation time
 *
 * Total extension: 16 bytes (6.7% overhead on 24-byte standard RREQ)
 */
class SlicRreqHeader : public Header
{
public:
  SlicRreqHeader ();

  // --- Standard AODV RREQ fields ---
  void SetHopCount (uint8_t count) { m_hopCount = count; }
  uint8_t GetHopCount () const { return m_hopCount; }
  void SetId (uint32_t id) { m_requestId = id; }
  uint32_t GetId () const { return m_requestId; }
  void SetDst (Ipv4Address dst) { m_dst = dst; }
  Ipv4Address GetDst () const { return m_dst; }
  void SetDstSeqno (uint32_t seqno) { m_dstSeqNo = seqno; }
  uint32_t GetDstSeqno () const { return m_dstSeqNo; }
  void SetOrigin (Ipv4Address origin) { m_origin = origin; }
  Ipv4Address GetOrigin () const { return m_origin; }
  void SetOriginSeqno (uint32_t seqno) { m_originSeqNo = seqno; }
  uint32_t GetOriginSeqno () const { return m_originSeqNo; }
  void SetGratuitousRrep (bool f) { m_flagG = f; }
  bool GetGratuitousRrep () const { return m_flagG; }
  void SetDestinationOnly (bool f) { m_flagD = f; }
  bool GetDestinationOnly () const { return m_flagD; }
  void SetUnknownSeqno (bool f) { m_flagU = f; }
  bool GetUnknownSeqno () const { return m_flagU; }

  // --- SLIC centrality extension fields ---
  void SetSenderCentrality (float c) { m_senderCentrality = c; }
  float GetSenderCentrality () const { return m_senderCentrality; }
  void SetPathMinCentrality (float c) { m_pathMinCentrality = c; }
  float GetPathMinCentrality () const { return m_pathMinCentrality; }
  void SetPathSumCentrality (float c) { m_pathSumCentrality = c; }
  float GetPathSumCentrality () const { return m_pathSumCentrality; }
  void SetCentralityTimestamp (uint32_t t) { m_centralityTimestamp = t; }
  uint32_t GetCentralityTimestamp () const { return m_centralityTimestamp; }

  // --- NS-3 Header interface ---
  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const override;
  uint32_t GetSerializedSize () const override;
  void Serialize (Buffer::Iterator start) const override;
  uint32_t Deserialize (Buffer::Iterator start) override;
  void Print (std::ostream& os) const override;

private:
  // Standard fields
  uint8_t m_hopCount;
  uint32_t m_requestId;
  Ipv4Address m_dst;
  uint32_t m_dstSeqNo;
  Ipv4Address m_origin;
  uint32_t m_originSeqNo;
  bool m_flagG;
  bool m_flagD;
  bool m_flagU;

  // SLIC extension
  float m_senderCentrality;
  float m_pathMinCentrality;
  float m_pathSumCentrality;
  uint32_t m_centralityTimestamp;
};

/**
 * \brief Extended RREP header with centrality annotation.
 *
 * Standard AODV RREP fields plus:
 *   - PathMinCentrality (4 bytes) : min centrality on discovered route
 *   - PathSumCentrality (4 bytes) : sum centrality on discovered route
 */
class SlicRrepHeader : public Header
{
public:
  SlicRrepHeader ();

  // --- Standard fields ---
  void SetHopCount (uint8_t count) { m_hopCount = count; }
  uint8_t GetHopCount () const { return m_hopCount; }
  void SetDst (Ipv4Address dst) { m_dst = dst; }
  Ipv4Address GetDst () const { return m_dst; }
  void SetDstSeqno (uint32_t seqno) { m_dstSeqNo = seqno; }
  uint32_t GetDstSeqno () const { return m_dstSeqNo; }
  void SetOrigin (Ipv4Address origin) { m_origin = origin; }
  Ipv4Address GetOrigin () const { return m_origin; }
  void SetLifeTime (uint32_t lt) { m_lifeTime = lt; }
  uint32_t GetLifeTime () const { return m_lifeTime; }
  void SetAckRequired (bool f) { m_flagA = f; }
  bool GetAckRequired () const { return m_flagA; }
  void SetPrefixSize (uint8_t sz) { m_prefixSize = sz; }
  uint8_t GetPrefixSize () const { return m_prefixSize; }

  // --- SLIC extension ---
  void SetPathMinCentrality (float c) { m_pathMinCentrality = c; }
  float GetPathMinCentrality () const { return m_pathMinCentrality; }
  void SetPathSumCentrality (float c) { m_pathSumCentrality = c; }
  float GetPathSumCentrality () const { return m_pathSumCentrality; }

  // --- NS-3 Header interface ---
  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const override;
  uint32_t GetSerializedSize () const override;
  void Serialize (Buffer::Iterator start) const override;
  uint32_t Deserialize (Buffer::Iterator start) override;
  void Print (std::ostream& os) const override;

private:
  uint8_t m_hopCount;
  Ipv4Address m_dst;
  uint32_t m_dstSeqNo;
  Ipv4Address m_origin;
  uint32_t m_lifeTime;
  bool m_flagA;
  uint8_t m_prefixSize;

  float m_pathMinCentrality;
  float m_pathSumCentrality;
};

/**
 * \brief Extended HELLO message carrying centrality and neighbor list.
 *
 * Piggybacks on AODV HELLO (which is a restricted RREP).
 * Additional data:
 *   - SenderCentrality (4 bytes)
 *   - NeighborCount    (1 byte)
 *   - NeighborList     (4 bytes per neighbor)
 */
class SlicHelloHeader : public Header
{
public:
  SlicHelloHeader ();

  void SetSenderCentrality (float c) { m_senderCentrality = c; }
  float GetSenderCentrality () const { return m_senderCentrality; }
  void SetNeighborList (const std::vector<Ipv4Address>& neighbors);
  std::vector<Ipv4Address> GetNeighborList () const { return m_neighbors; }

  static TypeId GetTypeId ();
  TypeId GetInstanceTypeId () const override;
  uint32_t GetSerializedSize () const override;
  void Serialize (Buffer::Iterator start) const override;
  uint32_t Deserialize (Buffer::Iterator start) override;
  void Print (std::ostream& os) const override;

private:
  float m_senderCentrality;
  std::vector<Ipv4Address> m_neighbors;
};

} // namespace slic
} // namespace ns3

#endif /* SLIC_AODV_PACKET_H */
