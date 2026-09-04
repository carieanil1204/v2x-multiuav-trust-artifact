/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-aodv-helper.h
 *
 * Helper class for installing SLIC-AODV on NS-3 nodes.
 */

#ifndef SLIC_AODV_HELPER_H
#define SLIC_AODV_HELPER_H

#include "ns3/ipv4-routing-helper.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"

namespace ns3 {
namespace slic {

class SlicAodvHelper : public Ipv4RoutingHelper
{
public:
  SlicAodvHelper ();

  SlicAodvHelper* Copy () const override;

  Ptr<Ipv4RoutingProtocol> Create (Ptr<Node> node) const override;

  /**
   * \brief Set SLIC weight parameters.
   */
  void SetWeights (double alpha1, double alpha2, double alpha3);

  /**
   * \brief Set centrality update interval.
   */
  void SetCentralityUpdateInterval (Time interval);

  /**
   * \brief Set any attribute on the underlying routing protocol.
   */
  void Set (std::string name, const AttributeValue& value);

private:
  ObjectFactory m_factory;
};

} // namespace slic
} // namespace ns3

#endif /* SLIC_AODV_HELPER_H */
