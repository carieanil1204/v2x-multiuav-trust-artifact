/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "slic-aodv-helper.h"
#include "../model/slic-aodv-routing-protocol.h"
#include "ns3/double.h"
#include "ns3/nstime.h"
#include "ns3/node.h"

namespace ns3 {
namespace slic {

SlicAodvHelper::SlicAodvHelper ()
{
  m_factory.SetTypeId ("ns3::slic::SlicAodvRoutingProtocol");
}

SlicAodvHelper*
SlicAodvHelper::Copy () const
{
  return new SlicAodvHelper (*this);
}

Ptr<Ipv4RoutingProtocol>
SlicAodvHelper::Create (Ptr<Node> node) const
{
  Ptr<SlicAodvRoutingProtocol> protocol = m_factory.Create<SlicAodvRoutingProtocol> ();
  node->AggregateObject (protocol);
  return protocol;
}

void
SlicAodvHelper::SetWeights (double alpha1, double alpha2, double alpha3)
{
  m_factory.Set ("Alpha1", DoubleValue (alpha1));
  m_factory.Set ("Alpha2", DoubleValue (alpha2));
  m_factory.Set ("Alpha3", DoubleValue (alpha3));
}

void
SlicAodvHelper::SetCentralityUpdateInterval (Time interval)
{
  m_factory.Set ("CentralityUpdateInterval", TimeValue (interval));
}

void
SlicAodvHelper::Set (std::string name, const AttributeValue& value)
{
  m_factory.Set (name, value);
}

} // namespace slic
} // namespace ns3
