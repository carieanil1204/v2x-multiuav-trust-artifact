/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-aodv-simulation.cc  (v5 — Flexible parameters for all protocols)
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/olsr-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/slic-aodv-helper.h"
#include "ns3/slic-aodv-routing-protocol.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <set>
#include <cmath>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("SlicAodvSimulation");

int
main (int argc, char *argv[])
{
  // ─── General Parameters ─────────────────────────────────────
  uint32_t nNodes = 50;
  double maxSpeed = 20.0, minSpeed = 1.0, pauseTime = 0.0;
  uint32_t nFlows = 10, packetSize = 64;
  double dataRate = 2048.0;
  std::string protocol = "slic-aodv";
  std::string phyMode = "canonical";          // "canonical" (802.11b) or "modern" (802.11g)
  std::string lossModel = "canonical";       // "canonical" (Friis) or "modern" (LogDist+Nakagami)
  double alpha1 = 0.33, alpha2 = 0.34, alpha3 = 0.33;
  double centralityInterval = 0.0;
  double duration = 200.0;
  uint32_t runNumber = 1;
  bool verbose = false;
  std::string outputPrefix = "slic-aodv-results";
  int areaW = 300, areaH = 1500;
  int customAreaW = 0, customAreaH = 0;
  std::string topology = "random";
  bool proofMode = false;
  double gridSpacing = 80.0;

  // ─── AODV specific parameters ───────────────────────────────
  uint32_t aodvRreqRetries = 5;
  uint32_t aodvNetDiameter = 35;
  double aodvPathDiscoveryTime = 5.6;   // seconds
  double aodvNetTraversalTime = 2.8;    // seconds

  // ─── OLSR specific parameters ───────────────────────────────
  double olsrTcInterval = 5.0;          // seconds
  double olsrHelloInterval = 1.0;       // seconds

  // ─── SLIC specific parameters (already have many, but allow override) ──
  // They are already passed via ns3::slic::SlicAodvRoutingProtocol::*

  CommandLine cmd;
  cmd.AddValue ("nodes",    "Node count",           nNodes);
  cmd.AddValue ("pause",    "Pause time (s)",       pauseTime);
  cmd.AddValue ("speed",    "Max speed (m/s)",      maxSpeed);
  cmd.AddValue ("flows",    "Number of flows",      nFlows);
  cmd.AddValue ("protocol", "aodv|slic-aodv|olsr",  protocol);
  cmd.AddValue ("phy",      "canonical|modern",     phyMode);
  cmd.AddValue ("lossModel","Loss model: canonical|modern", lossModel);
  cmd.AddValue ("run",      "Run number",           runNumber);
  cmd.AddValue ("duration", "Duration (s)",         duration);
  cmd.AddValue ("centralityInterval", "SLIC update (s), 0=auto", centralityInterval);
  cmd.AddValue ("alpha1",   "ISC weight",           alpha1);
  cmd.AddValue ("alpha2",   "SemiLocal weight",     alpha2);
  cmd.AddValue ("alpha3",   "LASP weight",          alpha3);
  cmd.AddValue ("verbose",  "Verbose logging",      verbose);
  cmd.AddValue ("output",   "Output CSV prefix",    outputPrefix);
  cmd.AddValue ("packetSize", "Packet size (bytes)", packetSize);
  cmd.AddValue ("dataRate", "Data rate/flow (bps)",  dataRate);
  cmd.AddValue ("areaW",    "Custom area width (m)",  customAreaW);
  cmd.AddValue ("areaH",    "Custom area height (m)", customAreaH);
  cmd.AddValue ("topology", "Node placement: random, line, grid, star", topology);
  cmd.AddValue ("proof",    "Enable proof mode (9-node grid, single flow 0->8)", proofMode);
  cmd.AddValue ("gridSpacing", "Spacing for grid topology (m)", gridSpacing);

  // AODV parameters
  cmd.AddValue ("aodvRreqRetries", "AODV RREQ retries", aodvRreqRetries);
  cmd.AddValue ("aodvNetDiameter", "AODV network diameter (hops)", aodvNetDiameter);
  cmd.AddValue ("aodvPathDiscoveryTime", "AODV path discovery time (s)", aodvPathDiscoveryTime);
  cmd.AddValue ("aodvNetTraversalTime", "AODV net traversal time (s)", aodvNetTraversalTime);

  // OLSR parameters
  cmd.AddValue ("olsrTcInterval", "OLSR TC interval (s)", olsrTcInterval);
  cmd.AddValue ("olsrHelloInterval", "OLSR HELLO interval (s)", olsrHelloInterval);

  cmd.Parse (argc, argv);

  // Override for proof mode
  if (proofMode)
    {
      nNodes = 9;
      topology = "grid";
      nFlows = 1;
      duration = 100;
      maxSpeed = 0;
      minSpeed = 0;
      pauseTime = 1000;
      std::cout << "\n*** PROOF MODE ENABLED ***\n"
                << "Proof mode: 9-node grid, static, single flow 0->8.\n"
                << "IMPORTANT: You must also add --ns3::slic::SlicAodvRoutingProtocol::WHop=0.0 --ns3::slic::SlicAodvRoutingProtocol::WCent=1.0\n"
                << "to make route selection depend only on centrality.\n";
    }

  // ─── Reproducibility ───────────────────────────────────────
  SeedManager::SetSeed (1);
  SeedManager::SetRun (runNumber);

  // ─── Auto-select centrality interval ───────────────────────
  if (centralityInterval <= 0.0)
    {
      if (maxSpeed >= 15.0)      centralityInterval = 15.0;
      else if (maxSpeed >= 8.0)  centralityInterval = 20.0;
      else if (maxSpeed >= 3.0)  centralityInterval = 30.0;
      else                       centralityInterval = 45.0;
    }

  // ─── Area selection ────────────────────────────────────────
  if (customAreaW > 0 && customAreaH > 0)
    {
      areaW = customAreaW;
      areaH = customAreaH;
    }
  else if (phyMode == "canonical")
    {
      areaW = 300; areaH = 1500;
    }
  else
    {
      if (nNodes <= 50)      { areaW = 1000; areaH = 1000; }
      else if (nNodes <= 75) { areaW = 1200; areaH = 1200; }
      else                   { areaW = 1500; areaH = 1500; }
    }

  if (topology != "random")
    {
      maxSpeed = 0.0;
      minSpeed = 0.0;
      pauseTime = 1000.0;
      std::cout << "Non-random topology: forcing speed=0, pause=1000s\n";
    }

  if (verbose)
    {
      LogComponentEnable ("SlicAodvRoutingProtocol", LOG_LEVEL_INFO);
      LogComponentEnable ("SlicAodvSimulation", LOG_LEVEL_INFO);
    }

  std::cout << "\n=== SLIC-AODV Simulation (v5) ===\n"
            << "Protocol: " << protocol << "  PHY: " << phyMode << "  Loss: " << lossModel << "\n"
            << "Topology: " << topology << "  GridSpacing: " << gridSpacing << "m\n"
            << "Nodes: " << nNodes << " Area: " << areaW << "x" << areaH << "\n"
            << "Speed: [" << minSpeed << ", " << maxSpeed << "] m/s  Pause: " << pauseTime << "s\n"
            << "Flows: " << nFlows << " PktSize: " << packetSize << "B  Rate: " << dataRate << " bps\n"
            << "Duration: " << duration << "s  Run: " << runNumber
            << "  CentInterval: " << centralityInterval << "s\n";

  // ─── Create nodes ──────────────────────────────────────────
  NodeContainer nodes;
  nodes.Create (nNodes);

  // ─── Mobility / Position Allocation ────────────────────────
  MobilityHelper mobility;
  Ptr<PositionAllocator> posAlloc;

  if (topology == "line")
    {
      Ptr<ListPositionAllocator> listAlloc = CreateObject<ListPositionAllocator>();
      double spacing = gridSpacing;
      for (uint32_t i = 0; i < nNodes; ++i)
        {
          double x = i * spacing;
          double y = 0.0;
          listAlloc->Add(Vector(x, y, 0.0));
        }
      posAlloc = listAlloc;
      areaW = (nNodes - 1) * spacing + 50;
      areaH = 100;
      std::cout << "Line topology: " << nNodes << " nodes spaced " << spacing << " m apart\n";
    }
  else if (topology == "grid")
    {
      int gridCols = static_cast<int>(std::ceil(std::sqrt(nNodes)));
      int gridRows = static_cast<int>(std::ceil(static_cast<double>(nNodes) / gridCols));
      double spacing = gridSpacing;
      Ptr<ListPositionAllocator> listAlloc = CreateObject<ListPositionAllocator>();
      for (int row = 0; row < gridRows; ++row)
        {
          for (int col = 0; col < gridCols; ++col)
            {
              uint32_t idx = row * gridCols + col;
              if (idx >= nNodes) break;
              double x = col * spacing;
              double y = row * spacing;
              listAlloc->Add(Vector(x, y, 0.0));
            }
        }
      posAlloc = listAlloc;
      areaW = gridCols * spacing;
      areaH = gridRows * spacing;
      std::cout << "Grid topology: " << gridCols << "x" << gridRows << " grid, spacing " << spacing << " m\n";
    }
  else if (topology == "star")
    {
      Ptr<ListPositionAllocator> listAlloc = CreateObject<ListPositionAllocator>();
      if (nNodes < 2) { std::cerr << "Star topology needs at least 2 nodes.\n"; return 1; }
      listAlloc->Add(Vector(0.0, 0.0, 0.0));
      double radius = gridSpacing;
      for (uint32_t i = 1; i < nNodes; ++i)
        {
          double angle = 2 * M_PI * (i-1) / (nNodes-1);
          double x = radius * std::cos(angle);
          double y = radius * std::sin(angle);
          listAlloc->Add(Vector(x, y, 0.0));
        }
      posAlloc = listAlloc;
      areaW = 2 * radius + 50;
      areaH = 2 * radius + 50;
      std::cout << "Star topology: center node 0, " << nNodes-1 << " leaves on radius " << radius << " m\n";
    }
  else // random
    {
      Ptr<RandomRectanglePositionAllocator> randAlloc = CreateObject<RandomRectanglePositionAllocator> ();
      randAlloc->SetAttribute ("X", StringValue ("ns3::UniformRandomVariable[Min=0|Max=" + std::to_string (areaW) + "]"));
      randAlloc->SetAttribute ("Y", StringValue ("ns3::UniformRandomVariable[Min=0|Max=" + std::to_string (areaH) + "]"));
      posAlloc = randAlloc;
    }

  mobility.SetPositionAllocator (posAlloc);
  std::ostringstream speedSS, pauseSS;
  speedSS << "ns3::UniformRandomVariable[Min=" << minSpeed << "|Max=" << maxSpeed << "]";
  pauseSS << "ns3::ConstantRandomVariable[Constant=" << pauseTime << "]";
  mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
    "Speed", StringValue (speedSS.str ()),
    "Pause", StringValue (pauseSS.str ()),
    "PositionAllocator", PointerValue (posAlloc));
  mobility.Install (nodes);

  // ─── WiFi ──────────────────────────────────────────────────
  YansWifiChannelHelper channel;
  channel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");

  // Select propagation loss model based on lossModel
  if (lossModel == "canonical")
    {
      channel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
    }
  else if (lossModel == "modern")
    {
      channel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
        "Exponent", DoubleValue (3.0),
        "ReferenceDistance", DoubleValue (1.0),
        "ReferenceLoss", DoubleValue (46.67));
      channel.AddPropagationLoss ("ns3::NakagamiPropagationLossModel",
        "m0", DoubleValue (1.5), "m1", DoubleValue (1.0), "m2", DoubleValue (1.0),
        "Distance1", DoubleValue (80.0), "Distance2", DoubleValue (200.0));
    }
  else
    {
      std::cerr << "Unknown lossModel: " << lossModel << ". Using canonical (Friis)." << std::endl;
      channel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
    }

  YansWifiPhyHelper phy;
  phy.SetChannel (channel.Create ());

  WifiHelper wifi;
  std::string wifiDataRate, wifiCtrlRate;

  if (phyMode == "canonical")
    {
      phy.Set ("TxPowerStart", DoubleValue (7.5));
      phy.Set ("TxPowerEnd", DoubleValue (7.5));
      wifi.SetStandard (WIFI_STANDARD_80211b);
      wifiDataRate = "DsssRate2Mbps";
      wifiCtrlRate = "DsssRate1Mbps";
      std::cout << "PHY: 802.11b  Data: 2Mbps  Ctrl: 1Mbps  Tx: 7.5dBm\n";
    }
  else if (phyMode == "modern")
    {
      phy.Set ("TxPowerStart", DoubleValue (16.0));
      phy.Set ("TxPowerEnd", DoubleValue (16.0));
      phy.Set ("RxSensitivity", DoubleValue (-82.0));
      wifi.SetStandard (WIFI_STANDARD_80211g);
      wifiDataRate = "ErpOfdmRate6Mbps";
      wifiCtrlRate = "ErpOfdmRate6Mbps";
      std::cout << "PHY: 802.11g  Data: 6Mbps  Ctrl: 6Mbps  Tx: 16dBm\n";
    }
  else
    {
      std::cerr << "Unknown phyMode: " << phyMode << ". Using canonical." << std::endl;
      phy.Set ("TxPowerStart", DoubleValue (7.5));
      phy.Set ("TxPowerEnd", DoubleValue (7.5));
      wifi.SetStandard (WIFI_STANDARD_80211b);
      wifiDataRate = "DsssRate2Mbps";
      wifiCtrlRate = "DsssRate1Mbps";
    }

  WifiMacHelper mac;
  mac.SetType ("ns3::AdhocWifiMac");
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
    "DataMode", StringValue (wifiDataRate),
    "ControlMode", StringValue (wifiCtrlRate));
  NetDeviceContainer devices = wifi.Install (phy, mac, nodes);

  // ─── Routing ───────────────────────────────────────────────
  InternetStackHelper internet;
  if (protocol == "slic-aodv")
    {
      slic::SlicAodvHelper slicAodv;
      slicAodv.SetWeights (alpha1, alpha2, alpha3);
      slicAodv.SetCentralityUpdateInterval (Seconds (centralityInterval));
      internet.SetRoutingHelper (slicAodv);
      std::cout << "Routing: SLIC-AODV (a=" << alpha1 << "," << alpha2 << "," << alpha3
                << " interval=" << centralityInterval << "s)\n";
    }
  else if (protocol == "aodv")
    {
      AodvHelper aodv;
      aodv.Set("RreqRetries", UintegerValue(aodvRreqRetries));
      aodv.Set("NetDiameter", UintegerValue(aodvNetDiameter));
      aodv.Set("PathDiscoveryTime", TimeValue(Seconds(aodvPathDiscoveryTime)));
      aodv.Set("NetTraversalTime", TimeValue(Seconds(aodvNetTraversalTime)));
      internet.SetRoutingHelper (aodv);
      std::cout << "Routing: Standard AODV (RreqRetries=" << aodvRreqRetries
                << ", NetDiameter=" << aodvNetDiameter
                << ", PathDiscoveryTime=" << aodvPathDiscoveryTime << "s)\n";
    }
  else if (protocol == "olsr")
    {
      OlsrHelper olsr;
      olsr.Set("TcInterval", TimeValue(Seconds(olsrTcInterval)));
      olsr.Set("HelloInterval", TimeValue(Seconds(olsrHelloInterval)));
      internet.SetRoutingHelper (olsr);
      std::cout << "Routing: OLSR (TcInterval=" << olsrTcInterval
                << "s, HelloInterval=" << olsrHelloInterval << "s)\n";
    }
  else
    {
      std::cerr << "Unknown protocol: " << protocol << "\n";
      return 1;
    }

  internet.Install (nodes);
  Ipv4AddressHelper address;
  address.SetBase ("10.1.0.0", "255.255.0.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  // ─── Traffic ───────────────────────────────────────────────
  uint16_t port = 9;
  uint32_t flowsCreated = 0;

  if (proofMode)
    {
      // Fixed flow: node 0 -> node 8
      uint32_t src = 0, dst = 8;
      Ipv4Address dstAddr = interfaces.GetAddress (dst);
      // Sink
      PacketSinkHelper sink ("ns3::UdpSocketFactory",
                             InetSocketAddress (Ipv4Address::GetAny (), port));
      ApplicationContainer sinkApp = sink.Install (nodes.Get (dst));
      sinkApp.Start (Seconds (0.0));
      sinkApp.Stop (Seconds (duration));
      // Source
      OnOffHelper source ("ns3::UdpSocketFactory",
                          InetSocketAddress (dstAddr, port));
      source.SetAttribute ("DataRate", DataRateValue (DataRate (static_cast<uint64_t> (dataRate))));
      source.SetAttribute ("PacketSize", UintegerValue (packetSize));
      source.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
      source.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
      ApplicationContainer srcApp = source.Install (nodes.Get (src));
      srcApp.Start (Seconds (30.0));
      srcApp.Stop (Seconds (duration - 1.0));
      flowsCreated = 1;
      std::cout << "Proof flow: " << src << "->" << dst << " @t=30s\n";

      // Schedule multiple route checks (at 35s, 45s, 55s)
      for (double t : {35.0, 45.0, 55.0})
        {
          Simulator::Schedule (Seconds (t), [&, t]()
          {
              Ptr<Ipv4RoutingProtocol> rp = nodes.Get(0)->GetObject<Ipv4RoutingProtocol>();
              Ptr<slic::SlicAodvRoutingProtocol> slic = DynamicCast<slic::SlicAodvRoutingProtocol>(rp);
              if (slic)
              {
                  Ipv4Address dstAddrCheck = interfaces.GetAddress(8);
                  slic::RouteEntry rt;
                  if (slic->LookupRoute(dstAddrCheck, rt))
                  {
                      std::cout << "\n[PROOF at " << t << "s] Route from node 0 to " << dstAddrCheck << ":\n"
                                << "  Next hop = " << rt.nextHop << "\n"
                                << "  Hop count = " << (int)rt.hopCount << "\n"
                                << "  Path min centrality = " << rt.pathMinCentrality << "\n"
                                << "  Route score = " << rt.routeScore << "\n";
                      Ipv4Address centerAddr = interfaces.GetAddress(4); // node 4 is center in 3x3 grid
                      if (rt.nextHop == centerAddr)
                          std::cout << "*** SUCCESS: Route goes through the high‑centrality center node! ***\n";
                      else
                          std::cout << "*** FAILURE: Route does NOT go through the center node. ***\n";
                  }
                  else
                  {
                      std::cout << "[PROOF at " << t << "s] No route to " << dstAddrCheck << "\n";
                  }
              }
          });
        }
    }
  else
    {
      // Random flows
      Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable> ();
      rng->SetStream (runNumber + 100);
      std::set<std::pair<uint32_t, uint32_t>> usedPairs;
      for (uint32_t i = 0; i < nFlows; ++i)
        {
          uint32_t src, dst;
          uint32_t attempts = 0;
          do {
            src = rng->GetInteger (0, nNodes - 1);
            dst = rng->GetInteger (0, nNodes - 1);
            attempts++;
          } while ((src == dst || usedPairs.count ({src, dst})) && attempts < 1000);
          if (attempts >= 1000) break;
          usedPairs.insert ({src, dst});
          Ipv4Address dstAddr = interfaces.GetAddress (dst);
          PacketSinkHelper sink ("ns3::UdpSocketFactory",
                                 InetSocketAddress (Ipv4Address::GetAny (), port + i));
          ApplicationContainer sinkApp = sink.Install (nodes.Get (dst));
          sinkApp.Start (Seconds (0.0));
          sinkApp.Stop (Seconds (duration));
          OnOffHelper source ("ns3::UdpSocketFactory",
                              InetSocketAddress (dstAddr, port + i));
          source.SetAttribute ("DataRate", DataRateValue (DataRate (static_cast<uint64_t> (dataRate))));
          source.SetAttribute ("PacketSize", UintegerValue (packetSize));
          source.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
          source.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
          double startTime = 30.0 + i * 0.5;
          ApplicationContainer srcApp = source.Install (nodes.Get (src));
          srcApp.Start (Seconds (startTime));
          srcApp.Stop (Seconds (duration - 1.0));
          flowsCreated++;
          std::cout << "Flow " << i << ": " << src << "->" << dst << " @t=" << startTime << "s\n";
        }
    }

  std::cout << "Created " << flowsCreated << " flows\nStarting simulation...\n";

  // ─── FlowMonitor ───────────────────────────────────────────
  FlowMonitorHelper fmHelper;
  Ptr<FlowMonitor> fm = fmHelper.InstallAll ();

  // ─── Run ───────────────────────────────────────────────────
  Simulator::Stop (Seconds (duration));
  Simulator::Run ();

  // ─── Collect metrics ───────────────────────────────────────
  fm->CheckForLostPackets ();
  FlowMonitor::FlowStatsContainer stats = fm->GetFlowStats ();

  uint64_t totalTx = 0, totalRx = 0, totalLost = 0;
  double totalDelaySum_ms = 0.0, totalJitterSum_ms = 0.0;
  uint64_t totalRxForDelay = 0, totalRxForJitter = 0;
  double totalThroughput = 0.0;
  uint32_t activeFlows = 0;

  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (fmHelper.GetClassifier ());
  for (auto& kv : stats)
    {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (kv.first);
      if (proofMode)
        {
          // Accept any flow (only one)
        }
      else if (t.destinationPort < port || t.destinationPort >= static_cast<uint16_t> (port + nFlows))
        continue;

      uint64_t tx = kv.second.txPackets;
      uint64_t rx = kv.second.rxPackets;
      totalTx += tx;
      totalRx += rx;
      totalLost += kv.second.lostPackets;
      if (rx > 0)
        {
          totalDelaySum_ms += kv.second.delaySum.GetMilliSeconds ();
          totalJitterSum_ms += kv.second.jitterSum.GetMilliSeconds ();
          totalRxForDelay += rx;
          totalRxForJitter += (rx > 1) ? (rx - 1) : 0;
          Time dur = kv.second.timeLastRxPacket - kv.second.timeFirstRxPacket;
          if (dur.GetSeconds () > 0)
            totalThroughput += (rx * packetSize * 8.0) / dur.GetSeconds () / 1000.0;
          activeFlows++;
        }
    }

  double pdr = (totalTx > 0) ? (double)totalRx / totalTx * 100.0 : 0.0;
  double avgDelay = (totalRxForDelay > 0) ? totalDelaySum_ms / totalRxForDelay : 0.0;
  double avgJitter = (totalRxForJitter > 0) ? totalJitterSum_ms / totalRxForJitter : 0.0;
  double avgThroughputPerFlow = (activeFlows > 0) ? totalThroughput / activeFlows : 0.0;

  std::cout << "\n=== Results ===\n"
            << "Protocol:           " << protocol << "\n"
            << "PHY:                " << phyMode << "\n"
            << "Loss model:         " << lossModel << "\n"
            << "Run:                " << runNumber << "\n"
            << std::fixed << std::setprecision (2)
            << "PDR:                " << pdr << " %\n"
            << "Avg Delay:          " << avgDelay << " ms\n"
            << "Avg Jitter:         " << avgJitter << " ms\n"
            << "Agg Throughput:     " << totalThroughput << " kbps\n"
            << "Avg Tput/flow:      " << avgThroughputPerFlow << " kbps\n"
            << "Tx Packets:         " << totalTx << "\n"
            << "Rx Packets:         " << totalRx << "\n"
            << "Lost Packets:       " << totalLost << "\n"
            << "Active Flows:       " << activeFlows << "\n\n";

  // ─── Routing table dump for proof mode (optional) ─────────
  if (proofMode)
    {
      std::cout << "\n=== PROOF MODE ROUTING TABLE FOR NODE 0 (after simulation) ===\n";
      Ptr<Ipv4RoutingProtocol> rp = nodes.Get(0)->GetObject<Ipv4RoutingProtocol>();
      Ptr<slic::SlicAodvRoutingProtocol> slic = DynamicCast<slic::SlicAodvRoutingProtocol>(rp);
      if (slic)
        {
          std::cout << "Node 0 centrality: " << slic->GetMyCentrality() << "\n";
          Ptr<OutputStreamWrapper> stream = Create<OutputStreamWrapper>(&std::cout);
          slic->PrintRoutingTable(stream);
        }
    }

  // ─── CSV output ────────────────────────────────────────────
  std::string csvFile = outputPrefix + ".csv";
  std::ifstream check (csvFile);
  bool writeHeader = !check.good ();
  check.close ();
  std::ofstream out (csvFile, std::ios::app);
  if (writeHeader)
    out << "protocol,phy,lossModel,nodes,pause,speed,flows,centrality_interval,"
        << "run,pdr,avg_delay_ms,avg_jitter_ms,"
        << "agg_throughput_kbps,avg_throughput_per_flow_kbps,"
        << "tx_packets,rx_packets,lost_packets,active_flows,"
        << "alpha1,alpha2,alpha3,packetSize,dataRate,area,topology,gridSpacing,"
        << "aodvRreqRetries,aodvNetDiameter,aodvPathDiscoveryTime,"
        << "olsrTcInterval,olsrHelloInterval\n";
  out << std::fixed << std::setprecision (4)
      << protocol << "," << phyMode << "," << lossModel << "," << nNodes << "," << pauseTime << ","
      << maxSpeed << "," << nFlows << "," << centralityInterval << ","
      << runNumber << "," << pdr << "," << avgDelay << "," << avgJitter << ","
      << totalThroughput << "," << avgThroughputPerFlow << ","
      << totalTx << "," << totalRx << "," << totalLost << "," << activeFlows << ","
      << alpha1 << "," << alpha2 << "," << alpha3 << ","
      << packetSize << "," << dataRate << ","
      << areaW << "x" << areaH << "," << topology << "," << gridSpacing << ","
      << aodvRreqRetries << "," << aodvNetDiameter << "," << aodvPathDiscoveryTime << ","
      << olsrTcInterval << "," << olsrHelloInterval << "\n";
  out.close ();

  std::string xmlFile = outputPrefix + "-" + protocol + "-" + phyMode
                        + "-run" + std::to_string (runNumber) + ".xml";
  fm->SerializeToXmlFile (xmlFile, true, true);

  Simulator::Destroy ();
  return 0;
}