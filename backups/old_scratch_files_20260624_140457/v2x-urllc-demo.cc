// v2x-urllc-demo.cc  (Path-A patched)
// Custom 5G NR V2X scenario: 1 gNB + N vehicle UEs on a highway.
// Traffic mix: URLLC-only UEs (safety beacons) + eMBB-only UEs (infotainment).
// Split-by-UE-index enables per-RNTI scheduler classification for NrMacSchedulerTdmaAi.
//
// Author: srmap  |  NS-3.41 + 5G-LENA v3.0
//
// Run (baseline):
//   ./ns3 run "scratch/v2x-urllc-demo --nUes=20 --simTime=5.0"
// Run (TdmaAi, 50/50 bias):
//   ./ns3 run "scratch/v2x-urllc-demo --scheduler=ns3::NrMacSchedulerTdmaAi 
//              --nUes=20 --urllcOnlyUes=10 --urllcFraction=0.5 --simTime=5.0"
//
// Outputs a CSV: v2x-urllc-results.csv

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/nr-module.h"
#include "ns3/nr-helper.h"
#include "ns3/nr-point-to-point-epc-helper.h"
#include "ns3/ideal-beamforming-algorithm.h"
#include "ns3/antenna-module.h"
#include "ns3/config-store.h"
#include "ns3/nr-mac-scheduler-tdma-ai.h"   // NEW: our custom scheduler
#include "ns3/lte-ue-rrc.h"                 // NEW: for GetRnti()

#include <fstream>
#include <iomanip>
#include <map>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("V2xUrllcDemo");

// ----------------------------------------------------------------------------
// Helper scheduled post-attach: tell the TdmaAi scheduler which RNTIs are URLLC.
// No-op (with warning) if the running scheduler is not TdmaAi.
// ----------------------------------------------------------------------------
static void
RegisterUrllcRntis(NetDeviceContainer ueDevs,
                   NetDeviceContainer gnbDevs,
                   uint32_t urllcCount)
{
    Ptr<NrGnbNetDevice> gnbDev = DynamicCast<NrGnbNetDevice>(gnbDevs.Get(0));
    Ptr<NrMacScheduler> schedBase = gnbDev->GetScheduler(0);  // bwpId 0
    Ptr<NrMacSchedulerTdmaAi> sched = DynamicCast<NrMacSchedulerTdmaAi>(schedBase);
    if (!sched)
    {
        std::cout << "[RNTI-REG] scheduler is not TdmaAi -- skipping RNTI registration"
                  << std::endl;
        return;
    }
    sched->ClearUrllcRntis();
    uint32_t registered = 0;
    for (uint32_t i = 0; i < urllcCount && i < ueDevs.GetN(); ++i)
    {
        Ptr<NrUeNetDevice> ueDev = DynamicCast<NrUeNetDevice>(ueDevs.Get(i));
        uint16_t rnti = ueDev->GetRrc()->GetRnti();
        if (rnti != 0)
        {
            sched->AddUrllcRnti(rnti);
            ++registered;
        }
    }
    std::cout << "[RNTI-REG] registered " << registered << "/" << urllcCount
              << " URLLC RNTIs with TdmaAi scheduler" << std::endl;
}

int
main(int argc, char* argv[])
{
    // ---------------- Default parameters ----------------
    uint16_t nUes          = 10;
    double   speed         = 22.0;
    double   simTime       = 5.0;
    double   gNbHeight     = 25.0;
    double   ueHeight      = 1.5;
    double   centralFreq   = 3.5e9;
    double   bandwidth     = 100e6;
    uint16_t numerology    = 2;
    double   txPowerGnb    = 30.0;
    double   txPowerUe     = 23.0;
    std::string scheduler  = "ns3::NrMacSchedulerTdmaRR";
    std::string outFile    = "v2x-urllc-results.csv";
    bool     enableInfotainment = true;

    // NEW: Path-A controls
    uint32_t urllcOnlyUes  = 0;      // 0 = auto (nUes/2)
    double   urllcFraction = 0.5;    // TdmaAi UrllcSymbolFraction

    // ---------------- Command-line ----------------
    CommandLine cmd(__FILE__);
    cmd.AddValue("nUes",                "Number of vehicle UEs", nUes);
    cmd.AddValue("speed",               "Vehicle speed in m/s", speed);
    cmd.AddValue("simTime",             "Simulation time (s)", simTime);
    cmd.AddValue("scheduler",           "NR MAC scheduler TypeId", scheduler);
    cmd.AddValue("bandwidth",           "Channel bandwidth in Hz", bandwidth);
    cmd.AddValue("numerology",          "NR numerology (0..4)", numerology);
    cmd.AddValue("outFile",             "Output CSV file", outFile);
    cmd.AddValue("enableInfotainment",  "Enable eMBB infotainment flow", enableInfotainment);
    // NEW flags
    cmd.AddValue("urllcOnlyUes",  "Number of URLLC-only UEs (0 = auto = nUes/2)", urllcOnlyUes);
    cmd.AddValue("urllcFraction", "TdmaAi UrllcSymbolFraction [0..1]", urllcFraction);
    cmd.Parse(argc, argv);

    // Auto-pick URLLC split if unset / out of range
    if (urllcOnlyUes == 0 || urllcOnlyUes > nUes)
    {
        urllcOnlyUes = nUes / 2;
    }
    const uint32_t embbUes = nUes - urllcOnlyUes;

    // NEW: push TdmaAi attribute into ConfigStore BEFORE InstallGnbDevice
    // (scheduler is instantiated inside InstallGnbDevice; attribute must be set prior).
    if (scheduler == "ns3::NrMacSchedulerTdmaAi")
    {
        Config::SetDefault("ns3::NrMacSchedulerTdmaAi::UrllcSymbolFraction",
                           DoubleValue(urllcFraction));
    }

    // ---------------- Nodes ----------------
    NodeContainer gnbNodes;
    gnbNodes.Create(1);

    NodeContainer ueNodes;
    ueNodes.Create(nUes);

    // ---------------- Mobility: gNB fixed, UEs on a highway ----------------
    MobilityHelper mobilityGnb;
    Ptr<ListPositionAllocator> gnbPos = CreateObject<ListPositionAllocator>();
    gnbPos->Add(Vector(0.0, 0.0, gNbHeight));
    mobilityGnb.SetPositionAllocator(gnbPos);
    mobilityGnb.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobilityGnb.Install(gnbNodes);

    MobilityHelper mobilityUe;
    mobilityUe.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    Ptr<ListPositionAllocator> uePos = CreateObject<ListPositionAllocator>();
    for (uint16_t i = 0; i < nUes; ++i)
    {
        double x = -100.0 + 25.0 * i;
        double y = 50.0;
        uePos->Add(Vector(x, y, ueHeight));
    }
    mobilityUe.SetPositionAllocator(uePos);
    mobilityUe.Install(ueNodes);
    for (uint16_t i = 0; i < nUes; ++i)
    {
        ueNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>()
            ->SetVelocity(Vector(speed, 0.0, 0.0));
    }

    // ---------------- NR Helper setup ----------------
    Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
    Ptr<NrHelper>                nrHelper  = CreateObject<NrHelper>();
    nrHelper->SetEpcHelper(epcHelper);

    nrHelper->SetSchedulerTypeId(TypeId::LookupByName(scheduler));

    Ptr<IdealBeamformingHelper> idealBfHelper = CreateObject<IdealBeamformingHelper>();
    idealBfHelper->SetAttribute("BeamformingMethod",
                                TypeIdValue(DirectPathBeamforming::GetTypeId()));
    nrHelper->SetBeamformingHelper(idealBfHelper);

    // ---------------- Spectrum / BWP config ----------------
    CcBwpCreator ccBwpCreator;
    const uint8_t numCcPerBand = 1;
    BandwidthPartInfoPtrVector allBwps;
    CcBwpCreator::SimpleOperationBandConf bandConf(centralFreq, bandwidth, numCcPerBand,
                                                   BandwidthPartInfo::UMa);
    OperationBandInfo band = ccBwpCreator.CreateOperationBandContiguousCc(bandConf);
    nrHelper->InitializeOperationBand(&band);
    allBwps = CcBwpCreator::GetAllBwps({band});

    nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
    nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(1));
    nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(2));

    nrHelper->SetGnbPhyAttribute("TxPower", DoubleValue(txPowerGnb));
    nrHelper->SetUePhyAttribute("TxPower",  DoubleValue(txPowerUe));

    NetDeviceContainer gnbDevs = nrHelper->InstallGnbDevice(gnbNodes, allBwps);
    NetDeviceContainer ueDevs  = nrHelper->InstallUeDevice(ueNodes, allBwps);

    nrHelper->GetGnbPhy(gnbDevs.Get(0), 0)
        ->SetAttribute("Numerology", UintegerValue(numerology));

    for (auto it = gnbDevs.Begin(); it != gnbDevs.End(); ++it)
        DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    for (auto it = ueDevs.Begin(); it != ueDevs.End(); ++it)
        DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();

    // ---------------- Internet + Remote host ----------------
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create(1);
    Ptr<Node> remoteHost = remoteHostContainer.Get(0);

    InternetStackHelper internet;
    internet.Install(remoteHostContainer);
    internet.Install(ueNodes);

    PointToPointHelper p2ph;
    p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2ph.SetDeviceAttribute("Mtu", UintegerValue(2500));
    p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.000)));

    Ptr<Node> pgw = epcHelper->GetPgwNode();
    NetDeviceContainer internetDevs = p2ph.Install(pgw, remoteHost);

    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetIfs = ipv4h.Assign(internetDevs);

    Ipv4StaticRoutingHelper routing;
    Ptr<Ipv4StaticRouting> rhStatic = routing.GetStaticRouting(remoteHost->GetObject<Ipv4>());
    rhStatic->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

    Ipv4InterfaceContainer ueIfs = epcHelper->AssignUeIpv4Address(ueDevs);

    // Build UE-IP -> UE-index map for CSV classification
    std::map<Ipv4Address, uint32_t> ueIpToIdx;
    for (uint32_t i = 0; i < ueIfs.GetN(); ++i)
    {
        ueIpToIdx[ueIfs.GetAddress(i)] = i;
    }

    for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
        Ptr<Ipv4StaticRouting> ueStatic = routing.GetStaticRouting(
            ueNodes.Get(i)->GetObject<Ipv4>());
        ueStatic->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    nrHelper->AttachToClosestEnb(ueDevs, gnbDevs);

    // NEW: schedule RNTI registration after RRC attach settles
    if (scheduler == "ns3::NrMacSchedulerTdmaAi")
    {
        Simulator::Schedule(Seconds(0.3), &RegisterUrllcRntis,
                            ueDevs, gnbDevs, urllcOnlyUes);
    }

    // ---------------- Applications (split per UE index) ----------------
    uint16_t dlPortUrllc = 1234;
    uint16_t dlPortEmbb  = 1235;

    ApplicationContainer clientApps;
    ApplicationContainer serverApps;

    for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
        if (i < urllcOnlyUes)
        {
            // URLLC-only UE: 200B @ 10 Hz  (~16 kbps, latency-critical)
            UdpServerHelper urllcSrv(dlPortUrllc);
            serverApps.Add(urllcSrv.Install(ueNodes.Get(i)));

            UdpClientHelper urllcCli(ueIfs.GetAddress(i), dlPortUrllc);
            urllcCli.SetAttribute("Interval",   TimeValue(Seconds(0.1)));
            urllcCli.SetAttribute("PacketSize", UintegerValue(200));
            urllcCli.SetAttribute("MaxPackets", UintegerValue(1000000));
            clientApps.Add(urllcCli.Install(remoteHost));
        }
        else if (enableInfotainment)
        {
            // eMBB-only UE: 1 Mbps continuous
            UdpServerHelper embbSrv(dlPortEmbb);
            serverApps.Add(embbSrv.Install(ueNodes.Get(i)));

            UdpClientHelper embbCli(ueIfs.GetAddress(i), dlPortEmbb);
            embbCli.SetAttribute("Interval",   TimeValue(Seconds(0.001)));
            embbCli.SetAttribute("PacketSize", UintegerValue(125));
            embbCli.SetAttribute("MaxPackets", UintegerValue(1000000));
            clientApps.Add(embbCli.Install(remoteHost));
        }
    }

    serverApps.Start(Seconds(0.1));
    clientApps.Start(Seconds(0.2));
    serverApps.Stop(Seconds(simTime));
    clientApps.Stop(Seconds(simTime));

    // ---------------- Flow Monitor ----------------
    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor = flowHelper.InstallAll();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // ---------------- Collect results ----------------
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    std::ofstream csv;
    csv.open(outFile);
    csv << "flowId,srcAddr,dstAddr,dstPort,trafficType,ueClass,ueIdx,"
        << "txPackets,rxPackets,lossPercent,"
        << "throughputMbps,meanDelayMs,meanJitterMs\n";

    double   aggUrllcTput   = 0.0;
    double   aggEmbbTput    = 0.0;
    uint32_t nFlows         = 0;
    double   urllcDelaySum  = 0.0;
    double   urllcLossSum   = 0.0;
    uint32_t urllcFlowCount = 0;

    for (auto& kv : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(kv.first);
        auto& s = kv.second;

        // Skip 5G core signaling flows (GTP-C, GTP-U, etc.)
        if (t.destinationPort != dlPortUrllc && t.destinationPort != dlPortEmbb)
            continue;

        std::string type = (t.destinationPort == dlPortUrllc) ? "URLLC" : "eMBB";

        // Resolve UE index from destination IP
        uint32_t ueIdx = 9999;
        auto itIdx = ueIpToIdx.find(t.destinationAddress);
        if (itIdx != ueIpToIdx.end()) ueIdx = itIdx->second;
        std::string ueClass = (ueIdx < urllcOnlyUes) ? "URLLC_UE" : "eMBB_UE";

        double duration = (s.timeLastRxPacket - s.timeFirstTxPacket).GetSeconds();
        double tputMbps = (duration > 0) ? (s.rxBytes * 8.0 / duration / 1e6) : 0.0;
        double meanDelayMs  = (s.rxPackets > 0)
                              ? (s.delaySum.GetSeconds() * 1000.0 / s.rxPackets) : 0.0;
        double meanJitterMs = (s.rxPackets > 1)
                              ? (s.jitterSum.GetSeconds() * 1000.0 / (s.rxPackets - 1)) : 0.0;
        double lossPct = (s.txPackets > 0)
                          ? (100.0 * (s.txPackets - s.rxPackets) / s.txPackets) : 0.0;

        csv << kv.first << ","
            << t.sourceAddress << "," << t.destinationAddress << ","
            << t.destinationPort << ","
            << type << "," << ueClass << "," << ueIdx << ","
            << s.txPackets << "," << s.rxPackets << ","
            << std::fixed << std::setprecision(3) << lossPct << ","
            << tputMbps << "," << meanDelayMs << "," << meanJitterMs << "\n";

        ++nFlows;
        if (type == "URLLC")
        {
            aggUrllcTput  += tputMbps;
            urllcDelaySum += meanDelayMs;
            urllcLossSum  += lossPct;
            ++urllcFlowCount;
        }
        else
        {
            aggEmbbTput += tputMbps;
        }
    }
    csv.close();

    std::cout << "\n========= V2X URLLC SUMMARY =========\n";
    std::cout << "Vehicles (UEs):    " << nUes
              << "  (URLLC=" << urllcOnlyUes << ", eMBB=" << embbUes << ")\n";
    std::cout << "Speed (m/s):       " << speed << "  (" << speed*3.6 << " km/h)\n";
    std::cout << "Scheduler:         " << scheduler << "\n";
    if (scheduler == "ns3::NrMacSchedulerTdmaAi")
    {
        std::cout << "UrllcFraction:     " << urllcFraction << "\n";
    }
    std::cout << "Flows tallied:     " << nFlows << "\n";
    std::cout << "URLLC  Tput:       " << aggUrllcTput << " Mbps\n";
    std::cout << "eMBB   Tput:       " << aggEmbbTput  << " Mbps\n";
    if (urllcFlowCount > 0)
    {
        std::cout << "URLLC  Mean Delay: " << (urllcDelaySum / urllcFlowCount) << " ms\n";
        std::cout << "URLLC  Mean Loss:  " << (urllcLossSum  / urllcFlowCount) << " %\n";
    }
    std::cout << "CSV output:        " << outFile << "\n";
    std::cout << "=====================================\n";

    Simulator::Destroy();
    return 0;
}
