// v2x-urllc-ai.cc
// AI-augmented 5G NR V2X scenario using ns3-ai (Gym interface).
// Extends v2x-urllc-demo.cc by exchanging {state, action, reward} with a
// Python DRL agent every decision interval (default 10 ms).
//
// STATE  (per decision step):
//   [nUes, aggUrllcTxRate, aggEmbbTxRate, meanUrllcDelayMs, p99UrllcDelayMs,
//    urllcLossPct, embbLossPct, aggThroughputMbps]   -> 8 floats
//
// ACTION:
//   [bwpSplitPct, mcsHint]   -> 2 uint32
//     bwpSplitPct  : 0..100  (percent of PRBs reserved for URLLC in next window)
//     mcsHint      : 0..27   (advisory MCS ceiling for eMBB)
//
// REWARD:
//   r = -p99UrllcDelayMs + 0.1 * aggEmbbTputMbps - 5.0 * urllcLossPct
//
// The C++ side does NOT enforce the action on the scheduler in this first
// version (that requires 5G-LENA-internal hooks). Instead, the action is
// recorded to CSV so we can validate the full training loop end-to-end,
// then wire the physical enforcement in iteration 2.
//
// Run:
//   Python side: python3 experiments/train_v2x_drl.py
//   (Python launches ns-3 automatically through ns3ai_utils.)
//
// Author: srmap | Day 3

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

#include "ns3/ai-module.h"          // ns3-ai
#include <ns3ai_msg_interface.h>    // Ns3AiMsgInterface

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <vector>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("V2xUrllcAi");

// ---------- Shared-memory message structs (POD only) ----------
struct V2xEnvState
{
    uint32_t nUes;
    float    aggUrllcTxRate;       // Mbps
    float    aggEmbbTxRate;        // Mbps
    float    meanUrllcDelayMs;
    float    p99UrllcDelayMs;
    float    urllcLossPct;
    float    embbLossPct;
    float    aggThroughputMbps;
    float    reward;               // reward for PREVIOUS action
    uint8_t  done;                 // 1 on last step
};

struct V2xEnvAction
{
    uint32_t bwpSplitPct;          // 0..100
    uint32_t mcsHint;              // 0..27
};

// ---------- Globals for stats sliding window ----------
static Ptr<FlowMonitor>             g_monitor;
static Ptr<Ipv4FlowClassifier>      g_classifier;
static uint16_t                     g_portUrllc = 1234;
static uint16_t                     g_portEmbb  = 1235;
static uint32_t                     g_stepIdx   = 0;

static uint32_t                     g_prevRxUrllc = 0;
static uint32_t                     g_prevRxEmbb  = 0;
static uint32_t                     g_prevTxUrllc = 0;
static uint32_t                     g_prevTxEmbb  = 0;
static double                       g_prevDelayUrllcSum = 0.0;
static uint32_t                     g_prevDelayUrllcCnt = 0;

// Last action (logged to CSV)
static uint32_t                     g_lastBwpSplitPct = 50;
static uint32_t                     g_lastMcsHint     = 14;

static std::ofstream                g_trace;

// ---------- Compute window-level stats ----------
static void
ComputeStats(V2xEnvState& s, uint32_t nUes, double windowSec)
{
    g_monitor->CheckForLostPackets();
    auto stats = g_monitor->GetFlowStats();

    uint32_t txU = 0, rxU = 0, txE = 0, rxE = 0;
    double   delaySumU = 0.0;   uint32_t delayCntU = 0;
    std::vector<double> urllcPerFlowDelayMs;
    double   rxBytesU = 0.0, rxBytesE = 0.0;

    for (auto& kv : stats)
    {
        auto t = g_classifier->FindFlow(kv.first);
        auto& f = kv.second;
        bool isU = (t.destinationPort == g_portUrllc);
        bool isE = (t.destinationPort == g_portEmbb);
        if (!isU && !isE) continue;

        if (isU) { txU += f.txPackets; rxU += f.rxPackets;
                   rxBytesU += f.rxBytes;
                   delaySumU += f.delaySum.GetSeconds();
                   delayCntU += f.rxPackets;
                   if (f.rxPackets > 0)
                       urllcPerFlowDelayMs.push_back(
                           f.delaySum.GetSeconds() * 1000.0 / f.rxPackets); }
        else     { txE += f.txPackets; rxE += f.rxPackets;
                   rxBytesE += f.rxBytes; }
    }

    // Deltas over this window
    uint32_t dTxU = (txU > g_prevTxUrllc) ? txU - g_prevTxUrllc : 0;
    uint32_t dRxU = (rxU > g_prevRxUrllc) ? rxU - g_prevRxUrllc : 0;
    uint32_t dTxE = (txE > g_prevTxEmbb)  ? txE - g_prevTxEmbb  : 0;
    uint32_t dRxE = (rxE > g_prevRxEmbb)  ? rxE - g_prevRxEmbb  : 0;

    double urllcLossPct = (dTxU > 0) ? 100.0 * (dTxU - dRxU) / dTxU : 0.0;
    double embbLossPct  = (dTxE > 0) ? 100.0 * (dTxE - dRxE) / dTxE : 0.0;

    // Mean delay: use cumulative per-flow average (stable estimator)
    double meanDelayUrllcMs = 0.0;
    if (delayCntU > 0)
        meanDelayUrllcMs = delaySumU * 1000.0 / delayCntU;

    // p99 across per-flow means (proxy for worst-vehicle latency)
    double p99DelayUrllcMs = 0.0;
    if (!urllcPerFlowDelayMs.empty())
    {
        std::sort(urllcPerFlowDelayMs.begin(), urllcPerFlowDelayMs.end());
        size_t idx = static_cast<size_t>(
            std::ceil(0.99 * urllcPerFlowDelayMs.size())) - 1;
        idx = std::min(idx, urllcPerFlowDelayMs.size() - 1);
        p99DelayUrllcMs = urllcPerFlowDelayMs[idx];
    }

    s.nUes               = nUes;
    s.aggUrllcTxRate     = (rxBytesU * 8.0 / 1e6) / std::max(windowSec, 1e-3);
    s.aggEmbbTxRate      = (rxBytesE * 8.0 / 1e6) / std::max(windowSec, 1e-3);
    s.meanUrllcDelayMs   = static_cast<float>(meanDelayUrllcMs);
    s.p99UrllcDelayMs    = static_cast<float>(p99DelayUrllcMs);
    s.urllcLossPct       = static_cast<float>(urllcLossPct);
    s.embbLossPct        = static_cast<float>(embbLossPct);
    s.aggThroughputMbps  = s.aggUrllcTxRate + s.aggEmbbTxRate;

    // Reward: minimize URLLC tail latency + loss, reward eMBB throughput
    double reward = -static_cast<double>(p99DelayUrllcMs)
                  + 0.1 * s.aggEmbbTxRate
                  - 5.0 * urllcLossPct;
    s.reward = static_cast<float>(reward);
    s.done   = 0;

    g_prevTxUrllc = txU;  g_prevRxUrllc = rxU;
    g_prevTxEmbb  = txE;  g_prevRxEmbb  = rxE;
    g_prevDelayUrllcSum = delaySumU;
    g_prevDelayUrllcCnt = delayCntU;
}

// ---------- Per-step callback: exchange with Python agent ----------
static void
DecisionStep(double stepInterval, uint32_t nUes, double simTime)
{
    auto msgIf = Ns3AiMsgInterface::Get();
    auto* send = msgIf->GetCpp2PyStruct();   // we write this
    auto* recv = msgIf->GetPy2CppStruct();   // we read this

    // ---- 1. Compute current state + reward for previous action ----
    V2xEnvState st{};
    ComputeStats(st, nUes, stepInterval);
    if (Simulator::Now().GetSeconds() + stepInterval >= simTime - 1e-6)
        st.done = 1;

    static_assert(sizeof(V2xEnvState) <= sizeof(*send),
                  "State too large for shmem slot");
    std::memcpy(send, &st, sizeof(st));

    msgIf->CppSendBegin();
    msgIf->CppSendEnd();

    // ---- 2. Block for action ----
    msgIf->CppRecvBegin();
    V2xEnvAction act{};
    std::memcpy(&act, recv, sizeof(act));
    msgIf->CppRecvEnd();

    g_lastBwpSplitPct = std::min<uint32_t>(act.bwpSplitPct, 100);
    g_lastMcsHint     = std::min<uint32_t>(act.mcsHint, 27);

    // ---- 3. Log the (s, a, r) tuple ----
    g_trace << g_stepIdx << ","
            << Simulator::Now().GetSeconds() << ","
            << st.nUes << ","
            << st.aggUrllcTxRate << ","
            << st.aggEmbbTxRate  << ","
            << st.meanUrllcDelayMs << ","
            << st.p99UrllcDelayMs  << ","
            << st.urllcLossPct << ","
            << st.embbLossPct  << ","
            << st.aggThroughputMbps << ","
            << st.reward << ","
            << g_lastBwpSplitPct << ","
            << g_lastMcsHint << "\n";
    g_trace.flush();

    ++g_stepIdx;

    // NOTE: physical action enforcement (PRB split, MCS cap) is a TODO
    // hook inside 5G-LENA's scheduler — this first version validates
    // the full training loop; iteration 2 wires the scheduler attributes.

    if (!st.done)
        Simulator::Schedule(Seconds(stepInterval),
                            &DecisionStep, stepInterval, nUes, simTime);
}

int
main(int argc, char* argv[])
{
    // ---- Defaults ----
    uint16_t    nUes        = 10;
    double      speed       = 22.0;
    double      simTime     = 5.0;
    double      stepInterval= 0.010;   // 10 ms decision period
    double      gNbHeight   = 25.0;
    double      ueHeight    = 1.5;
    double      centralFreq = 3.5e9;
    double      bandwidth   = 100e6;
    uint16_t    numerology  = 2;
    double      txPowerGnb  = 30.0;
    double      txPowerUe   = 23.0;
    std::string scheduler   = "ns3::NrMacSchedulerTdmaRR";
    std::string outFile     = "v2x-urllc-ai-trace.csv";

    CommandLine cmd(__FILE__);
    cmd.AddValue("nUes",          "Vehicle UEs",                nUes);
    cmd.AddValue("speed",         "Vehicle speed (m/s)",        speed);
    cmd.AddValue("simTime",       "Simulation time (s)",        simTime);
    cmd.AddValue("stepInterval",  "DRL decision interval (s)",  stepInterval);
    cmd.AddValue("scheduler",     "NR MAC scheduler TypeId",    scheduler);
    cmd.AddValue("outFile",       "Per-step trace CSV",         outFile);
    cmd.Parse(argc, argv);

    // ---- ns3-ai interface (one message slot of each type) ----
    Ns3AiMsgInterface::Get()->SetIsMemoryCreator(false);
    Ns3AiMsgInterface::Get()->SetUseVector(false);
    Ns3AiMsgInterface::Get()->SetHandleFinish(true);
    // register the templated struct pair
    Ns3AiMsgInterfaceImpl<V2xEnvState, V2xEnvAction>* _bind =
        Ns3AiMsgInterface::Get()
            ->GetInterface<V2xEnvState, V2xEnvAction>();
    (void)_bind;

    // ---- Nodes ----
    NodeContainer gnbNodes;  gnbNodes.Create(1);
    NodeContainer ueNodes;   ueNodes.Create(nUes);

    // ---- Mobility ----
    MobilityHelper mGnb;
    Ptr<ListPositionAllocator> gPos = CreateObject<ListPositionAllocator>();
    gPos->Add(Vector(0.0, 0.0, gNbHeight));
    mGnb.SetPositionAllocator(gPos);
    mGnb.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mGnb.Install(gnbNodes);

    MobilityHelper mUe;
    mUe.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    Ptr<ListPositionAllocator> uPos = CreateObject<ListPositionAllocator>();
    for (uint16_t i = 0; i < nUes; ++i)
        uPos->Add(Vector(-100.0 + 25.0 * i, 50.0, ueHeight));
    mUe.SetPositionAllocator(uPos);
    mUe.Install(ueNodes);
    for (uint16_t i = 0; i < nUes; ++i)
        ueNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>()
              ->SetVelocity(Vector(speed, 0.0, 0.0));

    // ---- NR ----
    Ptr<NrPointToPointEpcHelper> epc = CreateObject<NrPointToPointEpcHelper>();
    Ptr<NrHelper> nr = CreateObject<NrHelper>();
    nr->SetEpcHelper(epc);
    nr->SetSchedulerTypeId(TypeId::LookupByName(scheduler));

    Ptr<IdealBeamformingHelper> bf = CreateObject<IdealBeamformingHelper>();
    bf->SetAttribute("BeamformingMethod",
                     TypeIdValue(DirectPathBeamforming::GetTypeId()));
    nr->SetBeamformingHelper(bf);

    CcBwpCreator cc;
    CcBwpCreator::SimpleOperationBandConf bConf(centralFreq, bandwidth, 1,
                                                BandwidthPartInfo::UMa);
    OperationBandInfo band = cc.CreateOperationBandContiguousCc(bConf);
    nr->InitializeOperationBand(&band);
    auto allBwps = CcBwpCreator::GetAllBwps({band});

    nr->SetGnbAntennaAttribute("NumRows",    UintegerValue(4));
    nr->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    nr->SetUeAntennaAttribute ("NumRows",    UintegerValue(1));
    nr->SetUeAntennaAttribute ("NumColumns", UintegerValue(2));
    nr->SetGnbPhyAttribute("TxPower", DoubleValue(txPowerGnb));
    nr->SetUePhyAttribute ("TxPower", DoubleValue(txPowerUe));

    NetDeviceContainer gnbDevs = nr->InstallGnbDevice(gnbNodes, allBwps);
    NetDeviceContainer ueDevs  = nr->InstallUeDevice (ueNodes,  allBwps);

    nr->GetGnbPhy(gnbDevs.Get(0), 0)
       ->SetAttribute("Numerology", UintegerValue(numerology));

    for (auto it = gnbDevs.Begin(); it != gnbDevs.End(); ++it)
        DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    for (auto it = ueDevs.Begin(); it != ueDevs.End(); ++it)
        DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();

    // ---- Internet + Remote host ----
    NodeContainer rhC; rhC.Create(1);
    Ptr<Node> rh = rhC.Get(0);
    InternetStackHelper inet;
    inet.Install(rhC);
    inet.Install(ueNodes);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2p.SetDeviceAttribute("Mtu",      UintegerValue(2500));
    p2p.SetChannelAttribute("Delay",   TimeValue(Seconds(0.0)));
    Ptr<Node> pgw = epc->GetPgwNode();
    NetDeviceContainer iDev = p2p.Install(pgw, rh);

    Ipv4AddressHelper ip;
    ip.SetBase("1.0.0.0", "255.0.0.0");
    ip.Assign(iDev);

    Ipv4StaticRoutingHelper sr;
    sr.GetStaticRouting(rh->GetObject<Ipv4>())
      ->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

    Ipv4InterfaceContainer ueIfs = epc->AssignUeIpv4Address(ueDevs);
    for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
        sr.GetStaticRouting(ueNodes.Get(i)->GetObject<Ipv4>())
          ->SetDefaultRoute(epc->GetUeDefaultGatewayAddress(), 1);

    nr->AttachToClosestEnb(ueDevs, gnbDevs);

    // ---- Traffic ----
    ApplicationContainer clients, servers;
    for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
        UdpServerHelper u1(g_portUrllc);
        servers.Add(u1.Install(ueNodes.Get(i)));
        UdpClientHelper c1(ueIfs.GetAddress(i), g_portUrllc);
        c1.SetAttribute("Interval",   TimeValue(Seconds(0.1)));
        c1.SetAttribute("PacketSize", UintegerValue(200));
        c1.SetAttribute("MaxPackets", UintegerValue(1000000));
        clients.Add(c1.Install(rh));

        UdpServerHelper u2(g_portEmbb);
        servers.Add(u2.Install(ueNodes.Get(i)));
        UdpClientHelper c2(ueIfs.GetAddress(i), g_portEmbb);
        c2.SetAttribute("Interval",   TimeValue(Seconds(0.001)));
        c2.SetAttribute("PacketSize", UintegerValue(125));
        c2.SetAttribute("MaxPackets", UintegerValue(1000000));
        clients.Add(c2.Install(rh));
    }
    servers.Start(Seconds(0.1));
    clients.Start(Seconds(0.2));
    servers.Stop (Seconds(simTime));
    clients.Stop (Seconds(simTime));

    // ---- Flow monitor ----
    FlowMonitorHelper fh;
    g_monitor    = fh.InstallAll();
    g_classifier = DynamicCast<Ipv4FlowClassifier>(fh.GetClassifier());

    // ---- Open trace CSV ----
    g_trace.open(outFile);
    g_trace << "step,t_sec,nUes,urllcTxMbps,embbTxMbps,meanUrllcDelayMs,"
            << "p99UrllcDelayMs,urllcLossPct,embbLossPct,aggTputMbps,"
            << "reward,action_bwpSplitPct,action_mcsHint\n";

    // Schedule first decision step after 200 ms warm-up
    Simulator::Schedule(Seconds(0.3),
                        &DecisionStep, stepInterval, (uint32_t)nUes, simTime);

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    g_trace.close();

    std::cout << "\n========= V2X-AI RUN SUMMARY =========\n";
    std::cout << "Vehicles: " << nUes << "  speed=" << speed << " m/s\n";
    std::cout << "Scheduler: " << scheduler << "\n";
    std::cout << "Decision interval: " << stepInterval * 1000 << " ms\n";
    std::cout << "Total decision steps: " << g_stepIdx << "\n";
    std::cout << "Trace CSV: " << outFile << "\n";
    std::cout << "======================================\n";

    Simulator::Destroy();
    return 0;
}