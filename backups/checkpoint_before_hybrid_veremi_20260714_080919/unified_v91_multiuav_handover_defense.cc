/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * unified_v81_adaptive.cc  -- adaptive edge-cloud architecture
 *
 * Changes over v80:
 *  [v81-1] InternalCloud default changed to FALSE.
 *          Bridge mode (InternalCloud=0) is now the only supported mode.
 *          Cloud no longer judges individual vehicles — it is a population-level
 *          parameter tuner only. The InternalCloud=1 path is deprecated.
 *  [v81-2] InternalCloud=1 block clearly marked DEPRECATED.
 *          It is guarded by the existing (!m_useInternalCloud) early-exit and
 *          never executes in bridge mode. Left in place for reference only.
 *  [v81-3] TELEM message unchanged — already carries all fields bridge v5 needs:
 *          CID, TS, SPD, HDG, PX, PY, LAN, BRK, SIMNOW, SAFE_WINS, CLASS.
 *          Bridge derives ts_delta, lane_change_rate, spd_z, hdg_var from these.
 *  [v81-4] --CloudWindow, --CloudMaxPkts, --CloudScrAlert params kept but marked
 *          as unused in bridge mode.
 *
 * Architecture (bridge mode only — InternalCloud=0):
 *   Car BSM -> UAV -> TELEM -> Bridge:9998 -> Edge:9999 -> verdict -> Bridge -> NS3 -> Car
 *   Bridge (background): accumulates per-CID evidence, fires CALIBRATE batch to cloud
 *   Cloud (async):       returns CALIBRATION_RESULT (W_deltas only, no per-car verdicts)
 *   Edge (async):        applies weight corrections, logs to parameter_history.jsonl
 *
 * Fixes over original v78:
 *  [FIX-1] CLOUD_FB sent to Edge AI after LLM response (weights now evolve)
 *  [FIX-2] ZONE_MALICIOUS aligned to 0.30 (matches edge/cloud paper defaults)
 *  [FIX-3] CLOUD_SCR_ALERT raised to 0.40 (mixed-behaviour triggers cloud earlier)
 *  [FIX-4] GAME_Cf raised to 3.0 (beta grows faster for malicious/mixed cars)
 *  [FIX-5] hostApp now receives EdgePort so it can send CLOUD_FB to Edge AI
 *  [M1-FIX-D] CLOUD_SCR_ALERT raised further to 0.50
 *
 *  [FIX-ATTACK-TYPE] Four original + two new attack profiles:
 *     ATK_COMPOSITE   (0) : TS offset + speed spike + frozen GPS (all models)
 *     ATK_TS_ONLY     (1) : replay timestamp only (model2)
 *     ATK_GPS_ONLY    (2) : frozen GPS position only (model4)
 *     ATK_SPEED_ONLY  (3) : speed +10-15% above normal, heading frozen (model1+3)
 *     ATK_STEALTHY    (4) : near-threshold composite -- all models weakly challenged
 *     ATK_ADAPTIVE    (5) : intermittent 1-in-3 malicious packets -- exploits safeWins discount
 *
 *  [NEW-PARAM] --TsOffset      : override TS attack offset (default -0.5)
 *  [NEW-PARAM] --SpdFactor     : override speed multiplier for ATK_SPEED_ONLY (default 1.10)
 *
 *  [COMPAT-FIX-1] LEDGER_FILE -> "blockchain_ledger.jsonl" (matches cloud LEDGER_PATH)
 *  [COMPAT-FIX-2] BAN_REWARD  -> 1.5 (Nash p*=0.400, matches edge NASH_BAN_REWARD=1.5)
 *  [COMPAT-FIX-3] sim_ts added to CLOUD_FB (enables edge RTT tracking FIX-CD1/CD2/CD3)
 *  [COMPAT-FIX-4] --InternalCloud flag (0=bridge handles cloud, 1=NS3 queries directly)
 *  [BRIDGE-CLEANUP-FIX] In bridge mode, skip host-side proxy CLOUD-NASH/LEDGER path
 *  [COMPAT-FIX-5] Natural HDG jitter +-2deg for honest cars (fixes M3 false positives)
 *
 *  [TEMPTATION-T] Heterogeneous per-car payoff T_i ~ U(0.5, 2.5) for ATK_RATIONAL.
 *    Each malicious car draws its own temptation at startup (seeded by rngRun+carId).
 *    Break-even p*_i = C_fp / (T_i + C_fp):
 *      T=0.5  -> p*=0.50  (timid, rarely attacks even at low suspicion)
 *      T=1.5  -> p*=0.25  (default, same as original R_ATK_BAN=1.5)
 *      T=2.5  -> p*=0.167 (aggressive, attacks even under elevated suspicion)
 *    Replaces static R_ATK_BAN=1.5 with per-instance m_temptation.
 *    Effect: breaks perfect 100% DR into a realistic ~85-93% band.
 *
 *  [OBS-NOISE] Gaussian noise sigma=0.08 on observed suspicion in ReceiveCtrl().
 *    Affects ATK_RATIONAL, ATK_INTERMITTENT, ATK_OPTIMAL.
 *    Cars near Nash p*=0.40 mis-estimate their risk => realistic FP/FN variance.
 *    Implements incomplete-information Bayesian Nash equilibrium (IEEE-publishable).
 *
 * Build:
 *   ./ns3 build
 *
 * Run (direct mode -- NS3 queries cloud directly, no bridge):
 *   ./ns3 run "scratch/unified_v78-multi --nCars=20 --attackRate=30 --attackType=0 --RngRun=1 \
 *              --EdgePort=9999 --CloudAddr=172.16.10.220 --CloudPort=6666 --InternalCloud=1"
 *
 * Run (bridge mode -- bridge handles cloud, NS3 -> bridge -> edge/cloud):
 *   ./ns3 run "scratch/unified_v78-multi --nCars=20 --attackRate=30 --attackType=4 --RngRun=1 \
 *              --EdgePort=9998 --CloudAddr=127.0.0.1 --CloudPort=9998 --InternalCloud=0"
 *
 * External servers (direct mode):
 *   python3 edge_ai_server_v79_flex.py --port 9999
 *   python3 ai_cloud_llm_v79_flex.py --port 6666
 *
 * External servers (bridge mode):
 *   python3 edge_ai_server_v79_flex.py --port 9999
 *   python3 ai_cloud_llm_v79_flex.py --port 6666     (on DGX)
 *   EDGE_HOST=127.0.0.1 EDGE_PORT=9999 \
 *   CLOUD_HOST=172.16.10.220 CLOUD_PORT=6666 \
 *   MIN_PKTS_CLOUD=3 \
 *   python3 edge_cloud_bridge.py
 */

#include "ns3/antenna-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/nr-module.h"
#include "ns3/wifi-module.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <random>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <cerrno>
#include <chrono>

using namespace ns3;

// Use a distinct log component name for the multi‑UAV build.  This
// prevents log output from interleaving with the v78/v81 baseline and
// makes it obvious in ns-3 trace output which version is running.
NS_LOG_COMPONENT_DEFINE("UnifiedV90MultiUav");

namespace {

struct CarSubnetPlan
{
    const char* base;
    const char* mask;
    uint32_t usableHosts;
};

CarSubnetPlan
ChooseCarSubnetPlan(uint32_t nCars)
{
    const uint32_t neededHosts = nCars + 1; // +1 for the AP/UAV Wi-Fi interface
    if (neededHosts <= 254)
    {
        return {"192.168.0.0", "255.255.255.0", 254};
    }
    if (neededHosts <= 65534)
    {
        return {"172.16.0.0", "255.255.0.0", 65534};
    }
    if (neededHosts <= 16777214)
    {
        return {"10.0.0.0", "255.0.0.0", 16777214};
    }

    NS_FATAL_ERROR("nCars is too large for a single IPv4 subnet plan");
    return {"10.0.0.0", "255.0.0.0", 16777214};
}

double
GetAutoExtendedSimTimeSeconds(Time requestedSimTime,
                              uint32_t laneCount,
                              uint32_t carsPerLane,
                              double perLaneStartSkew,
                              double perWaveStartSkew,
                              uint32_t startWaveRows,
                              double settleMarginSeconds)
{
    const uint32_t safeLaneCount = std::max(1u, laneCount);
    const uint32_t safeRows = std::max(1u, carsPerLane);
    const uint32_t safeWaveRows = std::max(1u, startWaveRows);
    const uint32_t rowsParticipatingInOffset = std::min(safeRows, safeWaveRows);

    const double latestStart = 1.0
        + (safeLaneCount - 1) * perLaneStartSkew
        + (rowsParticipatingInOffset - 1) * perWaveStartSkew;
    const double minimumUsefulDuration = latestStart + settleMarginSeconds;

    return std::max(requestedSimTime.GetSeconds(), minimumUsefulDuration);
}

double
GetEnvDouble(const char* name, double defaultValue)
{
    const char* raw = std::getenv(name);
    if (raw == nullptr || *raw == '\0')
    {
        return defaultValue;
    }

    char* end = nullptr;
    errno = 0;
    const double value = std::strtod(raw, &end);
    if (end == raw || (end != nullptr && *end != '\0') || errno != 0)
    {
        std::cerr << "[WARN] Invalid env var " << name << "='" << raw
                  << "'. Using default " << defaultValue << std::endl;
        return defaultValue;
    }
    return value;
}

} // namespace

// =========================================================================
// Tunable parameters
// =========================================================================

double REWARD         = 1.0;
double FALSE_BAN_COST = 0.5;
// [COMPAT-FIX-2] Changed from 2.33 to 1.5 so Nash p* = 1.0/(1.5+1.0) = 0.400,
// matching edge server NASH_BAN_REWARD=1.5 and NASH_CHASE_COST=1.0.
// p* was already annotated as 0.4 in original comment -- this restores consistency.
double BAN_REWARD     = 1.5;
double CHASE_COST     = 1.0;
double NASH_P_STAR    = 0.4;  // default p* — overridden by --NashPStar via cmd.AddValue (line 961)

// [LATENCY-MODEL] Configurable simulated latency injected via Simulator::Schedule.
// EdgeLatencyMs  : UAV->EdgeAI round-trip (default 10 ms = local LAN inference).
// CloudLatencyMs : HOST->CloudLLM round-trip (default 150 ms = WAN inference server).
// Wall-clock RTT of every TCP call is measured with std::chrono and logged as
// [EDGE-RTT] / [CLOUD-RTT] so real vs simulated latency can be compared.
double EdgeLatencyMs  = 10.0;
double CloudLatencyMs = 150.0;
// [OBS-NOISE] Receiver-side Gaussian noise sigma on observed suspicion.
// Overridable via --ObsNoiseSigma. Needs file scope — used in ReceiveCtrl().
double ObsNoiseSigma  = 0.08;

// [FIX-2] Aligned with edge/cloud configuration and paper defaults.
// Read from environment for experiment consistency with the edge server.
// Runtime defaults remain 0.15 / 0.30 unless overridden.
double ZONE_SAFE      = GetEnvDouble("ZONE_SAFE", 0.15);
double ZONE_MALICIOUS = GetEnvDouble("ZONE_MALICIOUS", 0.30);
bool LEGACY_WIRE_ALIASES = (GetEnvDouble("LEGACY_WIRE_ALIASES", 0.0) > 0.5);

// Final car ban now uses a rolling evidence window rather than strictly
// consecutive BAN packets, which better matches intermittent/adaptive attacks.
int FINAL_BAN_WINDOW_PKTS = 4;
int FINAL_BAN_REQUIRED    = 2;

// Cloud trigger constants
double   CLOUD_WINDOW_S       = 3.0;   // [FIX-B4] was 5.0, faster T1 for sparse TS
uint32_t CLOUD_MAX_PKTS       = 10;
// [M1-FIX-D] Raised from 0.40 to 0.50
double   CLOUD_SCR_ALERT      = 0.62;   // [FIX-B2] was 0.50
uint32_t CLOUD_MIN_ALERT_PKTS = 4;      // [FIX-B4] was 5, sparse TS attacks

// Attack parameters (original -- unchanged)
static constexpr double SPEED_NORMAL     = 20.0;
static constexpr double SPEED_ATTACK     = 22.0;
static constexpr double TS_OFFSET_ATTACK = -0.5;
static constexpr double ATK_FROZEN_NOISE = 0.3;

// [ATK_STEALTHY] Near-threshold attack constants
static constexpr double TS_OFFSET_STEALTHY  = -0.32;
static constexpr double SPEED_STEALTHY      = SPEED_NORMAL * 1.05;
static constexpr double GPS_DRIFT_RATE      = 0.4;
static constexpr double HDG_JITTER_STEALTHY = 0.5;

static constexpr int TCP_TIMEOUT_MS = 8000;

// [FIX-4] GAME_Cf raised from 2.0 to 3.0
double GAME_Rs = 0.5;
double GAME_Cf = 3.0;
// [CREDIT-DISCOUNT] Honest history earns a reduced GAME_Cf penalty in the next zone.
// discount = min(CREDIT_DISCOUNT_MAX, prior_safe_wins * CREDIT_DISCOUNT_PER_WIN)
// e.g. 20 safe wins * 0.015 = 0.30 cap -> GAME_Cf effective = 3.0 * (1 - 0.30) = 2.1
// Rationale: an established honest car is less likely to be a new attacker -- prior
// trust record should dampen false-alarm penalty, not eliminate it.
double CREDIT_DISCOUNT_MAX     = 0.30;  // cap: max 30% reduction in GAME_Cf
double CREDIT_DISCOUNT_PER_WIN = 0.015; // each prior safe-win earns 1.5% discount

// =============================================================================
// HONEST-CAR REWARD SYSTEM
// Cars earn tangible benefits for sustained honest behaviour:
//   BENEFIT 1 — Speed lane upgrade: after TRUST_LANE_WINS clean packets the car
//               moves to lane 0 (fast lane) and gets a speed boost (TRUST_SPEED_MS).
//               The system grants this via a LANE_UPGRADE ctrl message.
//   BENEFIT 2 — Reduced scrutiny: after TRUST_REDUCE_WINS clean packets the car's
//               edge check interval doubles (every other packet is fast-tracked).
//               Simulated by halving the effective EdgeLatencyMs for trusted cars.
//   BENEFIT 3 — Cumulative payoff logging: every car accumulates m_cumulativePayoff
//               from rwd/pnl signals for paper payoff comparison tables.
// =============================================================================
uint32_t TRUST_LANE_WINS    = 15;   // clean packets to earn fast-lane upgrade
uint32_t TRUST_REDUCE_WINS  = 20;   // clean packets to earn reduced scrutiny
// [BAYESIAN-GATE] Beta-distribution prior (matches CarUavState::alpha/beta
// defaults below). p_car = beta/(alpha+beta) uses these as the starting
// point before any evidence is observed.
const double NASH_ALPHA0 = 2.0;
const double NASH_BETA0  = 1.0;
// [BAYESIAN-GATE] Minimum packet observations (CarUavState::obsCount, a
// plain per-packet counter -- NOT derived from alpha+beta, which are
// weighted by GAME_Cf/GAME_Rs/pEdge and grow at very different rates per
// verdict type) before a car is eligible for conviction. Replaces the old
// streak-based force-ban triggers (WarnForceBanStreak / WarnRatio), which
// could either deadlock against a persistent attacker that occasionally
// produced one clean packet, or false-positive against an honest car
// experiencing a short noisy run (observed near cross-zone handover under
// multi-UAV). Default 15 — a car must be observed for 15 packets (~7.5s)
// before its accumulated Bayesian estimate (p_car) is trusted enough to
// convict. Configurable via --MinObservationsBeforeBan.
uint32_t MIN_OBSERVATIONS_BEFORE_BAN = 15;
// [EXP-C] When true, the TRUST_HANDOVER_TRIGGER is never sent — Zone 2
// starts from blank state for every car.  Used to measure the handover
// protocol's contribution by comparing WITH vs WITHOUT handover.
bool DISABLE_HANDOVER = false;
// [HTD] Handover Trust Discount — reduces inherited Bayesian evidence at
// zone transition to limit trust inertia exploited by late-entry attackers.
// δ=1.0 means full trust transfer (current default, vulnerable to late-entry).
// δ=0.0 means fresh start (same as no-handover baseline).
// δ=0.3 (recommended) retains 30% of Zone 1 evidence, bounding post-handover
// detection time independently of Zone 1 observation count (see Proposition 1).
double HANDOVER_TRUST_DISCOUNT = 0.3;
// [HTD] Zone boundary position — cars with PX exceeding this are in Zone 2.
// Must match --ZoneLength. Used only for HTD zone-crossing detection.
double HTD_ZONE_BOUNDARY = 1800.0;
// [CUSUM] Sequential change-point detector activated at zone crossing.
// Detects abrupt behavioral change (honest→malicious) independently of
// Bayesian trust history.  Based on Page (1954) one-sided CUSUM-style
// score accumulation.  S_k = max(0, S_{k-1} + pEdge_k - μ₀).
// Conviction when S_k > h.
// μ₀ = expected pEdge under honest behavior (calibrated from clean traces).
// h  = detection threshold (higher = fewer false alarms, slower detection).
double CUSUM_MU0 = 0.05;   // honest baseline (~edge score for clean cars)
double CUSUM_H   = 3.0;    // threshold: h/(μ₁-μ₀) ≈ 3.0/0.95 ≈ 3.2 pkts expected delay
bool   DISABLE_CUSUM = false;
// [CUSUM-WARMUP] Number of post-handover packets to observe before
// CUSUM accumulation starts.  Prevents Zone-2 cold-start false positives
// where the edge has no baseline for an arriving honest car and produces
// spuriously high m1/m3 scores on the first few packets.
// Default 5: gives the edge enough packets to establish a baseline
// without meaningfully delaying detection of a genuine late-entry attack.
uint32_t CUSUM_WARMUP_K = 5;

// [HD-DEFENSE] Handover-aware defense knobs. These keep the architecture
// multi-UAV-ready without removing trust continuity.  They are intentionally
// configurable so experiments can compare: full handover, decayed handover,
// probation-only, and CUSUM-only variants.
double   HTD_ZONE_LENGTH_M             = 1800.0;  // synced from --ZoneLength after cmd.Parse
double   HTD_HANDOVER_LEAD_M           = 400.0;   // synced from --HandoverLeadM after cmd.Parse
uint32_t POST_HANDOVER_PROBATION_PKTS  = 8;       // first K packets after handover are scrutinized
double   POST_HANDOVER_CREDIT_FACTOR   = 0.25;    // ledger credit multiplier during probation
bool     POST_HANDOVER_DISABLE_UPGRADE = true;    // suppress lane/reduced-scrutiny upgrades during probation
double   TRUST_SPEED_BOOST  = 2.0;  // m/s speed bonus in fast lane (20→22 m/s)
double   TRUST_LATENCY_MULT = 0.5;  // latency multiplier for trusted cars (halved)
// [LANE-UPGRADE] Lane geometry — set from cmd at startup, used by LANE_UPGRADE
// waypoint injection inside the app (needs file scope to be reachable from ReceiveCtrl).
double   LaneGapMeters      = 10.0; // lateral spacing between lanes (m)
uint32_t LaneCount          = 5;    // number of lanes; synced from laneCount after cmd.Parse()
// [LANE-UPGRADE] Simulation end time — promoted to file scope so ReceiveCtrl
// can compute remaining simulation time when injecting new waypoints.
double   SimEndTime         = 30.0; // seconds; synced from simTime after cmd.Parse()

// [COMPAT-FIX-1] Match cloud server default LEDGER_PATH="blockchain_ledger.jsonl"
// Previously "blockchainledgerv76.jsonl" -- cloud ReadPriorBans() always returned 0
// because it was reading a different filename.
static const char* LEDGER_FILE = "blockchain_ledger.jsonl";

// =========================================================================
// Data structures
// =========================================================================

struct CarUavState {
    double   alpha = NASH_ALPHA0;
    double   beta  = NASH_BETA0;
    uint32_t safeWins = 0;
    uint32_t carClass = 0;
    bool     banned   = false;
    uint32_t cid      = 0;
    double   frozen_px     = 0.0;
    bool     frozen_px_set = false;
    uint32_t seq = 0;
    uint32_t banStreak  = 0;   // consecutive BAN signals from edge (diagnostic only -- see [BAYESIAN-GATE])
    uint32_t warnStreak = 0;   // consecutive WARN signals (diagnostic only -- see [BAYESIAN-GATE])
    // [BAYESIAN-GATE] Plain packet count, incremented once per verdict regardless
    // of type or pEdge weighting. Deliberately NOT derived from alpha+beta:
    // those are weighted by GAME_Cf/GAME_Rs/pEdge and grow at very different
    // rates per verdict type (a single BAN can add GAME_Cf=3.0 to beta, while
    // a single SAFE adds at most GAME_Rs=0.5 to alpha), so alpha+beta measures
    // accumulated weighted suspicion, not how many times the car has actually
    // been observed. Using alpha+beta as an observation-count gate would let a
    // handful of unlucky WARN packets satisfy the gate almost immediately --
    // reproducing the false-positive problem this gate exists to prevent.
    uint32_t obsCount = 0;
    // [HTD] Set to true after the handover trust discount has been applied
    // for this car.  Ensures the discount fires exactly once per car.
    bool     handoverDiscountApplied = false;
    // [CUSUM] Post-handover sequential change-point detector state.
    // cusum_active: set to true when car crosses zone boundary.
    // cusum_S: running CUSUM statistic, reset to 0 at zone crossing.
    bool     cusum_active = false;
    double   cusum_S      = 0.0;
    // [CUSUM-WARMUP] Packets observed in Zone 2 before CUSUM starts
    // accumulating. First CUSUM_WARMUP_K packets after handover are
    // observation-only: edge has no Zone-2 baseline yet, so early
    // high-p scores reflect cold-start noise, not real attack signal.
    uint32_t cusum_warmup_pkts = 0;
    // [HD-DEFENSE] Multi-zone handover/probation state. currentZone is updated
    // at each handover trigger point (zoneEnd - lead), not only at physical zone exit.
    uint32_t currentZone = 1;
    uint32_t lastDefenseZone = 1;
    bool     postHandoverProbation = false;
    uint32_t postHandoverPktCount = 0;
    double   lastHandoverSimTime = -1.0;
    std::vector<uint8_t> recentBanWindow;
    // [CREDIT-DISCOUNT] Cf multiplier reduction earned from prior honest history.
    // Set once at zone entry from ledger safeWins. Range [0.0, CREDIT_DISCOUNT_MAX].
    double   creditDiscount = 0.0;
    // [HONEST-REWARD] UAV-side effective latency for this car.
    // Starts at EdgeLatencyMs; halved once REDUCE_SCRUTINY milestone fires.
    // Used in [EDGE-RTT] log so the paper trace shows per-car latency correctly.
    double   effectiveLatency = 0.0;   // initialised on first packet (see Receive())
};

struct EnrichedBlock {
    std::string raw;
    double   scr      = 0.5;
    double   alpha    = 2.0;
    double   beta     = 1.0;
    uint32_t safeWins = 0;
    uint32_t carClass = 0;
    double   spd      = 0.0;
    double   px       = 0.0;
    bool     shadow   = false;
    uint32_t cid      = 0;
    double   ts       = 0.0;
};

// =========================================================================
// Attack types
// =========================================================================
enum AppRole { ROLE_CAR, ROLE_UAV, ROLE_HOST };

enum AttackType {
    ATK_COMPOSITE  = 0,
    ATK_TS_ONLY    = 1,
    ATK_GPS_ONLY   = 2,
    ATK_SPEED_ONLY = 3,
    ATK_STEALTHY   = 4,
    ATK_ADAPTIVE   = 5,
    ATK_RATIONAL     = 6,  // Bayesian Nash rational agent -- EU-driven strategy
    ATK_INTERMITTENT = 7,  // Intermittent attacker: adapts attack rate to suspicion level
    ATK_OPTIMAL      = 8   // Optimal adversary: scales BOTH rate AND magnitude by suspicion
                           // Minimum falsification needed to stay below Nash p*=0.40
                           // Most realistic and hardest to detect attacker model
};


// =========================================================================
// TCP framing helpers (UNCHANGED)
// =========================================================================

static bool TcpSend(int sock, const std::string& msg) {
    uint32_t nlen = htonl((uint32_t)msg.size());
    if (send(sock, &nlen, 4, 0) != 4) return false;
    size_t sent = 0;
    while (sent < msg.size()) {
        ssize_t n = send(sock, msg.c_str() + sent, msg.size() - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

static std::string TcpRecv(int sock) {
    uint32_t nlen = 0; int got = 0;
    while (got < 4) {
        ssize_t n = recv(sock, (char*)&nlen + got, 4 - got, 0);
        if (n <= 0) return "";
        got += n;
    }
    uint32_t len = ntohl(nlen);
    if (len == 0 || len > 65536) return "";
    std::string result(len, '\0');
    got = 0;
    while (got < (int)len) {
        ssize_t n = recv(sock, &result[got], len - got, 0);
        if (n <= 0) return "";
        got += n;
    }
    return result;
}

static std::string TcpCallFramed(const char* host, int port,
                                  const std::string& msg,
                                  const std::string& fallback = "") {
    for (int attempt = 0; attempt < 2; attempt++) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct timeval tv;
        tv.tv_sec  = TCP_TIMEOUT_MS / 1000;
        tv.tv_usec = (TCP_TIMEOUT_MS % 1000) * 1000;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        inet_pton(AF_INET, host, &addr.sin_addr);
        if (::connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            ::close(fd);
            if (attempt == 0) { usleep(50000); continue; }
            return fallback;
        }
        TcpSend(fd, msg);
        std::string resp = TcpRecv(fd);
        ::close(fd);
        if (!resp.empty()) return resp;
        if (attempt == 0) usleep(50000);
    }
    return fallback;
}

static std::string ParseKV(const std::string& s, const std::string& key) {
    size_t pos = s.find(key + ":");
    if (pos == std::string::npos) return "";
    size_t start = pos + key.size() + 1;
    size_t end   = s.find(' ', start);
    return s.substr(start, (end == std::string::npos) ? std::string::npos : end - start);
}

static int ReadPriorBans(uint32_t cid) {
    int bans = 0;
    std::ifstream ledger(LEDGER_FILE);
    if (!ledger.is_open()) return 0;

    std::string cidToken = "\"cid\":" + std::to_string(cid);

    std::string line;
    while (std::getline(ledger, line)) {

        // Step A: find the token "cid":NUMBER in this line
        size_t pos = line.find(cidToken);
        if (pos == std::string::npos) continue;  // token not in this line at all

        // Step B: check the character immediately after the number
        // Valid JSON terminators after a number: comma, closing brace, space
        // If the next character is another digit (0-9), this is a prefix match
        // e.g. we searched "cid":3 but found "cid":30 — digit '0' follows, skip it
        size_t afterNum = pos + cidToken.size();
        if (afterNum < line.size()) {
            char next = line[afterNum];
            if (std::isdigit((unsigned char)next)) continue;  // prefix match, not exact
        }

        // Step C: confirmed exact CID match — now check if this line is a BAN
        if (line.find("BAN") != std::string::npos) bans++;
    }

    return bans;
}

// [CREDIT-DISCOUNT] Read prior honest-packet count from ledger for this CID.
// Returns the number of SAFE events written by the cloud — used to compute
// the GAME_Cf discount that rewards established honest cars at zone entry.
static int ReadPriorSafeWins(uint32_t cid) {
    int wins = 0;
    std::ifstream ledger(LEDGER_FILE);
    if (!ledger.is_open()) return 0;
    std::string cidToken = "\"cid\":" + std::to_string(cid);
    std::string line;
    while (std::getline(ledger, line)) {
        size_t pos = line.find(cidToken);
        if (pos == std::string::npos) continue;
        size_t afterNum = pos + cidToken.size();
        if (afterNum < line.size()) {
            char next = line[afterNum];
            if (std::isdigit((unsigned char)next)) continue;
        }
        if (line.find("SAFE") != std::string::npos) wins++;
    }
    return wins;
}

// =========================================================================
// UnifiedApp
// =========================================================================

class UnifiedApp : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("UnifiedApp")
            .SetParent<Application>()
            .AddConstructor<UnifiedApp>();
        return tid;
    }

    UnifiedApp() : m_socket(nullptr), m_ctrlSocket(nullptr), m_cloudCtrlSocket(nullptr),
                   m_role(ROLE_CAR),
                   // [COMPAT-FIX-4] m_useInternalCloud declared before m_carId in class body,
                   // so it must be initialised here first to match declaration order (-Wreorder fix)
                   // [v81-1] Default changed to false — bridge mode only. InternalCloud=1 DEPRECATED.
                   m_useInternalCloud(false),
                   m_carId(0), m_laneId(0),
                   m_node(nullptr), m_isMalicious(false),
                   m_attackRate(20), m_attackType(ATK_COMPOSITE),
                   m_tsOffset(TS_OFFSET_ATTACK),
                   m_spdFactor(1.10),
                   m_pktDropRate(1) {}

    void Setup(AppRole role, Ipv4Address destAddr, uint16_t port,
               uint32_t carId = 0, int laneId = 0,
               Ptr<Node> node = nullptr) {
        m_role     = role;
        m_destAddr = destAddr;
        m_port     = port;
        m_carId    = carId;
        m_laneId   = laneId;
        m_originalLaneId      = laneId;        // [DEMOTION] restoration target
        m_originalSpeedNormal = SPEED_NORMAL;  // updated again when upgrade fires
        m_node     = node;
        m_effectiveLatency = EdgeLatencyMs;  // starts at full latency
    }

    void SetAttackRate       (uint32_t r)           { m_attackRate        = r; }
    void SetMalicious        (bool m)               { m_isMalicious       = m; }
    void SetAttackType       (uint32_t t)           { m_attackType        = (AttackType)t; }
    void SetUavCtrlAddr      (Ipv4Address a)        { m_uavCtrlAddr       = a; }
    void SetEdgePort         (uint16_t port)        { m_edgePort          = port; }
    void SetEdgePortZ2       (uint16_t port)        { m_edgePortZ2        = port; }
    void SetEdgeAddr         (const std::string& a) { m_edgeAddr          = a; }
    void SetCloudAddr        (const std::string& a) { m_cloudAddr         = a; }
    void SetCloudPort        (uint16_t port)        { m_cloudPort         = port; }
    void SetTsOffset         (double v)             { m_tsOffset          = v; }
    void SetSpdFactor        (double v)             { m_spdFactor         = v; }
    // [FIX-A2] Setter -- transfers CLI --PktDropRate value into class instance.
    void SetPktDropRate      (uint32_t r)           { m_pktDropRate        = r; }
    // [TEMPTATION-T] Per-car private payoff. Called in main() for malicious cars.
    void SetTemptation       (double t)             { m_temptation        = t; }
    void SetTemptationFixed  (double t)             { m_temptationFixed   = t; }
    void SetSimDuration      (double d)             { m_simDuration       = d; }
    // [CLI] Per-car speed init — overrides static constexpr defaults when
    // --SpeedNormal / --SpeedAttack are passed on the command line.
    void SetSpeedNormal      (double v)             { m_speedNormal       = v; }
    void SetSpeedAttack      (double v)             { m_speedAttack       = v; }
    double GetSpeedBoost()          const { return m_speedBoost; }

    // [LANE-UPGRADE] Called by Simulator::Schedule at T1 and T2 phase boundaries.
    // Applies current m_speedBoost so lane-upgraded cars keep their bonus
    // through all three speed phases.
    void SetSpeedPhase(double baseSpeed) {
        auto cvm = m_node ? m_node->GetObject<ConstantVelocityMobilityModel>() : nullptr;
        if (cvm) {
            cvm->SetVelocity(Vector(baseSpeed + m_speedBoost, 0.0, 0.0));
        }
    }
    // [PAYOFF] Public accessors — read after Simulator::Run() in main()
    // to guarantee output ordering (StopApplication cout is unreliable at shutdown).
    double   GetCumulativePayoff()  const { return m_cumulativePayoff; }
    uint32_t GetHonestSafeWins()    const { return m_honestSafeWins; }
    uint32_t GetAdverseCount()      const { return m_adverseCount; }
    uint32_t GetWarnCount()         const { return m_warnCount; }
    bool     GetLaneUpgraded()      const { return m_laneUpgraded; }
    bool     GetDemoted()           const { return m_demoted; }
    uint32_t GetReturnThreshold()   const { return m_returnThreshold; }
    bool     GetScrutinyReduced()   const { return m_scrutinyReduced; }
    bool     GetIsMalicious()       const { return m_isMalicious; }
    uint32_t GetCarId()             const { return m_carId; }
    // [COMPAT-FIX-4] setter for bridge-mode flag
    void SetUseInternalCloud (bool v)               { m_useInternalCloud  = v; }
    // [ITEM-5] Late malicious activation — flips car to attacker at runtime.
    // Scheduled via Simulator::Schedule to model a car that behaves honestly
    // during a warm-up phase then launches attacks at time T_flip.
    // Tests whether adaptive p* and Bayesian state respond to a density change.
    void ActivateMaliciousLate(AttackType atype, double tsOff, double spdFact) {
        m_isMalicious = true;
        m_attackType  = atype;
        m_tsOffset    = tsOff;
        m_spdFactor   = spdFact;
        std::cout << "[LATE-ATTACK] CID:" << m_carId
                  << " flipped to MALICIOUS at t="
                  << Simulator::Now().GetSeconds() << "s\n";
    }

    // [ITEM-5b] Position-aware late malicious activation.
    // Polls position every 1s. Flips when distToExit <= threshM.
    void PollAndFlipIfNearExit(AttackType atype, double tsOff, double spdFact,
                               double zoneLenM, double threshM) {
        if (m_isMalicious) return;
        auto mob = GetNode()->GetObject<ConstantVelocityMobilityModel>();
        if (!mob) return;
        double posX       = mob->GetPosition().x;
        double distToExit = zoneLenM - posX;
        if (distToExit <= threshM) {
            m_isMalicious = true;
            m_attackType  = atype;
            m_tsOffset    = tsOff;
            m_spdFactor   = spdFact;
            std::cout << "[LATE-ATTACK] CID:" << m_carId
                      << " POSITION-FLIP at t="
                      << std::fixed << std::setprecision(1)
                      << Simulator::Now().GetSeconds()
                      << "s posX=" << posX
                      << "m distToExit=" << distToExit
                      << "m (threshold=" << threshM << "m)\n";
            return;
        }
        // Not yet at exit threshold — reschedule poll in 1s
        Simulator::Schedule(Seconds(1.0),
                            &UnifiedApp::PollAndFlipIfNearExit, this,
                            atype, tsOff, spdFact, zoneLenM, threshM);
    }

    // [MU] Poll for trust handover near a zone boundary.  This version is
    // multi-UAV-ready: it can send one handover per transition
    // Zone i -> Zone i+1 instead of only one hard-coded Zone 1 -> Zone 2 event.
    void PollAndHandoverIfNearBoundary(uint32_t fromZone, uint32_t toZone,
                                       double zoneEndX, double leadM,
                                       const std::string& edgeAddr, uint16_t edgePort) {
        // Only send one trigger per car per source zone.
        if (m_handoverSentZones.count(fromZone)) return;
        auto mob = GetNode()->GetObject<ConstantVelocityMobilityModel>();
        if (!mob) return;
        double posX     = mob->GetPosition().x;
        double distLeft = zoneEndX - posX;
        if (distLeft <= leadM) {
            m_handoverSentZones.insert(fromZone);
            double simTs   = Simulator::Now().GetSeconds();
            std::ostringstream msg;
            msg << "TRUST_HANDOVER_TRIGGER CID:" << m_carId
                << " FROM_ZONE:" << fromZone
                << " TO_ZONE:" << toZone
                << " ZONE_END_X:" << std::fixed << std::setprecision(1) << zoneEndX
                << " LEAD_M:" << std::fixed << std::setprecision(1) << leadM
                << " POS_X:" << std::fixed << std::setprecision(1) << posX
                << " SIM_TS:" << std::fixed << std::setprecision(2) << simTs;

            // [RACE-FIX] No longer fire-and-forget: the coordinator already
            // blocks and waits for the target edge's TRUST_HANDOVER_LOAD ack
            // before replying (see handle_trust_handover_trigger in
            // trust_coordinator_v2_handover_defense.py). We now capture that
            // confirmation and propagate it to the UAV via the car's own
            // beacon (HOK: field) so the UAV can gate its zone-routing switch
            // on confirmed readiness instead of raw position alone.
            if (!DISABLE_HANDOVER) {
                std::string hoResp = TcpCallFramed(edgeAddr.c_str(), edgePort, msg.str());
                bool hoLoaded = (hoResp.find("\"loaded\": true") != std::string::npos
                               || hoResp.find("\"loaded\":true")  != std::string::npos);
                if (hoLoaded) {
                    m_handoverConfirmedZone = toZone;
                }
                std::cout << "[HANDOVER] CID:" << m_carId
                          << " trigger from_Z" << fromZone << " to_Z" << toZone
                          << " at posX=" << posX
                          << " distLeft=" << distLeft << "m"
                          << " loaded=" << (hoLoaded ? "YES" : "NO")
                          << " RAWRESP=[" << hoResp << "]\n";
            } else {
                std::cout << "[HANDOVER-DISABLED] CID:" << m_carId
                          << " trigger SUPPRESSED from_Z" << fromZone << " to_Z" << toZone
                          << " at posX=" << posX
                          << " distLeft=" << distLeft << "m\n";
            }
            return;
        }
        // Not yet at threshold — reschedule poll in 0.5 s.
        Simulator::Schedule(Seconds(0.5),
                            &UnifiedApp::PollAndHandoverIfNearBoundary, this,
                            fromZone, toZone, zoneEndX, leadM, edgeAddr, edgePort);
    }

    // Nash threshold (local Bayesian) -- UNCHANGED
    double ComputeNashThreshold(double p_car) {
        constexpr double NE_T_MIN  = 0.10;
        constexpr double NE_T_STAR = 1.5;
        if (p_car <= 0.0) return NE_T_MIN;
        if (p_car >= 0.5) return NE_T_STAR;
        return NE_T_MIN + (NE_T_STAR - NE_T_MIN) * (p_car / 0.5);
    }

    // [ADAPTIVE-NASH] Compute p* dynamically from observed attacker density.
    // Uses a Bayesian-weighted population density estimator:
    //   rho_hat_w = (Σ pᵢ) / N   where pᵢ = βᵢ/(αᵢ+βᵢ) for each known car
    // This is collusion-robust: a quiet malicious car still contributes its
    // Bayesian suspicion pᵢ to the estimate, preventing quiet-start bias.
    // The adaptive threshold follows the Nash equilibrium condition:
    //   p*(t) = CHASE_COST / ((1 + rho_hat_w) * BAN_REWARD + CHASE_COST)
    // When rho_hat_w = 0 (all cars fully trusted) this equals the static 0.4.
    // As rho_hat_w rises the denominator grows, p* falls, gate tightens.
    // m_popTotalObs is used only as a 5-decision warmup counter.
    double ComputeAdaptiveNashPStar() {
        if (m_popTotalObs < 5) return NASH_P_STAR;   // warmup: use static baseline

        // [COLLUSION-ROBUST ρ̂] Bayesian-weighted population density estimator.
        //
        // The naive estimator ρ̂ = bans/total is vulnerable to collusion: a group
        // of malicious cars that stays quiet initially can keep ρ̂ artificially low
        // and delay the tightening of the Nash gate.
        //
        // The Bayesian-weighted estimator instead computes:
        //   ρ̂_w = (Σ pᵢ) / N   where pᵢ = βᵢ / (αᵢ + βᵢ)
        //
        // Every car contributes its *current suspicion probability* to the
        // population estimate.  A quiet malicious car still accumulates β
        // from any partial edge signals (WARN verdicts increase β by GAME_Cf×pEdge),
        // so its pᵢ drifts upward even without a hard BAN verdict.  Only a car
        // with a genuinely growing α (many clean packets) can hold pᵢ near zero.
        // This closes the quiet-start collusion loophole without requiring
        // any additional network messages or per-car ground-truth labels.
        double sumP = 0.0;
        uint32_t n  = 0;
        for (const auto& kv : m_carState) {
            const CarUavState& cs = kv.second;
            double ab = cs.alpha + cs.beta;
            if (ab > 0.0) { sumP += cs.beta / ab; n++; }
        }
        double rho_hat = (n > 0) ? std::min(1.0, sumP / (double)n) : 0.0;

        double p_adaptive = CHASE_COST / ((1.0 + rho_hat) * BAN_REWARD + CHASE_COST);
        return std::max(0.10, std::min(0.70, p_adaptive));  // hard clamp [0.10, 0.70]
    }

    // [LATENCY-MODEL] Deferred ctrl sender — called via Simulator::Schedule so the
    // car receives its OK/WARN/BAN verdict at simulated_time + EdgeLatencyMs,
    // correctly modelling the round-trip through the Edge AI inference server.
    void SendCtrlToCarDelayed(Ipv4Address dest, std::string ctrlMsg) {
        SendCtrlToCar(dest, ctrlMsg);
    }

    // [CLOUD-LATENCY] Deferred CLOUDCTRL sender — called via Simulator::Schedule
    // so the UAV receives the cloud verdict at simulated_time + CloudLatencyMs,
    // modelling the WAN round-trip to the Cloud LLM server (default 150 ms).
    // This completes the end-to-end latency model: Edge (10 ms) + Cloud (150 ms).
    void SendCloudCtrlDelayed(Ipv4Address uavAddr, std::string cloudCtrlMsg) {
        if (!m_socket) return;
        m_socket->SendTo(
            Create<Packet>((uint8_t*)cloudCtrlMsg.c_str(), cloudCtrlMsg.length()),
            0, InetSocketAddress(uavAddr, 9002));
    }

    // [ITEM-2] Gaussian-jittered latency sampler.
    // Returns a delay sampled from Normal(mu, sigma) clamped to [1, 3*mu] ms.
    // This turns fixed scalar latency into a realistic distribution, enabling
    // detection latency CDFs as paper figures.  Uses the Box-Muller transform
    // seeded by the ns3 RNG stream so results are reproducible per --RngRun.
    static uint64_t JitteredMs(double mu_ms, double sigma_ms) {
        // Box-Muller: two uniform samples -> one Gaussian sample
        double u1 = ((double)(rand() % 10000) + 0.5) / 10000.0;
        double u2 = ((double)(rand() % 10000) + 0.5) / 10000.0;
        double z  = std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * M_PI * u2);
        double v  = mu_ms + sigma_ms * z;
        // clamp to [1 ms, 3*mu] to prevent negative or extreme outlier delays
        v = std::max(1.0, std::min(3.0 * mu_ms, v));
        return (uint64_t)std::round(v);
    }

    // Build enriched block for cloud -- UNCHANGED
    std::string BuildEnrichedBlock(const std::string& carIp,
                                    const std::string& carMsg,
                                    double scr, double alpha, double beta,
                                    uint32_t safeWins, uint32_t carClass,
                                    uint32_t seq, bool shadow, uint32_t cid,
                                    double ts, double spd, double px) {
        std::stringstream ss;
        ss << "BLK:" << std::hex << std::setw(4) << std::setfill('0') << (rand() % 0xFFFF)
           << "|TX:" << carIp
           << "|" << carMsg
           << "|SCR:"       << std::fixed << std::setprecision(3) << scr
           << "|ALPHA:"     << std::setprecision(2) << alpha
           << "|BETA:"      << std::setprecision(2) << beta
           << "|SAFE_WINS:" << safeWins
           << "|CLASS:"     << carClass
           << "|SHADOW:"    << (shadow ? "1" : "0")
           << "|SEQ:"       << std::dec << seq;
        return ss.str();
    }

    // Build CLOUD-QUERY -- UNCHANGED
    std::string BuildCloudQuery(uint32_t cid, uint32_t n, double avgEdgeSusp,
                                 uint32_t shadowCount, const std::string& trigger,
                                 int priorBans, double avgSpd, double pxRange,
                                 uint32_t safeWins) {
        std::stringstream ss;
        ss << "CLOUD-QUERY CID:" << cid
           << " N:"         << n
           << " AVG_EDGE_SUSP:" << std::fixed << std::setprecision(3) << avgEdgeSusp
           << " AVG:"       << std::fixed << std::setprecision(3) << avgEdgeSusp
           << " SHD:"       << shadowCount
           << " TRG:"       << trigger
           << " BANS:"      << priorBans
           << " SPD_AVG:"   << std::setprecision(1) << avgSpd
           << " PX_RANGE:"  << std::setprecision(1) << pxRange
           << " SAFE_WINS:" << safeWins;
        return ss.str();
    }

    // [REWARD-PENALTY] Control message -- realistic C-V2X feedback.
    // Car sees: status, reputation score, reward, penalty, credit balance.
    // Car does NOT see: internal ML score, Nash threshold, Bayesian alpha/beta.
    // REP = alpha/(alpha+beta) -- normalised trust, not raw pEdge.
    // RWD = reward for honest packet. PNL = penalty if flagged.
    // CREDIT = cumulative honest-packet balance (incentive token).
    std::string BuildCtrlMsg(uint32_t cid, const std::string& ip,
                              const std::string& act, double score,
                              double T_star, const std::string& why,
                              double alpha=2.0, double beta=1.0,
                              uint32_t safeWins=0) {
        double rep = (alpha + beta > 0) ? alpha / (alpha + beta) : 0.5;
        rep = std::max(0.0, std::min(1.0, rep));
        // [FIX-A1] Sender-side Gaussian noise on REP (sigma=0.15).
        // UAV obfuscates exact trust before broadcast -- information asymmetry.
        // Attackers (ATK_RATIONAL/INTERMITTENT/OPTIMAL) cannot precisely infer
        // their suspicion level, weakening EU-driven timing strategies.
        // Combined with receiver-side noise (sigma=0.08 in ReceiveCtrl):
        //   total_sigma ~= sqrt(0.15^2 + 0.08^2) ~= 0.17
        // Box-Muller on global rand() -- reproducible per --RngRun seed.
        {
            double _u1 = ((double)(rand() % 10000) + 0.5) / 10000.0;
            double _u2 = ((double)(rand() % 10000) + 0.5) / 10000.0;
            double _repNoise = 0.15 * std::sqrt(-2.0 * std::log(_u1))
                                     * std::cos(2.0 * M_PI * _u2);
            rep = std::max(0.0, std::min(1.0, rep + _repNoise));
        }
        double rwd = 0.0, pnl = 0.0;
        if      (act == "OK")   { rwd = REWARD * (1.0 - score); }
        else if (act == "WARN") { pnl = FALSE_BAN_COST * score; }
        else                    { pnl = FALSE_BAN_COST; }
        int32_t credit = (int32_t)safeWins
                       - (act == "BAN" ? 10 : act == "WARN" ? 2 : 0);
        std::stringstream ss;
        ss << "CTRL|CID:" << cid << "|IP:" << ip
           << "|ACT:"    << act
           << "|REP:"    << std::fixed << std::setprecision(3) << rep
           << "|RWD:"    << std::setprecision(3) << rwd
           << "|PNL:"    << std::setprecision(3) << pnl
           << "|CREDIT:" << credit;
        return ss.str();
    }

    // [HONEST-REWARD] Build ctrl message with tangible benefit flags
    std::string BuildBenefitCtrl(uint32_t cid, const std::string& ip,
                                  const std::string& benefit,
                                  double speedBoost, uint32_t safeWins) {
        std::stringstream ss;
        ss << "CTRL|CID:" << cid << "|IP:" << ip
           << "|ACT:OK"
           << "|BENEFIT:" << benefit
           << "|SPD_BOOST:" << std::fixed << std::setprecision(1) << speedBoost
           << "|SAFE_WINS:" << safeWins
           << "|RWD:" << std::setprecision(3) << (REWARD * 1.5)  // bonus reward
           << "|PNL:0.000|CREDIT:" << safeWins;
        return ss.str();
    }

    // [BAN-PUNISH] Build BAN ctrl with SLOW_LANE punishment embedded.
    // Car receives ACT=BAN (triggers forgiveness tier logic) AND BENEFIT=SLOW_LANE
    // (moves car to LAN=99 exile lane immediately on receipt).
    // Recovery is extremely slow — return_threshold doubles with each additional BAN.
    std::string BuildBanPunishCtrl(uint32_t cid, const std::string& ip,
                                    double score, double T_star,
                                    double alpha, double beta,
                                    uint32_t safeWins) {
        double rep = (alpha + beta > 0) ? alpha / (alpha + beta) : 0.1;
        rep = std::max(0.0, std::min(1.0, rep));
        std::stringstream ss;
        ss << "CTRL|CID:" << cid << "|IP:" << ip
           << "|ACT:BAN"
           << "|BENEFIT:SLOW_LANE"
           << "|SPD_BOOST:0.0"
           << "|REP:"    << std::fixed << std::setprecision(3) << rep
           << "|RWD:0.000"
           << "|PNL:"    << std::setprecision(3) << FALSE_BAN_COST
           << "|CREDIT:" << (int32_t)safeWins - 10;
        return ss.str();
    }

    void SendCtrlToCar(Ipv4Address carIp, const std::string& msg) {
        if (!m_ctrlSocket) return;
        m_ctrlSocket->SendTo(
            Create<Packet>((uint8_t*)msg.c_str(), msg.length()),
            0, InetSocketAddress(carIp, 9001));
    }

    // CAR: receive control from UAV -- UNCHANGED
    void ReceiveCtrl(Ptr<Socket> socket) {
        Ptr<Packet> pkt; Address from;
        while ((pkt = socket->RecvFrom(from))) {
            uint8_t buf[1024] = {0};
            pkt->CopyData(buf, pkt->GetSize());
            std::string msg((char*)buf, pkt->GetSize());
            auto ex = [&](const std::string& k) -> std::string {
                size_t p = msg.find(k + ":"); if (p == std::string::npos) return "";
                size_t e = msg.find('|', p + k.size() + 1);
                return msg.substr(p + k.size() + 1,
                    e == std::string::npos ? std::string::npos : e - p - k.size() - 1);
            };
            std::string act     = ex("ACT");
            std::string repStr  = ex("REP");
            std::string rwdStr  = ex("RWD");
            std::string pnlStr  = ex("PNL");
            std::string credStr = ex("CREDIT");
            // [HREADY-CTRL-FIX] This runs on the CAR's own instance -- update the
            // CAR's own m_handoverConfirmedZone here, not on any UAV-side copy.
            std::string hreadyStr = ex("HREADY");
            if (!hreadyStr.empty()) {
                try {
                    uint32_t hz = static_cast<uint32_t>(std::stoul(hreadyStr));
                    if (hz > m_handoverConfirmedZone) {
                        m_handoverConfirmedZone = hz;
                    }
                } catch (...) {}
            }

            // Parse reward/penalty fields
            double rep = 0.5, rwd = 0.0, pnl = 0.0;
            try { if (!repStr.empty())  rep = std::stod(repStr);  } catch(...){}
            try { if (!rwdStr.empty())  rwd = std::stod(rwdStr);  } catch(...){}
            try { if (!pnlStr.empty())  pnl = std::stod(pnlStr);  } catch(...){}

            // [ECON-HARDEN] Make malicious behaviour economically bad, not only
            // logically demoted:
            //   * while on economic probation, OK verdicts earn zero positive reward
            //   * first/repeated WARNs claw back earlier gains and add escalating cost
            //   * BAN wipes any remaining positive payoff and adds a strong penalty
            double priorPayoff = m_cumulativePayoff;
            double extraEconomicPenalty = 0.0;

            if (act == "OK" && m_econProbation) {
                if (rwd > 0.0) {
                    std::cout << "[ECON-GATE] CID:" << m_carId
                              << " probation active - suppressing OK reward "
                              << rwd << "\n";
                }
                rwd = 0.0;
            }

            if (act == "WARN") {
                m_econProbation = true;
                if (priorPayoff > 0.0) {
                    double clawFrac = (m_warnCount == 0) ? 0.75 : 0.50;
                    extraEconomicPenalty += clawFrac * priorPayoff;
                }
                extraEconomicPenalty += (FALSE_BAN_COST * 1.5)
                                      + 0.25 * static_cast<double>(m_warnCount + 1);
            } else if (act == "BAN") {
                m_econProbation = true;
                if (priorPayoff > 0.0) {
                    extraEconomicPenalty += priorPayoff;
                }
                extraEconomicPenalty += (FALSE_BAN_COST * 8.0)
                                      + 1.0 * static_cast<double>(m_adverseCount + 1);
            }

            if (extraEconomicPenalty > 0.0) {
                pnl += extraEconomicPenalty;
            }

            // [HONEST-REWARD] Accumulate payoff for ALL cars (paper comparison table)
            m_cumulativePayoff += rwd - pnl;

            if (extraEconomicPenalty > 0.0) {
                std::cout << "[ECON-CLAWBACK] CID:" << m_carId
                          << " ACT=" << act
                          << " prior_payoff=" << priorPayoff
                          << " extra_penalty=" << extraEconomicPenalty
                          << " new_payoff=" << m_cumulativePayoff << "\n";
            }

            // Revoke any active trust benefits after suspicious / adverse behaviour.
            // These flags represent CURRENT active benefits, not lifetime history.
            // IMPORTANT: apply only logical state changes here. Do NOT move the UE
            // with SetPosition/SetVelocity while NR is active.
            auto RevokeTrustBenefits = [&]() {
                bool changed = m_laneUpgraded || m_scrutinyReduced ||
                               (m_speedBoost != 0.0) ||
                               (std::fabs(m_effectiveLatency - EdgeLatencyMs) > 1e-9);

                m_laneUpgraded      = false;
                m_scrutinyReduced   = false;
                m_effectiveLatency  = EdgeLatencyMs;
                m_laneId            = m_originalLaneId;
                m_speedNormal       = m_originalSpeedNormal;
                m_speedAttack       = m_originalSpeedNormal;
                m_speedBoost        = 0.0;

                if (changed) {
                    std::cout << "[TRUST-REVOKED] CID:" << m_carId
                              << " benefits revoked logically; lane=" << m_laneId
                              << " speed=" << m_speedNormal
                              << " latency=" << m_effectiveLatency << "ms\n";
                }
            };

            // [FORGIVENESS] Three-tier graduated punishment system:
            //
            //  OK verdict:
            //    - increment honest_wins as normal
            //    - if car is demoted and hits m_returnThreshold → restore fast lane
            //
            //  Adverse verdict (WARN / BAN):
            //    Tier 1 — adverse_count == 1 (first offence):
            //      Excused. honest_wins unchanged, lane unchanged.
            //
            //    Tier 2 — adverse_count == 2 (second offence):
            //      Demote: return to original lane, restore pre-boost speed.
            //      Return threshold = 2 × honest_wins at demotion point.
            //      Halve honest_wins.
            //
            //    Tier 3 — adverse_count >= 3 (persistent offender):
            //      Slow-lane exile (LAN sentinel=99). Halve again. Threshold doubles.
            if (act == "OK") {
                m_honestSafeWins++;
                // Economic probation can be cleared only after enough clean packets.
                if (m_econProbation && !m_demoted && m_honestSafeWins >= TRUST_LANE_WINS) {
                    m_econProbation = false;
                    std::cout << "[ECON-RESTORE] CID:" << m_carId
                              << " probation cleared after " << m_honestSafeWins
                              << " clean packets\n";
                }
                // Re-earn check: a demoted car can return only to its NORMAL lane.
                // Trust benefits (fast lane / reduced scrutiny) must be re-earned again.
                if (m_demoted &&
                    m_returnThreshold > 0 &&
                    m_honestSafeWins >= m_returnThreshold) {
                    m_laneId           = m_originalLaneId;
                    m_speedNormal      = m_originalSpeedNormal;
                    m_speedAttack      = m_originalSpeedNormal;
                    m_speedBoost       = 0.0;
                    m_effectiveLatency = EdgeLatencyMs;

                    m_demoted         = false;
                    m_returnThreshold = 0;
                    m_econProbation   = false;

                    std::cout << "[FORGIVENESS] CID:" << m_carId
                              << " restored to NORMAL lane after " << m_honestSafeWins
                              << " clean packets; trust benefits must be re-earned"
                              << " [logical-only restore]\n";
                }
            } else {
                // [FORGIVENESS] Tier escalation — only on confirmed BAN.
                // WARN verdicts are suspicion signals, not confirmed bad behaviour.
                // A noisy WARN from the edge should not demote an honest car.
                // WARNs reset the honest_wins streak (UAV-side st.safeWins also resets)
                // but do not increment m_adverseCount or trigger tier punishment.
                if (act == "WARN") {
                    m_warnCount++;
                    m_honestSafeWins = 0;
                    RevokeTrustBenefits();
                    // No tier escalation — WARN is not a confirmed offence,
                    // but active trust benefits are revoked immediately.
                    std::cout << "[FORGIVENESS] CID:" << m_carId
                              << " WARN #" << m_warnCount
                              << " — streak reset, benefits revoked\n";
                } else {
                    // act == "BAN" — confirmed offence, tier escalation applies
                    m_adverseCount++;
                    RevokeTrustBenefits();
                    if (m_adverseCount == 1) {
                        // Tier 1 — first confirmed BAN excused
                        std::cout << "[FORGIVENESS] CID:" << m_carId
                                  << " BAN#1 excused (first confirmed offence)"
                                  << " honest_wins=" << m_honestSafeWins
                                  << " (preserved)\n";
                    } else if (m_adverseCount == 2) {
                        // Tier 2 — demote from fast lane, set double-points return bar
                        uint32_t before   = m_honestSafeWins;
                        m_demotedAt       = m_honestSafeWins;
                        m_returnThreshold = std::max(TRUST_LANE_WINS * 2u, m_demotedAt * 2);
                        m_honestSafeWins  = m_honestSafeWins / 2;
                        m_laneId          = m_originalLaneId;
                        m_speedNormal     = m_originalSpeedNormal;
                        m_speedAttack     = m_originalSpeedNormal;
                        m_demoted         = true;
                        std::cout << "[FORGIVENESS] CID:" << m_carId
                                  << " BAN#2 DEMOTED → lane=" << m_laneId
                                  << " speed=" << m_speedNormal << " m/s"
                                  << " honest_wins " << before << " → " << m_honestSafeWins
                                  << " (need " << m_returnThreshold << " to re-earn)\n";
                    } else {
                        // Tier 3 — persistent offender: slow-lane exile, halve wins.
                        // Threshold managed by SLOW_LANE benefit handler below.
                        uint32_t before = m_honestSafeWins;
                        m_honestSafeWins = m_honestSafeWins / 2;
                        m_laneId  = 99;
                        m_demoted = true;
                        std::cout << "[FORGIVENESS] CID:" << m_carId
                                  << " BAN#" << m_adverseCount
                                  << " SLOW-LANE EXILE"
                                  << " honest_wins " << before << " → " << m_honestSafeWins
                                  << " (threshold managed by SLOW_LANE handler)\n";
                    }
                }
            }

            // [HONEST-REWARD] Apply tangible benefit if BENEFIT field present
            std::string benefit = ex("BENEFIT");
            if (!benefit.empty()) {
                std::string spdBoostStr = ex("SPD_BOOST");
                double spdBoost = 0.0;
                try { spdBoost = std::stod(spdBoostStr); } catch(...) {}

                if (benefit == "LANE_UPGRADE") {
                    if (m_warnCount > 0 || m_adverseCount > 0 || m_demoted) {
                        std::cout << "[TRUST-BLOCKED] CID:" << m_carId
                                  << " ignored LANE_UPGRADE due to prior WARN/BAN/demotion\n";
                    } else if (!m_laneUpgraded) {
                        m_laneUpgraded        = true;
                        // FP-FIX: keep telemetry lane unchanged.
                        // Lane upgrade is logical/economic only; changing LAN can
                        // indirectly change generated speed and trigger M1 false positives.
                        // m_laneId remains m_originalLaneId.
                        m_originalSpeedNormal = m_speedNormal;

                        // FP-FIX: Do not change telemetry speed as a trust reward.
                        // Speed is also used by the edge anomaly detector M1.
                        // If we boost speed here, an honest rewarded car can look like
                        // a speed attacker and trigger WARN/CUSUM false positives.
                        m_speedBoost          = 0.0;

                        std::cout << "[TRUST-APPLIED] CID:" << m_carId
                                  << " LANE_UPGRADE → logical reward only; telemetry lane unchanged"
                                  << " lane=" << m_laneId << " speed unchanged=" << m_speedNormal << " m/s"
                                  << " [reward-speed disabled to avoid M1 false positive]\n";
                    }
                }
                if (benefit == "REDUCE_SCRUTINY") {
                    if (m_warnCount > 0 || m_adverseCount > 0 || m_demoted) {
                        std::cout << "[TRUST-BLOCKED] CID:" << m_carId
                                  << " ignored REDUCE_SCRUTINY due to prior WARN/BAN/demotion\n";
                    } else if (!m_scrutinyReduced) {
                        m_scrutinyReduced  = true;
                        m_effectiveLatency = EdgeLatencyMs * TRUST_LATENCY_MULT;
                        std::cout << "[TRUST-APPLIED] CID:" << m_carId
                                  << " REDUCE_SCRUTINY → latency="
                                  << m_effectiveLatency << "ms (was "
                                  << EdgeLatencyMs << "ms)\n";
                    }
                }
                if (benefit == "SLOW_LANE") {
                    // [BAN-PUNISH] Confirmed BAN punishment: exile to slowest lane.
                    RevokeTrustBenefits();
                    m_laneId      = 99;
                    m_speedNormal = m_originalSpeedNormal;
                    m_speedAttack = m_originalSpeedNormal;
                    m_speedBoost  = 0.0;
                    m_demoted     = true;
                    uint32_t newThreshold;
                    if (m_returnThreshold == 0)
                        newThreshold = TRUST_LANE_WINS * 4;
                    else
                        newThreshold = m_returnThreshold * 2;
                    m_returnThreshold = std::max(m_returnThreshold, newThreshold);
                    // NOTE: Do NOT physically move the car — NR channel model
                    // crashes on extreme Y coordinates outside road geometry.
                    // Exile is enforced via m_laneId=99 in BSM fields and the
                    // UAV dropping all future packets from banned cars.
                    std::cout << "[BAN-PUNISH] CID:" << m_carId
                              << " SLOW_LANE EXILE → LAN=99 speed=" << m_speedNormal
                              << " m/s  return_threshold=" << m_returnThreshold << "\n";
                }
            }

            // Log for all cars
            std::string icon = (act=="OK") ? "\xe2\x9c\x93"
                             : (act=="WARN") ? "\xe2\x9a\xa0" : "\xe2\x9c\x97";
            std::cout << icon << " [CAR " << m_carId << "]"
                      << " ACT=" << act
                      << " REP=" << std::fixed << std::setprecision(3) << rep
                      << " RWD=" << std::setprecision(3) << rwd
                      << " PNL=" << std::setprecision(3) << pnl
                      << " CREDIT=" << credStr << "\n";

            // Adaptive attackers infer their suspicion from REP.
            // susp_proxy = 1 - REP: REP=0.9 -> low suspicion, REP=0.3 -> high.
            // This is realistic: the car observes its reputation dropping
            // without seeing the internal ML score or Nash threshold.
            if (m_attackType == ATK_RATIONAL    ||
                m_attackType == ATK_INTERMITTENT ||
                m_attackType == ATK_OPTIMAL) {
                // [OBS-NOISE] Imperfect info: car observes suspicion with
                // Gaussian noise sigma=0.08. Cars near p*=0.40 mis-estimate
                // their risk, producing realistic FP/FN variance across seeds.
                // Box-Muller on global rand() — reproducible per --RngRun.
                {
                    double _u1 = ((rand() % 10000) + 0.5) / 10000.0;
                    double _u2 = ((rand() % 10000) + 0.5) / 10000.0;
                    double _noise = ObsNoiseSigma * std::sqrt(-2.0 * std::log(_u1))
                                         * std::cos(2.0 * M_PI * _u2);
                    m_rObsSusp = std::max(0.0, std::min(1.0, 1.0 - rep + _noise));
                }
                if (act == "OK")  { m_rSafeWins++; m_iHonestRun++; }
                else              { m_rSafeWins = 0; m_iHonestRun = 0; }
                if (m_rCooldown > 0) m_rCooldown--;
                // [REALISTIC-RATIONAL] Update learned p* from trial and error.
                // Only updates when the previous packet was an attack — the car
                // learns from outcomes of its own decisions, not from clean packets.
                //   No WARN after attack → system less strict than expected → lower p*
                //   WARN/BAN after attack → system stricter than expected → raise p*
                if (m_attackType == ATK_RATIONAL && m_rLastWasAtk) {
                    double before = m_rLearnedPStar;
                    if (act == "OK") {
                        // Got away — system was more lenient than expected
                        m_rLearnedPStar = std::max(0.05, m_rLearnedPStar - m_rLearnRate);
                    } else {
                        // Got caught — system was stricter than expected
                        m_rLearnedPStar = std::min(0.95, m_rLearnedPStar + m_rLearnRate * 3.0);
                    }
                    std::cout << "[RATIONAL] CID:" << m_carId
                              << " LEARN p*_est " << std::fixed << std::setprecision(3) << before
                              << " → " << m_rLearnedPStar
                              << " (outcome=" << act << ")\n";
                }
                m_rLastWasAtk = false;  // reset — set to true in Send() when attack fires
                // [V81-FIX-A2] trigger wash-out cooldown on WARN/BAN
if ((act == "WARN" || act == "BAN") &&
     m_attackType == ATK_RATIONAL && m_rCooldown == 0) {
    m_rCooldown = 5;
    std::cout << "[RATIONAL] CID:" << m_carId
              << " WARN-COOLDOWN=5 sw-reset\n";
}
                std::cout << "[CTRL-FB] CID:" << m_carId
                          << " susp_proxy=" << std::setprecision(3) << m_rObsSusp
                          << "(rep=" << std::setprecision(3) << rep << "+noise)"
                          << " sw=" << m_rSafeWins
                          << " pnl=" << std::setprecision(3) << pnl
                          << " rwd=" << std::setprecision(3) << rwd << "\n";
            }
        }
    }

    // UAV: receive CLOUDCTRL from cloud -- UNCHANGED
    void ReceiveCloudCtrl(Ptr<Socket> socket) {
        Ptr<Packet> pkt; Address from;
        while ((pkt = socket->RecvFrom(from))) {
            uint8_t buf[1024] = {0};
            pkt->CopyData(buf, pkt->GetSize());
            std::string msg((char*)buf, pkt->GetSize());
            std::cout << "<<< [UAV] Received CLOUDCTRL: " << msg << "\n";
            if (msg.find("CLOUDCTRL") == std::string::npos) continue;

            auto ex = [&](const std::string& k) -> std::string {
                size_t p = msg.find(k + ":"); if (p == std::string::npos) return "?";
                size_t e = msg.find('|', p + k.size() + 1);
                return msg.substr(p + k.size() + 1,
                    e == std::string::npos ? std::string::npos : e - p - k.size() - 1);
            };
            std::string carIpStr = ex("IP");
            std::string cidStr   = ex("CID");
            std::string verdict  = ex("VERDICT");
            Ipv4Address carIp(carIpStr.c_str());

            if (verdict == "BAN") {
                m_bannedCars.insert(carIp);
                if (m_carState.find(carIp) != m_carState.end())
                    m_carState[carIp].banned = true;
                SendCtrlToCar(carIp, BuildCtrlMsg(std::stoul(cidStr), carIpStr,
                                                   "BAN", 0.0, 0.0, "CLOUD_BAN",
                                                   1.0, 5.0, 0));
                std::cout << "<<< [UAV->CAR] Cloud override ? " << carIpStr << " BANNED\n";
            } else if (verdict == "SAFE") {
                auto itState = m_carState.find(carIp);
                if (itState != m_carState.end()) {
                    CarUavState& st = itState->second;
                    st.safeWins++;
                    uint32_t sw = st.safeWins;
                    std::cout << "<<< [UAV] Cloud SAFE: safeWins for "
                              << carIpStr << " = " << sw << "\n";

                    // [HONEST-REWARD] Milestone 1 — fast lane upgrade
                    if (sw == TRUST_LANE_WINS && !(POST_HANDOVER_DISABLE_UPGRADE && st.postHandoverProbation)) {
                        std::cout << "[TRUST-UPGRADE] CID:" << std::stoul(cidStr)
                                  << " earned LANE_UPGRADE after " << sw << " clean packets"
                                  << " → lane 0 + " << TRUST_SPEED_BOOST << " m/s boost\n";
                        SendCtrlToCar(carIp, BuildBenefitCtrl(
                            std::stoul(cidStr), carIpStr,
                            "LANE_UPGRADE", TRUST_SPEED_BOOST, sw));
                    }
                    // [HONEST-REWARD] Milestone 2 — reduced scrutiny
                    if (sw == TRUST_REDUCE_WINS && !(POST_HANDOVER_DISABLE_UPGRADE && st.postHandoverProbation)) {
                        std::cout << "[TRUST-UPGRADE] CID:" << std::stoul(cidStr)
                                  << " earned REDUCE_SCRUTINY after " << sw << " clean packets"
                                  << " → edge latency × " << TRUST_LATENCY_MULT << "\n";
                        st.effectiveLatency = EdgeLatencyMs * TRUST_LATENCY_MULT;
                        SendCtrlToCar(carIp, BuildBenefitCtrl(
                            std::stoul(cidStr), carIpStr,
                            "REDUCE_SCRUTINY", 0.0, sw));
                    }
                }
            }
        }
    }

    // Main receive dispatcher
    void Receive(Ptr<Socket> socket) {
        Ptr<Packet> pkt; Address from;
        while ((pkt = socket->RecvFrom(from))) {
            uint8_t buf[4096] = {0};
            pkt->CopyData(buf, pkt->GetSize());
            std::string msg((char*)buf, pkt->GetSize());
            Ipv4Address sender = InetSocketAddress::ConvertFrom(from).GetIpv4();

            // ===== UAV role =====
            if (m_role == ROLE_UAV) {
                // [ITEM-4] App-layer packet drop (1%).
                // Simulates NR radio impairments, HARQ residual error, and
                // processing overruns at the UAV relay.  A 1% drop rate is
                // conservative but tests whether Bayesian trust still converges
                // under sparse/missing evidence per car.
                // [FIX-A2] Configurable via --PktDropRate (default 1%).
                if ((uint32_t)(rand() % 100) < m_pktDropRate) {
                    std::cout << "[PKT-DROP] UAV dropped telemetry from " << sender
                              << " (drop_rate=" << m_pktDropRate << "%)\n";
                    continue;
                }
                // [FULL-VEREMI-PASSIVE]
                // Receiver-side passive beacon log for offline VeReMi-style baseline.
                // IMPORTANT: logged after simulated UAV packet drop but before proposed-method
                // BAN suppression, edge AI call, Bayesian update, CUSUM update, or trust action.
                // Ground-truth labels are NOT included here; join with [PAYOFF] during offline analysis.
                {
                    uint32_t pbCid = 0;
                    double pbTs = 0.0, pbSpd = 0.0, pbHdg = 0.0, pbPx = 0.0, pbPy = 0.0;
                    int pbLan = -1, pbBrk = -1;

                    size_t pb_cp = msg.find("CID:");
                    if (pb_cp != std::string::npos) {
                        try { pbCid = static_cast<uint32_t>(std::stoul(msg.substr(pb_cp + 4))); } catch (...) {}
                    }

                    size_t pb_tsp = msg.find("TS:");
                    if (pb_tsp != std::string::npos) {
                        try { pbTs = std::stod(msg.substr(pb_tsp + 3)); } catch (...) {}
                    }

                    size_t pb_spdp = msg.find("SPD:");
                    if (pb_spdp != std::string::npos) {
                        try { pbSpd = std::stod(msg.substr(pb_spdp + 4)); } catch (...) {}
                    }

                    size_t pb_hdgp = msg.find("HDG:");
                    if (pb_hdgp != std::string::npos) {
                        try { pbHdg = std::stod(msg.substr(pb_hdgp + 4)); } catch (...) {}
                    }

                    size_t pb_pxp = msg.find("PX:");
                    if (pb_pxp != std::string::npos) {
                        try { pbPx = std::stod(msg.substr(pb_pxp + 3)); } catch (...) {}
                    }

                    size_t pb_pyp = msg.find("PY:");
                    if (pb_pyp != std::string::npos) {
                        try { pbPy = std::stod(msg.substr(pb_pyp + 3)); } catch (...) {}
                    }

                    size_t pb_lanp = msg.find("LAN:");
                    if (pb_lanp != std::string::npos) {
                        try { pbLan = std::stoi(msg.substr(pb_lanp + 4)); } catch (...) {}
                    }

                    size_t pb_brkp = msg.find("BRK:");
                    if (pb_brkp != std::string::npos) {
                        try { pbBrk = std::stoi(msg.substr(pb_brkp + 4)); } catch (...) {}
                    }

                    double pbSimNow = Simulator::Now().GetSeconds();

                    double pbZLen = std::max(1.0, HTD_ZONE_LENGTH_M);
                    double pbLead = std::max(0.0, HTD_HANDOVER_LEAD_M);
                    uint32_t pbZone = static_cast<uint32_t>(std::floor((pbPx + pbLead) / pbZLen)) + 1;
                    if (pbZone < 1) pbZone = 1;

                    uint16_t pbEdgePort = m_edgePort;
                    if (pbZone >= 2 && m_edgePortZ2 > 0) {
                        pbEdgePort = m_edgePortZ2;
                    }

                    double rxX = 0.0, rxY = 0.0, rxZ = 0.0;
                    if (m_node) {
                        Ptr<MobilityModel> rxMob = m_node->GetObject<MobilityModel>();
                        if (rxMob) {
                            Vector rxPos = rxMob->GetPosition();
                            rxX = rxPos.x;
                            rxY = rxPos.y;
                            rxZ = rxPos.z;
                        }
                    }

                    std::ostringstream pb;
                    pb << "[PASSIVE-BEACON]"
                       << " SIMNOW:" << std::fixed << std::setprecision(3) << pbSimNow
                       << " CID:" << pbCid
                       << " ZONE:" << pbZone
                       << " RXUAV:" << ((pbZone >= 2 && m_edgePortZ2 > 0) ? 2 : 1)
                       << " EDGEPORT:" << pbEdgePort
                       << " TS:" << std::fixed << std::setprecision(3) << pbTs
                       << " SPD:" << std::fixed << std::setprecision(3) << pbSpd
                       << " HDG:" << std::fixed << std::setprecision(3) << pbHdg
                       << " PX:" << std::fixed << std::setprecision(3) << pbPx
                       << " PY:" << std::fixed << std::setprecision(3) << pbPy
                       << " LAN:" << pbLan
                       << " BRK:" << pbBrk
                       << " RX_X:" << std::fixed << std::setprecision(3) << rxX
                       << " RX_Y:" << std::fixed << std::setprecision(3) << rxY
                       << " RX_Z:" << std::fixed << std::setprecision(3) << rxZ;
                    std::cout << pb.str() << "\n";
                }

                if (m_carState.find(sender) == m_carState.end()) {
                    CarUavState st; st.cid = 0;
                    st.effectiveLatency = EdgeLatencyMs;
                    m_carState[sender] = st;
                }
                CarUavState& st = m_carState[sender];

                size_t cp = msg.find("CID:");
                if (cp != std::string::npos) {
                    try { st.cid = std::stoul(msg.substr(cp + 4)); } catch (...) {}
                }

                st.carClass = (st.cid % 5 == 1) ? 1 : 0;

                // [HD-DEFENSE] Parse car position and detect handover trigger crossing.
                // The defense fires at the handover trigger point (zoneEnd - lead),
                // not at the physical zone exit.  For n zones, a car enters the
                // post-handover monitoring state at each transition i -> i+1.
                {
                    double car_px = 0.0;
                    size_t pp = msg.find("PX:");
                    if (pp != std::string::npos)
                        try { car_px = std::stod(msg.substr(pp + 3)); } catch (...) {}

                    double zLen = std::max(1.0, HTD_ZONE_LENGTH_M);
                    double lead = std::max(0.0, HTD_HANDOVER_LEAD_M);
                    uint32_t triggerZone = static_cast<uint32_t>(std::floor((car_px + lead) / zLen)) + 1;
                    if (triggerZone < 1) triggerZone = 1;

                    // [RACE-FIX] Parse the car's self-reported handover confirmation.
                    // Do not flip zones / reroute this car's beacons to the new edge
                    // until it has confirmed (via HOK) that TRUST_HANDOVER_LOAD was
                    // actually delivered -- otherwise the new edge may score this car
                    // cold-start before its history/probation state has arrived.
                    uint32_t carHok = 0;
                    size_t hokp = msg.find("HOK:");
                    if (hokp != std::string::npos) {
                        try { carHok = std::stoul(msg.substr(hokp + 4)); } catch (...) {}
                    }

                    if (triggerZone > st.currentZone && carHok >= triggerZone) {
                        uint32_t fromZone = st.currentZone;
                        uint32_t toZone   = triggerZone;
                        st.currentZone = toZone;
                        st.lastDefenseZone = toZone;
                        st.postHandoverProbation = true;
                        st.postHandoverPktCount  = 0;
                        st.lastHandoverSimTime   = Simulator::Now().GetSeconds();

                        if (HANDOVER_TRUST_DISCOUNT < 1.0) {
                            double old_alpha = st.alpha;
                            double old_beta  = st.beta;
                            st.alpha = NASH_ALPHA0
                                     + HANDOVER_TRUST_DISCOUNT * (st.alpha - NASH_ALPHA0);
                            st.beta  = NASH_BETA0
                                     + HANDOVER_TRUST_DISCOUNT * (st.beta  - NASH_BETA0);
                            st.obsCount = 0;
                            st.recentBanWindow.clear();
                            st.handoverDiscountApplied = true;
                            std::cout << "[HTD] CID:" << st.cid
                                      << " handover Z" << fromZone << "->Z" << toZone
                                      << " trust discounted at PX="
                                      << std::fixed << std::setprecision(1) << car_px
                                      << " delta=" << HANDOVER_TRUST_DISCOUNT
                                      << " alpha:" << old_alpha << "->" << st.alpha
                                      << " beta:"  << old_beta  << "->" << st.beta
                                      << " obs/window reset probationK=" << POST_HANDOVER_PROBATION_PKTS << "\n";
                        } else {
                            std::cout << "[HTD] CID:" << st.cid
                                      << " handover Z" << fromZone << "->Z" << toZone
                                      << " full trust retained delta=1.0 probationK="
                                      << POST_HANDOVER_PROBATION_PKTS << "\n";
                        }

                        if (!DISABLE_CUSUM) {
                            st.cusum_active = true;
                            st.cusum_S = 0.0;
                            st.cusum_warmup_pkts = 0;
                            std::cout << "[CUSUM] CID:" << st.cid
                                      << " activated at HANDOVER Z" << fromZone << "->Z" << toZone
                                      << " PX=" << std::fixed << std::setprecision(1) << car_px
                                      << " warmupK=" << CUSUM_WARMUP_K
                                      << " mu0=" << CUSUM_MU0
                                      << " h=" << CUSUM_H << "\n";
                        }
                    }
                }

                // [BAN-CONTINUE-MOVED] Skip scoring/forwarding for banned cars,
                // but only AFTER zone-crossing/handover bookkeeping above has
                // already run -- a banned car's zone tracking must stay accurate
                // (e.g. if it later returns to good standing via
                // return_threshold, it must not be permanently stuck being
                // scored by a stale zone's edge).
                if (m_bannedCars.count(sender)) continue;

                double simNow = Simulator::Now().GetSeconds();

                std::string carMsgSpaces = msg;
                std::replace(carMsgSpaces.begin(), carMsgSpaces.end(), '|', ' ');

                std::string edgeTelem = "TELEM " + carMsgSpaces
                                        + " SAFE_WINS:" + std::to_string(st.safeWins)
                                        + " CLASS:"     + std::to_string(st.carClass)
                                        + " ZONE_ID:"   + std::to_string(st.currentZone)
                                        + " SIMNOW:"    + std::to_string(simNow);

                // [ZONE-ROUTE] After handover, route normal telemetry to Zone-2 bridge.
                uint16_t selectedEdgePort = m_edgePort;
                if (st.currentZone >= 2 && m_edgePortZ2 > 0) {
                    selectedEdgePort = m_edgePortZ2;
                }
                std::cout << "[ZONE-ROUTE] CID:" << st.cid
                          << " zone=" << st.currentZone
                          << " edge_port=" << selectedEdgePort << "\n";

                // [LATENCY-MODEL] measure wall-clock RTT of Edge AI call
                auto _t0_edge = std::chrono::steady_clock::now();
                std::string edgeResp = TcpCallFramed(m_edgeAddr.c_str(), selectedEdgePort, edgeTelem,
                    "SAFE CID:0 TS:0 SPD:0 HDG:0 PX:0 PY:0 LAN:1 BRK:0 SUSP:0.000 CLEAN_CONF:1.000 EDGE_FALLBACK SNRFALLBACK");
                auto _t1_edge = std::chrono::steady_clock::now();
                double _rtt_edge_ms = std::chrono::duration<double,std::milli>(_t1_edge - _t0_edge).count();
                std::cout << "[EDGE-RTT] CID:" << st.cid
                          << " wall=" << std::fixed << std::setprecision(1) << _rtt_edge_ms
                          << " ms  sim_delay=" << st.effectiveLatency << " ms\n";

                double pEdge    = 0.5;
                std::string sv  = ParseKV(edgeResp, "SUSP");
                if (!sv.empty()) {
                    try { pEdge = std::stod(sv); } catch (...) {}
                } else {
                    std::string cv = ParseKV(edgeResp, "CONF");
                    if (!cv.empty()) try { pEdge = std::stod(cv); } catch (...) {}
                }
                // [RACE-FIX] The one-shot handover trigger ACK is deliberately
                // non-blocking (edge dispatches to the coordinator in a
                // background thread) and never carries confirmation. Instead,
                // pick up confirmation from the regular, synchronous TELEM
                // response, which the edge stamps with HREADY once its
                // background dispatch to the coordinator has completed.
                std::string hrStr = ParseKV(edgeResp, "HREADY");
                if (!hrStr.empty()) {
                    try {
                        uint32_t hReadyZone = static_cast<uint32_t>(std::stoul(hrStr));
                        if (hReadyZone > m_handoverConfirmedZone) {
                            m_handoverConfirmedZone = hReadyZone;
                        }
                    } catch (...) {}
                }
                bool isFallback = (edgeResp.find("SNRFALLBACK") != std::string::npos);
                bool isBan      = (!isFallback && edgeResp.size() >= 3 && edgeResp.substr(0,3) == "BAN");
                bool isWarn     = (!isFallback && edgeResp.size() >= 4 && edgeResp.substr(0,4) == "WARN");

                // [RATIONAL-FEEDBACK] m_rObsSusp is now updated on the CAR side
                // via ReceiveCtrl() when the ctrl message arrives -- not here.
                // The UAV role processes a different car each packet; updating
                // m_rObsSusp here would corrupt the UAV instance, not the car.

                std::string why    = isBan ? "EDGE_BAN" : isWarn ? "EDGE_MALICIOUS" : "EDGE_SAFE";
                bool        shadow = isWarn || isBan;

                if (isFallback) {
                    double p_car_fb  = (st.alpha + st.beta > 0) ? st.beta / (st.alpha + st.beta) : 0.0;
                    double T_star_fb = ComputeNashThreshold(p_car_fb);
                    std::ostringstream ossFb; ossFb << sender;
                    SendCtrlToCar(sender, BuildCtrlMsg(st.cid, ossFb.str(),
                                                       "OK", 0.0, T_star_fb, "EDGE_UNAVAILABLE",
                                                       st.alpha, st.beta, st.safeWins));
                    std::cout << "[EDGE-FALLBACK] CID:" << st.cid
                              << " sender=" << sender
                              << " -> hold state (no alpha/beta update)\n";
                    continue;
                }

                if (isBan) {
                    st.banStreak++;
                    st.warnStreak = 0;
                } else if (isWarn) {
                    st.warnStreak++;
                    st.banStreak = 0;
                } else {
                    st.banStreak  = 0;
                    st.warnStreak = 0;
                }
                st.obsCount++;   // [BAYESIAN-GATE] one packet processed, regardless of verdict
                st.recentBanWindow.push_back(isBan ? 1 : 0);
                if (st.recentBanWindow.size() > static_cast<size_t>(FINAL_BAN_WINDOW_PKTS)) {
                    st.recentBanWindow.erase(st.recentBanWindow.begin());
                }
                uint32_t recentBanHits = 0;
                for (uint8_t v : st.recentBanWindow) recentBanHits += v;

                // [ADAPTIVE-NASH] update population-level counters before gate decision
                m_popTotalObs++;   // warmup counter only
                double adaptive_p_star = ComputeAdaptiveNashPStar();
                // rho_hat for logging — matches the Bayesian-weighted value
                // used inside ComputeAdaptiveNashPStar() above
                double rho_hat = 0.0;
                { double sp = 0.0; uint32_t nc = 0;
                  for (const auto& kv : m_carState) {
                      double ab = kv.second.alpha + kv.second.beta;
                      if (ab > 0.0) { sp += kv.second.beta / ab; nc++; }
                  }
                  if (nc > 0) rho_hat = std::min(1.0, sp / (double)nc); }

                // Update Bayesian alpha/beta
                // [CREDIT-DISCOUNT] Honest cars with prior safe history earn a
                // reduced effective GAME_Cf — makes honesty a compounding investment.
                double effectiveCreditDiscount = st.creditDiscount;
                if (st.postHandoverProbation) {
                    effectiveCreditDiscount *= POST_HANDOVER_CREDIT_FACTOR;
                }
                double effectiveCf = GAME_Cf * (1.0 - effectiveCreditDiscount);
                if (isBan) {
                    st.beta += effectiveCf;
                } else if (isWarn) {
                    st.beta += effectiveCf * pEdge;
                } else {
                    st.alpha += GAME_Rs * (1.0 - pEdge);
                }

                double p_car  = (st.alpha + st.beta > 0) ? st.beta / (st.alpha + st.beta) : 0.0;
                double T_star = ComputeNashThreshold(p_car);

                // [CUSUM] Post-handover sequential change-point detector.
                // Runs in parallel with the Bayesian gate.  If CUSUM detects
                // a behavioral change (S_k > h), convict immediately — this
                // catches late-entry attackers that the Bayesian gate cannot
                // convict due to trust inertia from Zone 1 clean history.
                // S₀=0 at zone crossing → detection delay depends only on
                // post-change score magnitude, not on Zone 1 history length.
                if (st.cusum_active && !st.banned) {
                    st.cusum_warmup_pkts++;
                    if (st.cusum_warmup_pkts <= CUSUM_WARMUP_K) {
                        // [CUSUM-WARMUP] Still in warmup window — observe only,
                        // do not accumulate. Edge baseline not yet stable.
                        std::cout << "[CUSUM-WARMUP] CID:" << st.cid
                                  << " warmup " << st.cusum_warmup_pkts
                                  << "/" << CUSUM_WARMUP_K
                                  << " pEdge=" << pEdge << " (skipping)\n";
                    } else {
                    st.cusum_S = std::max(0.0, st.cusum_S + pEdge - CUSUM_MU0);
                    // [CUSUM-OBS-GATE] CUSUM conviction requires the same
                    // minimum observation count as the Nash Bayesian gate.
                    // Without this, CUSUM bypasses the evidence floor that
                    // prevents the Nash gate from convicting on insufficient
                    // data — exactly what happened with CID:4: Nash gate
                    // correctly held at obs=4-8/15, CUSUM fired anyway.
                    // CUSUM is a complementary signal, not a bypass path.
                    if (st.cusum_S > CUSUM_H && st.obsCount >= MIN_OBSERVATIONS_BEFORE_BAN) {
                        st.banned = true;
                        m_bannedCars.insert(sender);
                        std::ostringstream ossCusum; ossCusum << sender;
                        std::string banPunishCtrl = BuildBanPunishCtrl(
                            st.cid, ossCusum.str(), pEdge, T_star,
                            st.alpha, st.beta, st.safeWins);
                        // [HREADY-CTRL-FIX] Forward the UAV's HREADY confirmation
                        // (learned from the edge's TELEM response) to the CAR via
                        // the control channel it actually listens to -- ReceiveCtrl.
                        banPunishCtrl += "|HREADY:" + (hrStr.empty() ? std::string("0") : hrStr);
                        Simulator::Schedule(MilliSeconds((uint64_t)std::max(1.0, _rtt_edge_ms)),
                                            &UnifiedApp::SendCtrlToCarDelayed, this, sender, banPunishCtrl);
                        // Ledger entry for audit trail
                        {
                            std::ofstream ledger(LEDGER_FILE, std::ios::app);
                            if (ledger.is_open()) {
                                ledger << "{\"blk\":0,\"t\":"  << Simulator::Now().GetSeconds()
                                       << ",\"cid\":"          << st.cid
                                       << ",\"evt\":\"BAN00001\""
                                       << ",\"zone_id\":"      << st.currentZone
                                       << ",\"handover\":true"
                                       << ",\"post_handover_pkt\":" << st.postHandoverPktCount
                                       << ",\"reason\":\"CUSUM_CHANGEPOINT\""
                                       << ",\"scr\":"          << std::fixed << std::setprecision(3) << pEdge
                                       << ",\"hash\":\"dummy\",\"prev\":\"dummy\""
                                       << ",\"note\":\"CUSUM_CHANGEPOINT_S="
                                       << std::setprecision(3) << st.cusum_S << "\"}\n";
                            }
                        }
                        std::cout << "[CUSUM-BAN] CID:" << st.cid
                                  << " change-point detected S="
                                  << std::fixed << std::setprecision(3) << st.cusum_S
                                  << " > h=" << CUSUM_H
                                  << " pEdge=" << pEdge
                                  << " (post-handover behavioral change)\n";
                        continue;  // skip Bayesian gate — already convicted
                    } else {
                        std::cout << "[CUSUM] CID:" << st.cid
                                  << " S=" << std::fixed << std::setprecision(3) << st.cusum_S
                                  << "/" << CUSUM_H
                                  << " pEdge=" << pEdge << "\n";
                    }
                    } // end cusum_warmup_pkts > CUSUM_WARMUP_K
                }

                // [BAYESIAN-GATE] Replaces the prior streak-based force-ban triggers
                // (WarnForceBanStreak / WarnRatio). Conviction is now driven solely by
                // accumulated Bayesian evidence (st.alpha/st.beta -- a Beta-reputation
                // estimator, see Beta reputation systems literature, e.g. Josang &
                // Ismail 2002) gated on total observation count, not on consecutive-
                // signal streaks. This removes two failure modes confirmed in testing:
                // (1) deadlock -- a persistent attacker that occasionally produces one
                //     clean packet could reset a streak counter indefinitely, blocking
                //     conviction forever even with overwhelming cumulative evidence;
                // (2) false-positive streaks -- an honest car experiencing a short run
                //     of noisy packets (e.g. near the cross-zone handover point) could
                //     complete a short streak threshold and be wrongly convicted.
                // p_car decays/grows smoothly with every packet (no hard reset), so
                // neither failure mode is structurally possible: persistent evidence
                // accumulates in p_car regardless of occasional contrary packets, and
                // a brief noisy run from an honest car is diluted by its surrounding
                // clean history rather than triggering an isolated streak match.
                // [BAYESIAN-GATE] Use the plain per-packet obsCount, NOT alpha+beta
                // (see struct field comment -- alpha/beta are weighted by GAME_Cf/
                // GAME_Rs/pEdge and do not represent a neutral observation count).
                bool hasEnoughObservations = (st.obsCount >= MIN_OBSERVATIONS_BEFORE_BAN);

                if (isBan) {
                    // Nash gate v3 — adaptive p* version.
                    // p*(t) adapts to observed attacker density rho_hat so the gate
                    // tightens automatically under high-attack conditions and relaxes
                    // when the network appears clean, reducing false positives.
                    double eu_ban   =  pEdge * BAN_REWARD  - (1.0 - pEdge) * FALSE_BAN_COST;
                    double eu_trust = (1.0 - pEdge) * REWARD - pEdge * CHASE_COST;
                    bool nashConfirmsBan = (pEdge > adaptive_p_star && eu_ban > eu_trust);
                    bool windowConfirms  = (recentBanHits >= static_cast<uint32_t>(FINAL_BAN_REQUIRED));
                    // [BAYESIAN-GATE] hasEnoughObservations (computed earlier in this
                    // block, from total alpha+beta evidence) replaces the old
                    // safeWins-based hasMinHistory gate. See rationale above.

                    std::ostringstream ossN; ossN << sender;
                    std::string banCtrl  = BuildCtrlMsg(st.cid, ossN.str(), "BAN",  pEdge, T_star, "EDGE_NASH_BAN",
                                                        st.alpha, st.beta, st.safeWins);
                    std::string warnCtrl = BuildCtrlMsg(st.cid, ossN.str(), "WARN", pEdge, T_star,
                                                        nashConfirmsBan ? "EDGE_NASH_PENDING" : "EDGE_BAN_NASH_OVERRIDE",
                                                        st.alpha, st.beta, st.safeWins);
                    warnCtrl += "|HREADY:" + (hrStr.empty() ? std::string("0") : hrStr);

                    if (nashConfirmsBan && windowConfirms && hasEnoughObservations) {
                        st.banned = true;
                        m_bannedCars.insert(sender);
                        // [BAN-PUNISH] Send BAN with embedded SLOW_LANE punishment.
                        // Car is exiled to LAN=99 immediately on receipt.
                        // return_threshold doubles with each BAN — recovery very slow.
                        std::ostringstream ossBan; ossBan << sender;
                        std::string banPunishCtrl = BuildBanPunishCtrl(
                            st.cid, ossBan.str(), pEdge, T_star,
                            st.alpha, st.beta, st.safeWins);
                        banPunishCtrl += "|HREADY:" + (hrStr.empty() ? std::string("0") : hrStr);
                        Simulator::Schedule(MilliSeconds((uint64_t)std::max(1.0, _rtt_edge_ms)),
                                            &UnifiedApp::SendCtrlToCarDelayed, this, sender, banPunishCtrl);
                        std::cout << "[NASH-GATE] CID:" << st.cid
                                  << " p=" << std::fixed << std::setprecision(3) << pEdge
                                  << " p*=" << adaptive_p_star
                                  << " rho_hat=" << rho_hat
                                  << " streak=" << st.banStreak
                                  << " windowHits=" << recentBanHits << "/" << FINAL_BAN_WINDOW_PKTS
                                  << " EU_ban=" << eu_ban
                                  << " -> CONFIRMED BAN (SLOW_LANE punishment sent)\n";
                    } else if (nashConfirmsBan && !windowConfirms) {
                        Simulator::Schedule(MilliSeconds((uint64_t)std::max(1.0, _rtt_edge_ms)),
                                            &UnifiedApp::SendCtrlToCarDelayed, this, sender, warnCtrl);
                        std::cout << "[NASH-GATE] CID:" << st.cid
                                  << " p=" << pEdge
                                  << " p*=" << adaptive_p_star
                                  << " rho_hat=" << rho_hat
                                  << " Nash=BAN windowHits=" << recentBanHits
                                  << "/" << FINAL_BAN_WINDOW_PKTS
                                  << " -> WARN (pending confirmation)\n";
                    } else {
                        Simulator::Schedule(MilliSeconds((uint64_t)std::max(1.0, _rtt_edge_ms)),
                                            &UnifiedApp::SendCtrlToCarDelayed, this, sender, warnCtrl);
                        std::cout << "[NASH-GATE] CID:" << st.cid
                                  << " p=" << pEdge
                                  << " p*=" << adaptive_p_star
                                  << " EDGE=BAN nashConfirms=" << (nashConfirmsBan ? "Y" : "N")
                                  << " windowConfirms=" << (windowConfirms ? "Y" : "N")
                                  << " obs=" << st.obsCount
                                  << "/" << MIN_OBSERVATIONS_BEFORE_BAN
                                  << " p_car=" << std::fixed << std::setprecision(3) << p_car
                                  << " -> WARN (insufficient evidence)\n";
                    }
                    continue;
                }

                // [LATENCY-MODEL] defer OK/WARN ctrl by EdgeLatencyMs in simulation time
                std::ostringstream oss2; oss2 << sender;
                std::string okWarnCtrl = BuildCtrlMsg(st.cid, oss2.str(),
                                                      isWarn ? "WARN" : "OK",
                                                      pEdge, T_star, why,
                                                      st.alpha, st.beta, st.safeWins);
                okWarnCtrl += "|HREADY:" + (hrStr.empty() ? std::string("0") : hrStr);
                Simulator::Schedule(MilliSeconds((uint64_t)std::max(1.0, _rtt_edge_ms)),
                                    &UnifiedApp::SendCtrlToCarDelayed, this, sender, okWarnCtrl);

                // [HONEST-REWARD] Increment safeWins on edge-only SAFE verdict.
                // In bridge mode (FORWARD_WARNS=0, FORWARD_BANS=0) ReceiveCloudCtrl
                // never fires for regular traffic, so safeWins must be maintained here.
                // Only increment on a clean SAFE — WARN or BAN resets the streak.
                if (!isWarn && !isBan && !isFallback) {
                    st.safeWins++;
                    uint32_t sw = st.safeWins;
                    std::ostringstream ossCarIp; ossCarIp << sender;
                    std::string carIpStr2 = ossCarIp.str();
                    // Milestone 1 — fast lane upgrade
                    if (sw == TRUST_LANE_WINS && !(POST_HANDOVER_DISABLE_UPGRADE && st.postHandoverProbation)) {
                        std::cout << "[TRUST-UPGRADE] CID:" << st.cid
                                  << " earned LANE_UPGRADE after " << sw << " clean packets"
                                  << " → lane 0 + " << TRUST_SPEED_BOOST << " m/s\n";
                        SendCtrlToCar(sender, BuildBenefitCtrl(
                            st.cid, carIpStr2, "LANE_UPGRADE", TRUST_SPEED_BOOST, sw));
                    }
                    // Milestone 2 — reduced scrutiny
                    if (sw == TRUST_REDUCE_WINS && !(POST_HANDOVER_DISABLE_UPGRADE && st.postHandoverProbation)) {
                        std::cout << "[TRUST-UPGRADE] CID:" << st.cid
                                  << " earned REDUCE_SCRUTINY after " << sw << " clean packets"
                                  << " → latency × " << TRUST_LATENCY_MULT << "\n";
                        st.effectiveLatency = EdgeLatencyMs * TRUST_LATENCY_MULT;
                        SendCtrlToCar(sender, BuildBenefitCtrl(
                            st.cid, carIpStr2, "REDUCE_SCRUTINY", 0.0, sw));
                    }
                } else if (isWarn || isBan) {
                    st.safeWins = 0;   // streak resets on any adverse verdict
                }

                // [HD-DEFENSE] Advance probation window after a real post-handover packet.
                if (st.postHandoverProbation) {
                    st.postHandoverPktCount++;
                    std::cout << "[POST-HANDOVER] CID:" << st.cid
                              << " zone=" << st.currentZone
                              << " pkt=" << st.postHandoverPktCount << "/" << POST_HANDOVER_PROBATION_PKTS
                              << " credit_factor=" << POST_HANDOVER_CREDIT_FACTOR << "\n";
                    if (st.postHandoverPktCount >= POST_HANDOVER_PROBATION_PKTS) {
                        st.postHandoverProbation = false;
                        std::cout << "[POST-HANDOVER-END] CID:" << st.cid
                                  << " zone=" << st.currentZone
                                  << " probation complete\n";
                    }
                }

                double safety = 1.0 - pEdge;
                double ts = 0, spd = 0, px = 0;
                size_t tsp  = msg.find("TS:");  if (tsp  != std::string::npos) try { ts  = std::stod(msg.substr(tsp+3));  } catch(...) {}
                size_t spdp = msg.find("SPD:"); if (spdp != std::string::npos) try { spd = std::stod(msg.substr(spdp+4)); } catch(...) {}
                size_t pxp  = msg.find("PX:");  if (pxp  != std::string::npos) try { px  = std::stod(msg.substr(pxp+3));  } catch(...) {}

                std::ostringstream oss3; oss3 << sender;
                std::string eb = BuildEnrichedBlock(oss3.str(), msg,
                                                    safety, st.alpha, st.beta,
                                                    st.safeWins, st.carClass,
                                                    st.seq++, shadow, st.cid,
                                                    ts, spd, px);
                m_socket->SendTo(
                    Create<Packet>((uint8_t*)eb.c_str(), eb.length()),
                    0, InetSocketAddress(m_destAddr, m_port));
                std::cout << ">>> [UAV->CLOUD] " << eb.substr(0, 72) << "...\n";

                // [LEDGER-BRIDGE] Write verdict to ledger in bridge mode.
                // In bridge mode the HOST-role ledger path never runs (InternalCloud=0).
                // The UAV role receives every edge verdict and is the correct place to
                // record the honest/malicious history that ReadPriorSafeWins() reads back
                // at zone entry to compute the CREDIT discount.
                // Write every SAFE (honest packet) and every confirmed BAN.
                // WARNs are not written — they are provisional, not settled verdicts.
                if (!isFallback && (isBan || (!isBan && !isWarn))) {
                    std::ofstream ledger(LEDGER_FILE, std::ios::app);
                    if (ledger.is_open()) {
                        std::string evt = isBan ? "BAN00001" : "SAFE00001";
                        ledger << "{\"blk\":0,\"t\":"  << Simulator::Now().GetSeconds()
                               << ",\"cid\":"          << st.cid
                               << ",\"evt\":\""        << evt << "\""
                               << ",\"zone_id\":"      << st.currentZone
                               << ",\"handover\":"     << (st.postHandoverProbation ? "true" : "false")
                               << ",\"post_handover_pkt\":" << (st.postHandoverProbation ? st.postHandoverPktCount : 0)
                               << ",\"reason\":\""     << (isBan ? "BRIDGE_BAN" : "BRIDGE_SAFE") << "\""
                               << ",\"scr\":"          << std::fixed << std::setprecision(3)
                                                       << (isBan ? pEdge : 1.0 - pEdge)
                               << ",\"hash\":\"dummy\",\"prev\":\"dummy\""
                               << ",\"note\":\"BRIDGE_" << (isBan ? "BAN" : "SAFE") << "\"}\n";
                    }
                }
            }

            // ===== Cloud HOST role =====
            else if (m_role == ROLE_HOST) {
                auto ex = [&](const std::string& k) -> std::string {
                    size_t p = msg.find(k + ":"); if (p == std::string::npos) return "?";
                    size_t e = msg.find('|', p + k.size() + 1);
                    return msg.substr(p + k.size() + 1,
                        e == std::string::npos ? std::string::npos : e - p - k.size() - 1);
                };

                std::string txIp   = ex("TX");
                std::string cidStr = ex("CID");
                uint32_t    cid    = 0;
                try { cid = std::stoul(cidStr); } catch (...) {}

                EnrichedBlock blk;
                blk.raw = msg; blk.cid = cid;
                std::string scrStr = ex("SCR");      if (!scrStr.empty()) try { blk.scr      = std::stod(scrStr);  } catch (...) {}
                std::string spdStr = ex("SPD");      if (!spdStr.empty()) try { blk.spd      = std::stod(spdStr);  } catch (...) {}
                std::string pxStr  = ex("PX");       if (!pxStr.empty())  try { blk.px       = std::stod(pxStr);   } catch (...) {}
                std::string swStr  = ex("SAFE_WINS");if (!swStr.empty())  try { blk.safeWins = std::stoul(swStr);  } catch (...) {}
                std::string clStr  = ex("CLASS");    if (!clStr.empty())  try { blk.carClass = std::stoul(clStr);  } catch (...) {}
                std::string shStr  = ex("SHADOW");   if (!shStr.empty())  try { blk.shadow   = (shStr == "1");     } catch (...) {}
                std::string tsStr  = ex("TS");       if (!tsStr.empty())  try { blk.ts       = std::stod(tsStr);   } catch (...) {}

                // [LEDGER-FIRST-PACKET] Check ban history on the FIRST packet
                // from any car IP, regardless of bridge/internal-cloud mode.
                // This closes the 2-3s trust gap and ensures cross-session
                // ban continuity even in bridge mode (--InternalCloud=0).
                // The ledger is written by the cloud LLM on the DGX and
                // read here on the ns3 host -- the only shared artefact.
                bool isNewCar = (m_cloudBuffer.find(txIp) == m_cloudBuffer.end()
                              || m_cloudBuffer[txIp].empty());
                if (isNewCar) {
                    int priorBans = ReadPriorBans(cid);
                    if (priorBans > 0) {
                        // Car has prior bans -- pre-load Bayesian state with
                        // elevated suspicion before any edge AI inference.
                        // UAV state is updated via the existing m_carState map.
                        std::cout << "[LEDGER-GATE] CID:" << cid
                                  << " IP:" << txIp
                                  << " PRIOR_BANS=" << priorBans
                                  << " -> pre-flagged on first packet\n";
                        // Inject prior ban evidence into UAV Bayesian state
                        // by sending a synthetic CLOUD_BAN ctrl to the UAV
                        // so it immediately marks this car as suspicious.
                        Ipv4Address uavCtrl = m_uavCtrlAddr;
                        std::string ledgerBanMsg =
                            std::string("CLOUDCTRL|CID:") + cidStr
                            + "|IP:" + txIp
                            + "|VERDICT:BAN|REASON:LEDGER_PRIOR_BAN";
                        // ROLE_HOST never creates m_ctrlSocket, so send the
                        // synthetic ledger BAN via the always-present data
                        // socket (m_socket), which is already bound on the
                        // host app and can transmit to the UAV cloud-control
                        // port 9002.
                        if (m_socket) {
                            m_socket->SendTo(
                                Create<Packet>((uint8_t*)ledgerBanMsg.c_str(),
                                               ledgerBanMsg.length()),
                                0, InetSocketAddress(uavCtrl, 9002));
                        }
                    }

                    // [CREDIT-DISCOUNT] Honest cars earn a GAME_Cf discount
                    // proportional to their prior safe-win history in the ledger.
                    // This makes honesty a compounding investment: a car that has
                    // been consistently honest across zones faces a lower penalty
                    // rate on borderline verdicts, making continued honesty rational
                    // even for high-temptation agents (T_i > 1.5).
                    int priorSafeWins = ReadPriorSafeWins(cid);
                    if (priorSafeWins > 0 && priorBans == 0) {
                        // Only grant discount if car has no prior bans --
                        // a car that has been banned cannot cash in safe history.
                        double discount = std::min(CREDIT_DISCOUNT_MAX,
                            priorSafeWins * CREDIT_DISCOUNT_PER_WIN);
                        // Store discount in UAV state — applied per-packet in beta update.
                        if (m_carState.find(Ipv4Address(txIp.c_str())) != m_carState.end()) {
                            m_carState[Ipv4Address(txIp.c_str())].creditDiscount = discount;
                        }
                        std::cout << "[CREDIT-DISCOUNT] CID:" << cid
                                  << " prior_safe_wins=" << priorSafeWins
                                  << " discount=" << std::fixed << std::setprecision(3) << discount
                                  << " -> effective_Cf=" << std::setprecision(3)
                                  << (GAME_Cf * (1.0 - discount)) << "\n";
                    }
                }

                m_cloudBuffer[txIp].push_back(blk);
                if (m_windowStart.find(txIp) == m_windowStart.end())
                    m_windowStart[txIp] = Simulator::Now().GetSeconds();

                double elapsed = Simulator::Now().GetSeconds() - m_windowStart[txIp];
                size_t bufSize = m_cloudBuffer[txIp].size();

                double sumScr = 0, sumSpd = 0, maxPx = -1e9, minPx = 1e9;
                uint32_t shadowCount = 0;
                for (const auto& b : m_cloudBuffer[txIp]) {
                    sumScr += b.scr; sumSpd += b.spd;
                    if (b.px > maxPx) maxPx = b.px;
                    if (b.px < minPx) minPx = b.px;
                    if (b.shadow) shadowCount++;
                }
                double avgScr  = (bufSize > 0) ? sumScr / bufSize : 1.0;  // legacy clean-confidence in INTERNAL-CLOUD mode
                double avgSpd  = (bufSize > 0) ? sumSpd / bufSize : SPEED_NORMAL;
                double pxRange = (maxPx > -1e8 && minPx < 1e8) ? (maxPx - minPx) : 0.0;

                bool trigT3 = (avgScr < CLOUD_SCR_ALERT && bufSize >= CLOUD_MIN_ALERT_PKTS);
                bool trigT1 = (elapsed >= CLOUD_WINDOW_S);
                bool trigT2 = (bufSize >= CLOUD_MAX_PKTS);

                std::cout << "[CLOUD-BUF] " << txIp
                          << " buf=" << bufSize << "/" << CLOUD_MAX_PKTS
                          << " t+" << std::fixed << std::setprecision(1) << elapsed << "s"
                          << " avgSCR=" << std::setprecision(3) << avgScr;
                if (trigT3) std::cout << " ?SCORE_ALERT";
                std::cout << "\n";

                if (!trigT3 && !trigT1 && !trigT2) continue;

                std::string triggerName;
                if      (trigT3) triggerName = "SCORE_ALERT";
                else if (trigT1) triggerName = "TIME";
                else             triggerName = "COUNT";

                int      priorBans = ReadPriorBans(cid);
                uint32_t safeWins  = m_cloudBuffer[txIp].empty() ? 0
                                   : m_cloudBuffer[txIp].back().safeWins;
                uint32_t carClass  = m_cloudBuffer[txIp].empty() ? 0
                                   : m_cloudBuffer[txIp].back().carClass;

                // [BRIDGE-CLEANUP-FIX]
                // In bridge mode (InternalCloud=0), the real bridge->cloud->edge path already
                // performs cloud inference and sends CLOUD_FB back to edge. Running the host-side
                // proxy cloud ledger here causes misleading SAFE windows, duplicate cloud semantics,
                // and contradictory CLOUD-NASH logs. So in bridge mode we flush the local host
                // buffer once a trigger condition is reached and skip local cloud verdicting.
                //
                // [v81-2] DEPRECATED BLOCK BELOW (reached only if InternalCloud=1).
                // Cloud no longer judges individual vehicles. Cloud is a population-level
                // parameter tuner only (receives CALIBRATE batches, returns W_deltas).
                // This path should never execute in the new architecture.
                // Kept for reference. Will be removed in v82.
                if (!m_useInternalCloud) {
                    std::cout << "[CLOUD-HOST] CID:" << cid
                              << " InternalCloud=0 -- bridge mode active; skipping host-side CLOUD-NASH/LEDGER path"
                              << " | TRIGGER=" << triggerName
                              << " | PKTS=" << bufSize
                              << " | avgSCR=" << std::fixed << std::setprecision(3) << avgScr
                              << "\n";
                    m_cloudBuffer[txIp].clear();
                    m_windowStart.erase(txIp);
                    continue;
                }

                double llmSusp = 0.3;
                std::string dominant = "normal";
                std::string summary  = "cloudunreachable";

                std::string cloudQuery = BuildCloudQuery(cid, bufSize, 1.0-avgScr,
                                                          shadowCount, triggerName,
                                                          priorBans, avgSpd,
                                                          pxRange, safeWins);
                std::cout << ">>> [CLOUD-LLM QUERY] " << cloudQuery << "\n";

                // [LATENCY-MODEL] measure wall-clock RTT of Cloud LLM call
                auto _t0_cloud = std::chrono::steady_clock::now();
                std::string llmResp = TcpCallFramed(m_cloudAddr.c_str(), m_cloudPort,
                                                     cloudQuery,
                    "LLM_RESP llm_susp:0.300 dominant:normal summary:cloudunreachable");
                auto _t1_cloud = std::chrono::steady_clock::now();
                double _rtt_cloud_ms = std::chrono::duration<double,std::milli>(_t1_cloud - _t0_cloud).count();
                std::cout << "[CLOUD-RTT] wall=" << std::fixed << std::setprecision(1)
                          << _rtt_cloud_ms << " ms  sim_delay=" << CloudLatencyMs << " ms\n";
                std::cout << "[CLOUD-LLM-RESP] " << llmResp << "\n";

                std::string sv = ParseKV(llmResp, "llm_susp");
                if (!sv.empty()) try { llmSusp = std::stod(sv); } catch (...) {}
                dominant = ParseKV(llmResp, "dominant");
                if (dominant.empty()) dominant = "normal";
                summary  = ParseKV(llmResp, "summary");
                if (summary.empty()) summary = "cloudunreachable";

                // Shadow boost if cloud unreachable -- UNCHANGED
                if (summary == "cloudunreachable" && shadowCount > 2) {
                    double shdBoost = std::min(0.05 * (double)shadowCount, 0.15);
                    llmSusp = std::min(0.30, llmSusp + shdBoost);
                    summary  = "cloudunreachable-shdboosted";
                    NS_LOG_UNCOND("CLOUD-LLM-BOOST CID" << cid
                        << " SHD" << shadowCount
                        << " boost+" << shdBoost
                        << " newllmsusp" << llmSusp);
                }

                // [FIX-1] + [COMPAT-FIX-3]
                // Send CLOUD_FB to Edge AI so weights can evolve.
                // [COMPAT-FIX-3] Added sim_ts field -- edge parse_cloud_fb() uses it
                // for RTT tracking (FIX-CD1/CD2/CD3). Without it edge always defaults
                // to CLOUD_RTT_MS=400ms and RTT measurement is permanently broken.
                double simNow  = Simulator::Now().GetSeconds();
                std::string cloudFb = "CLOUD_FB CID:"   + std::to_string(cid)
                                    + " llm_susp:"      + std::to_string(llmSusp)
                                    + " dominant:"      + dominant
                                    + " safe_wins:"     + std::to_string(safeWins)
                                    + (LEGACY_WIRE_ALIASES ? (std::string(" safeWins:") + std::to_string(safeWins)) : std::string(""))
                                    + " class:"         + std::to_string(carClass)
                                    + " sim_ts:"        + std::to_string(simNow);
                std::string fbResp = TcpCallFramed(m_edgeAddr.c_str(), m_edgePort,
                                                    cloudFb, "NASH_FB_FAILED");
                std::cout << "[CLOUD->EDGE FB] CID:" << cid
                          << " llm_susp=" << llmSusp
                          << " dominant=" << dominant
                          << " sim_ts="   << simNow
                          << " -> " << fbResp.substr(0, 60) << "\n";

                // Nash verdict at cloud -- INTERNAL CLOUD MODE ONLY
                double avgEdgeSusp = 1.0 - avgScr;
                double p_comb = std::max(0.0, std::min(1.0,
                                    0.6 * llmSusp + 0.4 * avgEdgeSusp));

                double ban_reward     = BAN_REWARD;
                double false_ban_cost = FALSE_BAN_COST;
                double chase_cost     = CHASE_COST;
                if (carClass == 1) {
                    ban_reward     *= 1.5;
                    false_ban_cost *= 2.0;
                    chase_cost     *= 1.5;
                }

                double eu_ban   = p_comb * ban_reward - (1 - p_comb) * false_ban_cost;
                double eu_trust = (1 - p_comb) * REWARD - p_comb * chase_cost;
                std::string verdict = (p_comb > NASH_P_STAR && eu_ban > eu_trust)
                                      ? "BAN" : "TRUST";

                std::cout << "[CLOUD-NASH] CID:" << cid
                          << " p_comb=" << std::fixed << std::setprecision(3) << p_comb
                          << " p*=" << NASH_P_STAR
                          << " EU_ban=" << eu_ban
                          << " EU_trust=" << eu_trust
                          << " -> " << verdict << "\n";

                // Clear buffer
                m_cloudBuffer[txIp].clear();
                m_windowStart.erase(txIp);

                // Write ledger -- INTERNAL CLOUD MODE ONLY
                {
                    std::ofstream ledger(LEDGER_FILE, std::ios::app);
                    if (ledger.is_open()) {
                        ledger << "{\"blk\":0,\"t\":" << Simulator::Now().GetSeconds()
                               << ",\"cid\":"  << cid
                               << ",\"evt\":\"" << (verdict == "BAN" ? "BAN00001" : "SAFE00001") << "\""
                               << ",\"scr\":"  << (verdict == "BAN" ? p_comb : 1.0 - p_comb)
                               << ",\"hash\":\"dummy\",\"prev\":\"dummy\""
                               << ",\"note\":\"NASH_" << verdict << "\"}\n";
                    }
                }

                // CLOUDCTRL to UAV — scheduled via CloudLatencyMs
                // [CLOUD-LATENCY] Both BAN and SAFE verdicts are deferred by
                // CloudLatencyMs so the UAV state update happens at the correct
                // simulated time, completing the end-to-end latency model.
                if (verdict == "BAN") {
                    std::cout << "!!! [CLOUD] CONSOLIDATED MALICIOUS " << txIp
                              << " | pkts=" << bufSize
                              << " | avgSCR=" << avgScr
                              << " | TRIGGER=" << triggerName
                              << " | delay=" << CloudLatencyMs << "ms\n";
                    std::stringstream ccs;
                    ccs << "CLOUDCTRL|CID:" << cid
                        << "|IP:"     << txIp
                        << "|VERDICT:BAN"
                        << "|TRIGGER:" << triggerName;
                    Simulator::Schedule(MilliSeconds((uint64_t)CloudLatencyMs),
                                        &UnifiedApp::SendCloudCtrlDelayed,
                                        this, m_uavCtrlAddr, ccs.str());
                    std::cout << "<<< [CLOUD->UAV] CLOUDCTRL BAN scheduled +" << CloudLatencyMs
                              << "ms for " << txIp << "\n";
                } else {
                    std::cout << "[LEDGER-WIN] " << txIp
                              << " | WIN=" << std::fixed << std::setprecision(1) << elapsed << "s"
                              << " | PKTS=" << bufSize
                              << " | avgSCR=" << avgScr
                              << " | TRIGGER=" << triggerName
                              << " | VERDICT=SAFE delay=" << CloudLatencyMs << "ms\n";
                    std::stringstream ccs;
                    ccs << "CLOUDCTRL|CID:" << cid
                        << "|IP:"     << txIp
                        << "|VERDICT:SAFE"
                        << "|TRIGGER:" << triggerName;
                    Simulator::Schedule(MilliSeconds((uint64_t)CloudLatencyMs),
                                        &UnifiedApp::SendCloudCtrlDelayed,
                                        this, m_uavCtrlAddr, ccs.str());
                }
            }
            // ROLE_CAR: receives via ReceiveCtrl
        }
    }

    // CAR: transmit BSM beacons every 0.5s
    void Send() {
        if (m_role != ROLE_CAR) return;
        std::string msg;
        if (m_node) {
            Ptr<MobilityModel> mob = m_node->GetObject<MobilityModel>();
            if (mob) {
                Vector pos = mob->GetPosition();
                Vector vel = mob->GetVelocity();
                double ts  = Simulator::Now().GetSeconds();
                double spd = std::sqrt(vel.x*vel.x + vel.y*vel.y + vel.z*vel.z);

                // [COMPAT-FIX-5] Add natural heading jitter (+-2 deg) for honest cars.
                // Without this every honest car sends HDG=0.0 always (ConstantVelocity
                // with vel.x=20 -> hdg=0.0 every packet -> variance=0 -> edge M3 heading
                // anomaly fires on ALL cars). The +-2 deg range still clearly distinguishes:
                //   honest cars    : var ~ 1.3 (noisy, safe)
                //   ATK_STEALTHY   : var ~ 0.08 (semi-frozen, suspicious)
                //   ATK_SPEED_ONLY : hdg=0.0 exactly (frozen, malicious)
                double hdg = (vel.x >= 0) ? 0.0 : 180.0;
                if (!m_isMalicious) {
                    hdg += ((rand() % 400) / 100.0 - 2.0);  // uniform [-2.0, +2.0] degrees
                }

                int brk = (rand() % 10 < 2) ? 1 : 0;

                std::ostringstream o;
                o << "CID:" << m_carId
                  << "|TS:"  << std::fixed << std::setprecision(3) << ts
                  << "|SPD:" << std::setprecision(1) << (spd + (!m_isMalicious ? (rand()%100)/100.0*1.0-0.5 : 0.0))
                  << "|HDG:" << hdg
                  << "|PX:"  << (pos.x + (!m_isMalicious ? (rand()%100)/100.0*1.5-0.75 : 0.0))
                  << "|PY:"  << pos.y
                  << "|LAN:" << m_laneId
                  << "|BRK:" << brk
                  << "|HOK:" << m_handoverConfirmedZone;
                msg = o.str();

                // ---------------------------------------------------------------
                // [FIX-ATTACK-TYPE] Multi-profile attack injection -- UNCHANGED
                // ---------------------------------------------------------------
                if (m_isMalicious) {  // always attack (persistent threat model)

                    static std::map<uint32_t, double>   frozen_px_map;
                    static std::map<uint32_t, bool>     frozen_set_map;
                    static std::map<uint32_t, double>   frozen_ts_map;
                    static std::map<uint32_t, uint32_t> pkt_counter;

                    if (!frozen_set_map[m_carId]) {
                        frozen_px_map[m_carId]  = pos.x;
                        frozen_ts_map[m_carId]  = ts;
                        frozen_set_map[m_carId] = true;
                        pkt_counter[m_carId]    = 0;
                    }

                    double fake_ts  = ts;
                    double fake_spd = spd;
                    double fake_px  = pos.x;
                    double fake_hdg = hdg;

                    switch (m_attackType) {

                    case ATK_TS_ONLY:
                        fake_ts  = ts + m_tsOffset;
                        fake_spd = m_speedNormal;
                        fake_px  = pos.x;
                        break;

                    case ATK_GPS_ONLY:
                        fake_ts  = ts;
                        fake_spd = m_speedNormal;
                        fake_px  = frozen_px_map[m_carId]
                                   + ((rand() % 100) / 100.0 * ATK_FROZEN_NOISE * 2
                                      - ATK_FROZEN_NOISE);
                        break;

                    case ATK_SPEED_ONLY:
                        fake_ts  = ts;
                        fake_spd = m_speedNormal * (m_spdFactor + (rand() % 100) / 2000.0);
                        fake_px  = pos.x;
                        fake_hdg = 0.0;
                        break;

                    case ATK_STEALTHY:
                    {
                        double sim_elapsed = ts - frozen_ts_map[m_carId];
                        fake_ts  = ts + TS_OFFSET_STEALTHY;
                        fake_spd = SPEED_STEALTHY;
                        fake_px  = frozen_px_map[m_carId]
                                   + (GPS_DRIFT_RATE * sim_elapsed)
                                   + ((rand() % 100) / 100.0 * ATK_FROZEN_NOISE
                                      - ATK_FROZEN_NOISE * 0.5);
                        fake_hdg = hdg + HDG_JITTER_STEALTHY
                                   * ((rand() % 100) / 50.0 - 1.0);
                        break;
                    }

                    case ATK_ADAPTIVE:
                    {
                        pkt_counter[m_carId]++;
                        bool burst_packet = (pkt_counter[m_carId] % 3 == 0); // attack every 3rd packet
                        if (burst_packet) {
                            fake_ts  = ts + TS_OFFSET_ATTACK;
                            fake_spd = m_speedAttack;
                            fake_px  = frozen_px_map[m_carId]
                                       + ((rand() % 100) / 100.0 * ATK_FROZEN_NOISE * 2
                                          - ATK_FROZEN_NOISE);
                        } else {
                            fake_ts  = ts;
                            fake_spd = m_speedNormal;
                            fake_px  = pos.x;
                            fake_hdg = hdg;
                        }
                        break;
                    }

                    case ATK_COMPOSITE:
                    default:
                        fake_ts  = ts + TS_OFFSET_ATTACK;
                        fake_spd = m_speedAttack;
                        fake_px  = frozen_px_map[m_carId]
                                   + ((rand() % 100) / 100.0 * ATK_FROZEN_NOISE * 2
                                      - ATK_FROZEN_NOISE);
                        break;

                    case ATK_RATIONAL:
{
    // [REALISTIC-RATIONAL] Two changes from the original omniscient model:
    //
    // 1. Noisy p: the car adds extra perception noise to its SUSP estimate.
    //    m_rObsSusp already has ObsNoiseSigma noise from ReceiveCtrl.
    //    Here we add another layer — the car's own cognitive uncertainty
    //    about what SUSP means relative to the detection threshold.
    //    This prevents the car from having perfect self-knowledge.
    double extra_noise = ObsNoiseSigma * (((rand() % 10000) + 0.5) / 10000.0 - 0.5);
    double p = std::max(0.0, std::min(1.0, m_rObsSusp + extra_noise));

    // 2. Learned p*: car uses m_rLearnedPStar (starts at 0.50, updates from
    //    outcomes) instead of the true NASH_P_STAR=0.40.
    //    Early in the simulation the car is cautious (p*_est=0.50).
    //    If it attacks and gets away, estimate drops and it attacks more.
    //    If it gets caught, estimate rises and it backs off.
    //    This is trial-and-error learning, not omniscient equilibrium play.
    double p_star_est = m_rLearnedPStar;

    // Nash-stop uses learned threshold — car backs off when it THINKS
    // detection is imminent, not when detection actually is imminent.
    if (p >= p_star_est) {
        fake_ts  = ts;
        fake_spd = spd;
        fake_px  = pos.x;
        fake_hdg = hdg;
        m_rTotalCoop++;
        m_rLastWasAtk = false;
        std::cout << "[RATIONAL] CID:" << m_carId
                  << " NASH-STOP p=" << std::fixed << std::setprecision(3) << p
                  << " >= p*_est=" << p_star_est
                  << " (true_p*=" << NASH_P_STAR << ")"
                  << " sw=" << m_rSafeWins << " FORCED-COOP\n";
        break;
    }

    // Wash-out cooldown after WARN — car goes honest to rebuild safe wins.
    if (m_rCooldown > 0) {
        fake_ts  = ts;
        fake_spd = spd;
        fake_px  = pos.x;
        fake_hdg = hdg;
        m_rTotalCoop++;
        m_rLastWasAtk = false;
        m_rCooldown--;
        if (m_rTotalCoop % 5 == 0)
            std::cout << "[RATIONAL] CID:" << m_carId
                      << " WASHOUT p=" << std::setprecision(3) << p
                      << " cd=" << m_rCooldown
                      << " sw=" << m_rSafeWins << "\n";
        break;
    }

    // EU-driven decision using noisy p and learned p*.
    //
    // MODE A — per-packet temptation (TemptationFixed=0, default):
    //   EUattack =  p * T_i  - (1-p) * Cf
    //   EUcoop   = (1-p) * Rs - p * Cc
    //
    // MODE B — lump-sum fixed-reward (TemptationFixed>0):
    //   Models a real-world attacker with a one-time high-value target
    //   (causing an accident, disrupting a corridor, triggering false braking).
    //   EUattack = (1-p) * T_FIXED - p * (m_cumulativePayoff + BAN_PENALTY)
    //   EUcoop   = remaining_sim_pkts * R_COOP
    //   Attacker attacks when one-time reward exceeds total detection cost.
    double euatk, eucoop;
    if (m_temptationFixed > 0.0) {
        // Fixed-reward lump-sum model
        double sim_elapsed   = Simulator::Now().GetSeconds();
        double sim_stop      = m_simDuration;
        double sim_remaining = std::max(1.0, sim_stop - sim_elapsed);
        double remaining_pkts = sim_remaining / 0.5; // ~0.5s BSM interval
        double ban_total_cost = std::max(0.0, m_cumulativePayoff) + (FALSE_BAN_COST * 8.0);
        euatk  = (1.0 - p) * m_temptationFixed - p * ban_total_cost;
        eucoop = remaining_pkts * R_COOP;
        if ((int)m_rTotalCoop % 20 == 0)
            std::cout << "[RATIONAL-FIXED] CID:" << m_carId
                      << " T_FIXED=" << std::setprecision(1) << m_temptationFixed
                      << " eu_atk=" << std::setprecision(2) << euatk
                      << " eu_coop=" << std::setprecision(2) << eucoop
                      << " remaining_pkts=" << (int)remaining_pkts
                      << " ban_cost=" << std::setprecision(1) << ban_total_cost << "\n";
    } else {
        // per-packet temptation model (original)
        euatk  = p * m_temptation - (1.0 - p) * C_ATK_FP;
        eucoop = (1.0 - p) * R_COOP  - p * C_COOP_MISS;
    }

    bool attacknow = (euatk > eucoop)
                  && (m_rSafeWins >= R_TRUST_THRESH)
                  && (m_rCooldown == 0);

    if (attacknow) {
        fake_ts  = ts + TS_OFFSET_ATTACK;
        fake_spd = m_speedAttack;
        fake_px  = frozen_px_map[m_carId]
                  + (rand() % 100) / 100.0 * ATK_FROZEN_NOISE * 2
                  - ATK_FROZEN_NOISE;
        m_rTotalAtk++;
        m_rLastWasAtk = true;  // flag so ReceiveCtrl updates learned p*
        std::cout << "[RATIONAL] CID:" << m_carId
                  << " ATTACK p="  << std::fixed << std::setprecision(3) << p
                  << " T="         << std::setprecision(3) << m_temptation
                  << " eu_atk="    << std::setprecision(3) << euatk
                  << " eu_coop="   << std::setprecision(3) << eucoop
                  << " p*_est="    << std::setprecision(3) << p_star_est
                  << " sw=" << m_rSafeWins
                  << " tot_atk=" << m_rTotalAtk << "\n";
    } else {
        fake_ts  = ts;
        fake_spd = spd;
        fake_px  = pos.x;
        fake_hdg = hdg;
        m_rTotalCoop++;
        m_rLastWasAtk = false;
        if (m_rTotalCoop % 10 == 0)
            std::cout << "[RATIONAL] CID:" << m_carId
                      << " COOP p="     << std::setprecision(3) << p
                      << " p*_est="     << std::setprecision(3) << p_star_est
                      << " sw="         << m_rSafeWins
                      << " eu_gap="     << std::setprecision(3) << (eucoop - euatk) << "\n";
    }
    break;
}


                    case ATK_INTERMITTENT:
                    {
                        // Suspicion-adaptive intermittent attacker.
                        // Reads own SUSP each packet and modulates attack frequency:
                        //   p < 0.10  -> attack 1-in-2  (low suspicion, aggressive)
                        //   p < 0.20  -> attack 1-in-4  (rising suspicion, cautious)
                        //   p < 0.35  -> attack 1-in-8  (near threshold, very rare)
                        //   p >= 0.35 -> go fully honest for 10 packets (near detection)
                        // Uses 60% of normal attack magnitude to stay under edge AI models.
                        m_iPktCount++;
                        double p_obs = m_rObsSusp;

                        uint32_t atk_interval;
                        if      (p_obs >= 0.35) { atk_interval = 999; m_rCooldown = 10; }
                        else if (p_obs >= 0.20) { atk_interval = 8; }
                        else if (p_obs >= 0.10) { atk_interval = 4; }
                        else                    { atk_interval = 2; }

                        bool do_attack = (m_rCooldown == 0) &&
                                         (m_iPktCount % atk_interval == 0);

                        if (do_attack) {
                            fake_ts  = ts + TS_OFFSET_ATTACK * 0.6;
                            fake_spd = m_speedNormal * 1.06;
                            fake_px  = frozen_px_map[m_carId]
                                       + ((rand() % 100) / 100.0 * ATK_FROZEN_NOISE
                                          - ATK_FROZEN_NOISE * 0.5);
                            m_rTotalAtk++;
                            std::cout << "[INTERMITTENT] CID:" << m_carId
                                      << " ATTACK p=" << std::fixed << std::setprecision(3) << p_obs
                                      << " interval=" << atk_interval
                                      << " tot_atk="  << m_rTotalAtk << "\n";
                        } else {
                            fake_ts  = ts; fake_spd = spd;
                            fake_px  = pos.x; fake_hdg = hdg;
                            m_rTotalCoop++;
                        }
                        break;
                    }

                    case ATK_OPTIMAL:
                    {
                        // Optimal adversary — scales BOTH attack rate AND magnitude
                        // proportionally to observed suspicion level.
                        //
                        // Core idea: never let p_edge exceed p*=0.40.
                        // Uses minimum falsification that still achieves goal.
                        //
                        // Attack magnitude scaling:
                        //   mag = max(0.20, 1.0 - p_obs * 2.5)
                        //   p=0.004 (trusted)  -> mag=0.99 (nearly full)
                        //   p=0.15  (rising)   -> mag=0.625
                        //   p=0.30  (medium)   -> mag=0.25 (very subtle)
                        //   p=0.38  (near p*)  -> mag=0.20 (minimum)
                        //   p>=0.40 (at limit) -> go honest, reset
                        //
                        // Attack frequency:
                        //   p < 0.15  -> every 2nd packet  (aggressive)
                        //   p < 0.30  -> every 4th packet  (moderate)
                        //   p < 0.38  -> every 8th packet  (cautious)
                        //   p >= 0.40 -> cooldown 15 pkts  (abort)
                        m_iPktCount++;
                        double p_obs = m_rObsSusp;

                        // Go dark if near or above Nash threshold
                        if (p_obs >= 0.40) {
                            m_rCooldown = 15;
                            fake_ts  = ts; fake_spd = spd;
                            fake_px  = pos.x; fake_hdg = hdg;
                            m_rTotalCoop++;
                            break;
                        }

                        // Compute magnitude scale — decreases as suspicion rises
                        double mag = std::max(0.20, 1.0 - p_obs * 2.5);

                        // Compute attack interval — increases as suspicion rises
                        uint32_t atk_interval;
                        if      (p_obs < 0.15) atk_interval = 2;
                        else if (p_obs < 0.30) atk_interval = 4;
                        else                   atk_interval = 8;

                        bool do_attack = (m_rCooldown == 0) &&
                                         (m_iPktCount % atk_interval == 0);

                        if (do_attack) {
                            // Scale attack magnitude proportionally
                            fake_ts  = ts  + TS_OFFSET_ATTACK * mag;
                            fake_spd = m_speedNormal + (m_speedAttack - m_speedNormal) * mag;
                            fake_px  = frozen_px_map[m_carId]
                                       + ((rand() % 100) / 100.0 * ATK_FROZEN_NOISE * mag
                                          - ATK_FROZEN_NOISE * mag * 0.5);
                            m_rTotalAtk++;
                            std::cout << "[OPTIMAL] CID:" << m_carId
                                      << " ATTACK p="    << std::fixed << std::setprecision(3) << p_obs
                                      << " mag="         << std::setprecision(3) << mag
                                      << " interval="    << atk_interval
                                      << " fake_ts_off=" << std::setprecision(3) << (TS_OFFSET_ATTACK*mag)
                                      << " fake_spd="    << std::setprecision(1) << fake_spd
                                      << " tot_atk="     << m_rTotalAtk << "\n";
                        } else {
                            fake_ts  = ts; fake_spd = spd;
                            fake_px  = pos.x; fake_hdg = hdg;
                            m_rTotalCoop++;
                        }
                        break;
                    }

                    } // end switch

                    std::ostringstream b;
                    b << "CID:" << m_carId
                      << "|TS:"  << std::fixed << std::setprecision(3) << fake_ts
                      << "|SPD:" << std::setprecision(1) << fake_spd
                      << "|HDG:" << fake_hdg
                      << "|PX:"  << fake_px
                      << "|PY:"  << pos.y
                      << "|LAN:" << m_laneId
                      << "|BRK:" << brk
                      << "|HOK:" << m_handoverConfirmedZone;
                    msg = b.str();
                }
            }
        }
        m_socket->SendTo(
            Create<Packet>((uint8_t*)msg.c_str(), msg.length()),
            0, InetSocketAddress(m_destAddr, m_port));
        Simulator::Schedule(Seconds(0.5), &UnifiedApp::Send, this);
    }

    virtual void StartApplication(void) override {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9000));
        m_socket->SetRecvCallback(MakeCallback(&UnifiedApp::Receive, this));

        if (m_role == ROLE_CAR) {
            m_ctrlSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            m_ctrlSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9001));
            m_ctrlSocket->SetRecvCallback(MakeCallback(&UnifiedApp::ReceiveCtrl, this));
            Simulator::Schedule(Seconds(1.0 + (rand() % 100) / 100.0),
                                 &UnifiedApp::Send, this);
        }
        if (m_role == ROLE_UAV) {
            m_ctrlSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            m_ctrlSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9001));
            m_cloudCtrlSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            m_cloudCtrlSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9002));
            m_cloudCtrlSocket->SetRecvCallback(MakeCallback(&UnifiedApp::ReceiveCloudCtrl, this));
        }
    }

    virtual void StopApplication(void) override {
        // [HONEST-REWARD] Print per-car payoff summary for paper comparison table
        if (m_role == ROLE_CAR) {
            std::cout << "[PAYOFF] CID:" << m_carId
                      << " cumulative_payoff=" << std::fixed << std::setprecision(3)
                      << m_cumulativePayoff
                      << " honest_wins=" << m_honestSafeWins
                      << " lane_upgraded=" << (m_laneUpgraded ? "YES" : "NO")
                      << " scrutiny_reduced=" << (m_scrutinyReduced ? "YES" : "NO")
                      << " malicious=" << (m_isMalicious ? "YES" : "NO")
                      << "\n";
        }
        if (m_socket)          m_socket->Close();
        if (m_ctrlSocket)      m_ctrlSocket->Close();
        if (m_cloudCtrlSocket) m_cloudCtrlSocket->Close();
    }

private:
    Ptr<Socket>  m_socket;
    Ptr<Socket>  m_ctrlSocket;
    Ptr<Socket>  m_cloudCtrlSocket;
    AppRole      m_role;
    Ipv4Address  m_destAddr;
    Ipv4Address  m_uavCtrlAddr;
    uint16_t     m_port;

    uint16_t     m_edgePort   = 9999;  // Zone-1 bridge/edge port
    uint16_t     m_edgePortZ2 = 9996;  // Zone-2 bridge/edge port
    std::string  m_edgeAddr   = "127.0.0.1";
    std::string  m_cloudAddr = "127.0.0.1";
    uint16_t     m_cloudPort = 6666;

    // [COMPAT-FIX-4] bridge-mode flag (true = NS3 queries cloud; false = bridge does)
    bool         m_useInternalCloud;

    std::map<Ipv4Address, CarUavState>                m_carState;
    std::set<Ipv4Address>                             m_bannedCars;
    std::map<std::string, std::vector<EnrichedBlock>> m_cloudBuffer;
    std::map<std::string, double>                     m_windowStart;

    // [ADAPTIVE-NASH] population-level ban tracking
    uint32_t    m_popTotalObs = 0;
    uint32_t    m_popBanObs   = 0;
    uint32_t    m_carId;
    int         m_laneId;
    // [HONEST-REWARD] Per-car honest history state
    uint32_t    m_honestSafeWins   = 0;    // consecutive OK verdicts (all car types)
    // [FORGIVENESS] Counts lifetime adverse (WARN/BAN) verdicts received.
    // First adverse verdict is excused — honest_wins unchanged.
    // Second adverse verdict onwards halves honest_wins (lesson learned penalty).
    uint32_t    m_adverseCount     = 0;
    uint32_t    m_warnCount        = 0;   // lifetime WARN verdicts (no tier escalation)
    // [DEMOTION] State for graduated punishment system.
    // m_originalLaneId    : lane assigned at startup — restoration target on demotion
    // m_originalSpeedNormal: speed before lane upgrade — restored on demotion
    // m_demoted           : true once the car has been demoted from fast lane
    // m_demotedAt         : honest_wins value at the moment of demotion
    // m_returnThreshold   : honest_wins needed to return to NORMAL lane after demotion
    int         m_originalLaneId     = 0;
    double      m_originalSpeedNormal = SPEED_NORMAL;
    double      m_speedBoost       = 0.0;   // [LANE-UPGRADE] permanent speed bonus applied to all phases
    bool        m_demoted            = false;
    uint32_t    m_demotedAt          = 0;
    uint32_t    m_returnThreshold    = 0;
    double      m_cumulativePayoff = 0.0;  // accumulated rwd - pnl over simulation
    bool        m_econProbation    = false; // while true, OK verdicts do not earn positive reward
    bool        m_laneUpgraded     = false; // true while fast-lane upgrade is currently active
    bool        m_scrutinyReduced  = false; // true while reduced-scrutiny benefit is currently active
    double      m_effectiveLatency = 0.0;  // EdgeLatencyMs (halved for trusted cars)
    Ptr<Node>   m_node;
    bool        m_isMalicious;
    uint32_t    m_attackRate;
    AttackType  m_attackType;
    double      m_tsOffset;
    double      m_spdFactor;
    // Per-instance speed values — initialized from global constants but mutable
    // so that LANE_UPGRADE benefit in ReceiveCtrl() can permanently raise a
    // trusted car's operating speed (m_speedNormal/m_speedAttack replace the
    // static constexpr SPEED_NORMAL/SPEED_ATTACK in all per-car BSM generation).
    double      m_speedNormal  = SPEED_NORMAL;
    double      m_speedAttack  = SPEED_ATTACK;
    uint32_t    m_pktDropRate = 1;  // [FIX-A2] after m_spdFactor => matches init list order

    // [RATIONAL-AGENT] Per-vehicle state for ATK_RATIONAL (type 6)
    // Observes own SUSP from edge AI response, computes EU each packet.
    // EU(attack) = p*R_b - (1-p)*C_fp
    // EU(coop)   = (1-p)*R_s - p*C_c
    double      m_rObsSusp   = 0.004; // last observed SUSP from edge AI
    uint32_t    m_rSafeWins  = 0;     // honest packets since last attack
    uint32_t    m_rCooldown  = 0;     // cooldown packets after attack
    uint32_t    m_rTotalAtk  = 0;     // lifetime attack packets
    uint32_t    m_rTotalCoop = 0;     // lifetime cooperative packets
    uint32_t    m_iPktCount  = 0;     // packet counter for ATK_INTERMITTENT
    uint32_t    m_iHonestRun = 0;     // current honest streak (intermittent)
    // [REALISTIC-RATIONAL] Learned p* via trial and error.
    // Car does NOT know the true p*=0.40 — it starts with a pessimistic
    // prior of 0.50 and updates it based on outcomes:
    //   - Attacked and got away (no WARN) → lower estimate (system is lenient)
    //   - Attacked and got WARN/BAN      → raise estimate (system is strict)
    // Learning rate m_rLearnRate controls how fast beliefs update.
    double      m_rLearnedPStar = 0.70;   // starts very cautious — true p* unknown
    double      m_rLearnRate    = 0.05;   // Bayesian update step per observation
    bool        m_rLastWasAtk   = false;  // was the previous packet an attack?
    // [TEMPTATION-T] Per-car temptation payoff replaces static R_ATK_BAN=1.5.
    // Default 1.5 keeps original behaviour; overridden per-car in main().
    double                    m_temptation   = 1.5;
    double                    m_temptationFixed = 0.0; // >0 = lump-sum fixed-reward model
    double                    m_simDuration   = 90.0; // sim stop time in seconds for fixed-reward EU
    static constexpr double   C_ATK_FP       = 0.5;
    static constexpr double   R_COOP         = 1.0;
    static constexpr double   C_COOP_MISS    = 1.0;
    static constexpr uint32_t R_TRUST_THRESH = 20;  // must earn 20 safe wins before first attack
    static constexpr uint32_t R_COOLDOWN_K   = 5;

    // [MU] Tracks source zones for which this car already sent a handover
    // trigger. Allows Zone1->2, Zone2->3, ... without duplicate triggers.
    std::set<uint32_t> m_handoverSentZones;
    uint32_t m_handoverConfirmedZone = 0;  // [RACE-FIX] highest zone confirmed loaded via TRUST_HANDOVER_LOAD ack
};

NS_OBJECT_ENSURE_REGISTERED(UnifiedApp);

// =========================================================================
// main()
// =========================================================================

int main(int argc, char* argv[]) {
    uint32_t    nCars             = 20;
    uint32_t    attackRate        = 20;
    uint32_t    attackType        = 0;
    uint32_t    rngRun            = 1;
    // [FIX-A2] Configurable UAV relay drop rate. Default 1 = original behaviour.
    // Pass --PktDropRate=5/10/15 for robustness experiments.
    uint32_t    pktDropRate       = 1;
    Time        simTime           = Seconds(30.0);
    std::string cloudAddr         = "127.0.0.1";
    std::string edgeAddr          = "127.0.0.1";
    uint16_t    edgePort          = 9999;  // Zone-1 bridge/edge port
    uint16_t    edgePortZ2        = 9996;  // Zone-2 bridge/edge port
    uint16_t    cloudPort         = 6666;
    double      tsOffset          = TS_OFFSET_ATTACK;
    double      spdFactor         = 1.10;
    uint32_t    laneCount         = 5;
    double      carSpacingMeters  = 20.0;
    double      laneGapMeters     = 10.0;
    double      perLaneStartSkew  = 0.01;
    double      perWaveStartSkew  = 0.002;
    uint32_t    startWaveRows     = 20;
    bool        autoExtendSimTime = true;
    double      settleMarginSeconds = 5.0;
    // [COMPAT-FIX-4] 1 = NS3 queries cloud (direct mode); 0 = bridge queries cloud
    // [v81-1] Default changed to false — bridge mode is now the only supported mode.
    bool        useInternalCloud  = false;
    // [CLI] Per-run overrides for speed profile and attacker heterogeneity.
    // These shadow the static constexpr globals for waypoint setup and per-car init.
    double      speedNormal       = SPEED_NORMAL;   // honest cruise speed (m/s)
    double      speedAttack       = SPEED_ATTACK;   // attacker speed (m/s)
    double      temptationMin     = 0.5;            // lower bound T_i ~ U(min,max)
    double      temptationMax     = 2.5;            // upper bound T_i ~ U(min,max)
    double      temptationFixed   = 0.0;            // >0 = lump-sum fixed-reward model (disables per-packet T_i)
    double      lateFlipFraction  = 0.50;           // tFlip = simTime * fraction (default 0.5 = midpoint)
    double      zoneLength        = 0.0;            // metres: 0=auto (speedNormal*simTime)
    double      zoneExitThreshM   = 200.0;          // metres from zone exit to trigger position-aware flip
    int         usePosFlip        = 1;              // 1=position-based flip, 0=time-based (legacy)

    // [MU] Multi‑UAV parameters.  The default nUAVs=1 reproduces the single‑UAV
    // baseline.  When nUAVs>=2 an additional UAV is added and trust handover
    // events are enabled.  zoneOverlapM controls the overlap between
    // adjacent zones in metres (not currently used by the simulator but
    // retained for future work).  handoverLeadM specifies how far before
    // the zone boundary a handover trigger should be sent.  coordAddr and
    // coordPort identify the trust coordinator; they are unused in ns‑3
    // directly but passed through to the edge via the handover message.
    uint32_t    nUAVs           = 1;
    double      zoneOverlapM    = 200.0;
    double      handoverLeadM   = 400.0;
    std::string coordAddr       = "127.0.0.1";
    uint32_t    coordPort       = 9997;

    CommandLine cmd;
    cmd.AddValue("nCars",             "Total vehicles",                    nCars);
    cmd.AddValue("attackRate",        "Attack rate 0-100%",                attackRate);
    cmd.AddValue("attackType",
        "Attack profile: 0=composite,1=TS-only,2=GPS-only,"
        "3=speed-only,4=stealthy,5=adaptive,6=rational-nash,7=intermittent,8=optimal", attackType);
    cmd.AddValue("RngRun",            "RNG run index",                     rngRun);
    // [FIX-A2]
    cmd.AddValue("PktDropRate",
                 "App-layer packet drop rate %% at UAV relay (default 1; try 5/10/15)",
                 pktDropRate);
    cmd.AddValue("NashPStar",         "Nash threshold p*",                 NASH_P_STAR);
    cmd.AddValue("Reward",            "Reward for correct trust",          REWARD);
    cmd.AddValue("FalseBanCost",      "Cost of false ban",                 FALSE_BAN_COST);
    cmd.AddValue("BanReward",         "Reward for correct ban",            BAN_REWARD);
    cmd.AddValue("ChaseCost",         "Cost of chasing malicious",         CHASE_COST);
    // [v81-2] These params controlled the host-side cloud buffer (InternalCloud=1 path).
    // In bridge mode (InternalCloud=0) the buffer is flushed but the trigger is skipped.
    // Kept for CLI compatibility. Unused in the new adaptive architecture.
    cmd.AddValue("CloudWindow",       "Time window for cloud (s) [unused in bridge mode]",   CLOUD_WINDOW_S);
    cmd.AddValue("CloudMaxPkts",      "Max pkts before COUNT trigger [unused in bridge mode]", CLOUD_MAX_PKTS);
    cmd.AddValue("CloudScrAlert",     "Safety threshold SCORE_ALERT [unused in bridge mode]",  CLOUD_SCR_ALERT);
    cmd.AddValue("CloudMinAlertPkts", "Min pkts for SCORE_ALERT [unused in bridge mode]",      CLOUD_MIN_ALERT_PKTS);
    cmd.AddValue("GameRs",            "Reward for safe verdict",           GAME_Rs);
    cmd.AddValue("GameCf",            "Cost of false alarm",               GAME_Cf);
    cmd.AddValue("CreditDiscountMax",
        "Max GAME_Cf reduction fraction for honest cross-zone history (default 0.30)", CREDIT_DISCOUNT_MAX);
    cmd.AddValue("CreditDiscountPerWin",
        "GAME_Cf discount earned per prior safe-win in ledger (default 0.015)",        CREDIT_DISCOUNT_PER_WIN);
    cmd.AddValue("TrustLaneWins",
        "Clean packets to earn fast-lane upgrade (default 15)",    TRUST_LANE_WINS);
    cmd.AddValue("TrustReduceWins",
        "Clean packets to earn reduced-scrutiny (default 20)",     TRUST_REDUCE_WINS);
    cmd.AddValue("TrustSpeedBoost",
        "Speed bonus m/s granted at fast-lane upgrade (default 2.0)", TRUST_SPEED_BOOST);
    cmd.AddValue("TrustLatencyMult",
        "Edge latency multiplier for trusted cars (default 0.5)",  TRUST_LATENCY_MULT);
    cmd.AddValue("FinalBanWindow",    "Ban evidence window size",          FINAL_BAN_WINDOW_PKTS);
    cmd.AddValue("FinalBanReq",       "BAN hits required in window",       FINAL_BAN_REQUIRED);
    cmd.AddValue("MinObservationsBeforeBan","Min total Bayesian evidence (alpha+beta - prior) before Nash gate can convict (default 15)",MIN_OBSERVATIONS_BEFORE_BAN);
    cmd.AddValue("DisableHandover","If true, suppress TRUST_HANDOVER_TRIGGER (Experiment C baseline)",DISABLE_HANDOVER);
    cmd.AddValue("HandoverTrustDiscount","Retention factor delta for HTD (0=fresh start, 1=full transfer, 0.3=recommended)",HANDOVER_TRUST_DISCOUNT);
    cmd.AddValue("HTDZoneBoundary","PX threshold for zone crossing detection (should match ZoneLength)",HTD_ZONE_BOUNDARY);
    cmd.AddValue("CusumMu0","CUSUM honest baseline score (default 0.05)",CUSUM_MU0);
    cmd.AddValue("CusumH","CUSUM detection threshold (default 3.0)",CUSUM_H);
    cmd.AddValue("DisableCUSUM","If true, disable post-handover CUSUM detector",DISABLE_CUSUM);
    cmd.AddValue("CusumWarmupK","Post-handover warmup packets before CUSUM accumulates (default 5)",CUSUM_WARMUP_K);
    cmd.AddValue("PostHandoverProbationPkts","Packets under strict scrutiny after handover",POST_HANDOVER_PROBATION_PKTS);
    cmd.AddValue("PostHandoverCreditFactor","Credit-discount multiplier during post-handover probation",POST_HANDOVER_CREDIT_FACTOR);
    cmd.AddValue("PostHandoverDisableUpgrade","If true, suppress trust upgrades during probation",POST_HANDOVER_DISABLE_UPGRADE);
    cmd.AddValue("CloudAddr",         "Cloud LLM server IP",               cloudAddr);
    cmd.AddValue("EdgeAddr",          "Edge AI / Bridge server IP",        edgeAddr);
    cmd.AddValue("EdgePort",          "Zone-1 Edge/Bridge server port",     edgePort);
    cmd.AddValue("EdgePortZ2",        "Zone-2 Edge/Bridge server port",     edgePortZ2);
    cmd.AddValue("CloudPort",         "Cloud LLM server port",             cloudPort);
    cmd.AddValue("TsOffset",
        "TS attack offset in seconds for ATK_TS_ONLY (default -0.5)",      tsOffset);
    cmd.AddValue("SpdFactor",
        "Speed multiplier for ATK_SPEED_ONLY (default 1.10)",              spdFactor);
    cmd.AddValue("LaneCount",         "Number of lanes for car placement", laneCount);
    cmd.AddValue("CarSpacingMeters",  "Longitudinal spacing between cars in the same lane", carSpacingMeters);
    cmd.AddValue("LaneGapMeters",     "Lateral spacing between lanes", laneGapMeters);
    cmd.AddValue("PerLaneStartSkew",  "Startup skew added per lane (s)", perLaneStartSkew);
    cmd.AddValue("PerWaveStartSkew",  "Startup skew added per row inside a bounded wave (s)", perWaveStartSkew);
    cmd.AddValue("StartWaveRows",     "Number of road rows that participate in bounded startup skew", startWaveRows);
    cmd.AddValue("AutoExtendSimTime", "Automatically extend simTime if startup pattern needs it", autoExtendSimTime);
    cmd.AddValue("SettleMarginSeconds", "Extra runtime after the latest application start", settleMarginSeconds);
    // [COMPAT-FIX-4]
    cmd.AddValue("InternalCloud",
        "1=NS3 ROLE_HOST queries cloud directly (default); "
        "0=bridge handles cloud queries (use with --EdgePort=9998)",        useInternalCloud);
    cmd.AddValue("simTime",           "Simulation duration in seconds",     simTime);
    // [LATENCY-MODEL] CLI overrides for simulated server latency
    cmd.AddValue("EdgeLatencyMs",
        "Simulated Edge AI round-trip latency in ms (default 10)",          EdgeLatencyMs);
    cmd.AddValue("CloudLatencyMs",
        "Simulated Cloud LLM round-trip latency in ms (default 150)",       CloudLatencyMs);
    cmd.AddValue("SpeedNormal",
        "Normal cruise speed m/s for honest cars and waypoint setup (default 20.0)", speedNormal);
    cmd.AddValue("SpeedAttack",
        "Attack speed m/s used in composite/rational/adaptive attacks (default 22.0)", speedAttack);
    cmd.AddValue("TemptationMin",
        "Lower bound of T_i ~ U(min,max) for ATK_RATIONAL temptation draw (default 0.5)", temptationMin);
    cmd.AddValue("TemptationMax",
        "Upper bound of T_i ~ U(min,max) for ATK_RATIONAL temptation draw (default 2.5)", temptationMax);
    cmd.AddValue("TemptationFixed",
        "Fixed one-time lump-sum reward for ATK_RATIONAL (0=disabled, >0 overrides per-packet T_i)", temptationFixed);
    cmd.AddValue("ObsNoiseSigma",
        "Gaussian sigma on observed suspicion in ReceiveCtrl (default 0.08)", ObsNoiseSigma);
    cmd.AddValue("LateFlipFraction",
        "tFlip = simTime * fraction for late attackers (default 0.50 = midpoint, 0.90 = near end)", lateFlipFraction);
    cmd.AddValue("ZoneLength",
        "Zone length in metres (0=auto: speedNormal*simTime)", zoneLength);
    cmd.AddValue("ZoneExitThreshM",
        "Metres from zone exit to trigger position-aware flip (default 200)", zoneExitThreshM);
    cmd.AddValue("UsePosFlip",
        "1=position-based late flip (realistic), 0=time-based proxy (legacy)", usePosFlip);

    // [MU] Register multi‑UAV CLI options.
    cmd.AddValue("nUAVs",        "Number of UAVs",            nUAVs);
    cmd.AddValue("ZoneOverlapM", "Zone overlap in metres",    zoneOverlapM);
    cmd.AddValue("HandoverLeadM", "Handover trigger lead (m)", handoverLeadM);
    cmd.AddValue("CoordAddr",    "Trust coordinator address",  coordAddr);
    cmd.AddValue("CoordPort",    "Trust coordinator port",     coordPort);
    cmd.Parse(argc, argv);

    // [HD-DEFENSE] Sync file-scope handover-defense geometry from CLI.
    HTD_ZONE_LENGTH_M   = (zoneLength > 0.0) ? zoneLength : (speedNormal * simTime.GetSeconds());
    HTD_HANDOVER_LEAD_M = handoverLeadM;
    if (HTD_ZONE_BOUNDARY == 1800.0) {
        // Backward-compatible default: if the old manual threshold was not
        // overridden, activate HTD/CUSUM at the real handover trigger point.
        HTD_ZONE_BOUNDARY = std::max(0.0, HTD_ZONE_LENGTH_M - HTD_HANDOVER_LEAD_M);
    }

    // Recalculate Nash p* after CommandLine parse (BanReward may have changed)
    // NASH_P_STAR = CHASE_COST / (BAN_REWARD + CHASE_COST); // DISABLED: --NashPStar CLI param sets this directly via cmd.AddValue

    laneCount = std::max(1u, laneCount);
    startWaveRows = std::max(1u, startWaveRows);
    carSpacingMeters = std::max(1.0, carSpacingMeters);
    laneGapMeters = std::max(1.0, laneGapMeters);
    LaneGapMeters = laneGapMeters;   // [LANE-UPGRADE] promote to file scope for ReceiveCtrl
    LaneCount     = laneCount;        // [SLOW-LANE] promote to file scope for exile Y calc
    perLaneStartSkew = std::max(0.0, perLaneStartSkew);
    perWaveStartSkew = std::max(0.0, perWaveStartSkew);
    settleMarginSeconds = std::max(0.0, settleMarginSeconds);

    const uint32_t CARS_PER_LANE = (nCars + laneCount - 1) / laneCount;
    if (autoExtendSimTime)
    {
        simTime = Seconds(GetAutoExtendedSimTimeSeconds(simTime,
                                                        laneCount,
                                                        CARS_PER_LANE,
                                                        perLaneStartSkew,
                                                        perWaveStartSkew,
                                                        startWaveRows,
                                                        settleMarginSeconds));
    }
    SimEndTime = simTime.GetSeconds();  // [LANE-UPGRADE] promote to file scope

    const CarSubnetPlan carSubnet = ChooseCarSubnetPlan(nCars);
    (void)carSubnet; // reserved for future subnet-aware routing; suppresses -Wunused

    RngSeedManager::SetRun(rngRun);
    srand(rngRun * 12345 + attackRate * 7);

    { std::ofstream lf(LEDGER_FILE, std::ios::trunc); }

    // Ground backhaul and aerial access use separate NR carriers.
    // - access: cars <-> UAV gNB
    // - backhaul: UAV UE <-> ground gNB
    double   accessFrequency    = 3.5e9;
    double   accessBandwidth    = 100e6;
    double   backhaulFrequency  = 28e9;
    double   backhaulBandwidth  = 50e6;
    double   accessTxPowerDbm   = 35.0;
    double   backhaulTxPowerDbm = 40.0;
    uint16_t accessNumerology   = 1;
    uint16_t backhaulNumerology = 3;

    const uint32_t LANES         = laneCount;

    NodeContainer groundGnbNodes, uavNodes, carNodes;
    groundGnbNodes.Create(1);
    // [MU] Create as many UAV nodes as specified.  In the baseline nUAVs=1
    // yields a single relay as before; nUAVs>=2 adds additional UAVs for
    // subsequent zones.
    uavNodes.Create(nUAVs);
    carNodes.Create(nCars);

    // -----------------------------------------------------------------------
    // Mobility setup — publication-ready single-UAV hovering scenario
    //
    // FIX-1 (gNB position): ground gNB moved to road-side mast height (10 m).
    //   The original (0,0,30) placed the gNB *above* the UAV (10 m AGL), which
    //   is physically incorrect.  A road-side macro cell mast is typically
    //   8-12 m; we use 10 m.
    //
    // FIX-2 (UAV altitude): UAV raised to 100 m AGL — the standard UAV relay
    //   altitude in 3GPP TR 36.777 and UAV-IAB literature.  At 100 m the
    //   UMa channel model on the backhaul band is fully justified (aerial node
    //   above rooftop height) and the LOS coverage radius matches the ~250-300 m
    //   link budget from the configured TX power.
    //   UAV is positioned above the lateral and longitudinal centre of the
    //   initial car formation so all nCars start within its coverage footprint.
    //
    // FIX-3 (UAV mobility model): switched from ConstantVelocityMobilityModel
    //   (co-moving at 20 m/s) to ConstantPositionMobilityModel.  The UAV now
    //   hovers — cars drive under it, exit its coverage zone naturally, and the
    //   gNB-to-UAV backhaul distance stays constant for the entire simulation.
    //   This is the canonical single-UAV relay scenario in the literature.
    // -----------------------------------------------------------------------

    // UAV starts above car formation centre (x ~ carSpacing/2)
    // then escorts convoy at speedNormal — always overhead throughout sim
    const double road_centre_x = ((double)(CARS_PER_LANE - 1) * carSpacingMeters) / 2.0;
    const double road_centre_y = -((double)(laneCount + 1) / 2.0) * laneGapMeters;

    MobilityHelper mob;
    {
        // FIX-1: gNB at road-side mast height — aligned laterally with convoy
        Ptr<ListPositionAllocator> p = CreateObject<ListPositionAllocator>();
        p->Add(Vector(0.0, road_centre_y, 10.0));
        mob.SetPositionAllocator(p);
        mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mob.Install(groundGnbNodes);
    }
    {
        // [MU] UAV(s) hover stationary at 100 m AGL.  For multi‑UAV scenarios
        // we position the first UAV above the initial car formation centre as
        // before, and subsequent UAVs are centred on successive zone midpoints.
        // The zone length is either the explicit --ZoneLength or the
        // product of speedNormal and simTime.  This placement ensures each
        // UAV provides coverage over its entire zone.  We do not model
        // lateral offset between zones; all UAVs share the same y‑coordinate.
        Ptr<ListPositionAllocator> p = CreateObject<ListPositionAllocator>();
        double _muZoneLen = (zoneLength > 0.0) ? zoneLength : (speedNormal * simTime.GetSeconds());
        for (uint32_t _muIdx = 0; _muIdx < nUAVs; ++_muIdx) {
            double cx;
            if (_muIdx == 0) {
                // The first UAV stays above the initial convoy centre as in v81.
                cx = road_centre_x;
            } else {
                // Subsequent UAVs centre on their respective zones.  Zone i
                // starts at i*zoneLen and the centre is at (i + 0.5)*zoneLen.
                cx = (_muIdx + 0.5) * _muZoneLen;
            }
            p->Add(Vector(cx, road_centre_y, 100.0));
        }
        mob.SetPositionAllocator(p);
        mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mob.Install(uavNodes);
        // Stationary — NR beamforming stable throughout simulation
    }
    {
        // [LANE-UPGRADE] ConstantVelocityMobilityModel for cars replaces
        // WaypointMobilityModel. This model supports SetVelocity() and
        // SetPosition() at any simulation time with no ordering constraints,
        // enabling physical lane upgrade and speed boost when the UAV grants
        // LANE_UPGRADE. Speed phase changes at T1 and T2 are scheduled as
        // simulator events. Each car app's SetSpeedPhase() applies m_speedBoost
        // so lane-upgraded cars keep their bonus through all phases.
        mob.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
        mob.Install(carNodes);
        double totalSim = simTime.GetSeconds();
        for (uint32_t i = 0; i < nCars; i++) {
            uint32_t lane = i % LANES;
            uint32_t pos  = i / LANES;
            double startX = (double)pos * carSpacingMeters;
            double startY = -(double)(lane + 1) * laneGapMeters;
            double T1 = totalSim * 0.33 + lane * 2.0;
            double T2 = totalSim * 0.66 + lane * 2.0;
            auto cvm = carNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
            cvm->SetPosition(Vector(startX, startY, 0.0));
            cvm->SetVelocity(Vector(speedNormal, 0.0, 0.0));
            // Schedule phase transitions — SetSpeedPhase reads m_speedBoost so
            // lane-upgraded cars automatically get the bonus at T1 and T2.
            // carApps[i] is not yet populated here so schedule via node/app index.
            // We use a lambda capturing the node pointer and base speed.
            Ptr<Node> carNode = carNodes.Get(i);
            Simulator::Schedule(Seconds(T1), [carNode]() {
                auto c = carNode->GetObject<ConstantVelocityMobilityModel>();
                // Get app's boost from the UnifiedApp installed on this node
                Ptr<Application> app = carNode->GetApplication(0);
                double boost = 0.0;
                if (app) {
                    auto ua = DynamicCast<UnifiedApp>(app);
                    if (ua) boost = ua->GetSpeedBoost();
                }
                if (c) c->SetVelocity(Vector(25.0 + boost, 0.0, 0.0));
            });
            Simulator::Schedule(Seconds(T2), [carNode]() {
                auto c = carNode->GetObject<ConstantVelocityMobilityModel>();
                Ptr<Application> app = carNode->GetApplication(0);
                double boost = 0.0;
                if (app) {
                    auto ua = DynamicCast<UnifiedApp>(app);
                    if (ua) boost = ua->GetSpeedBoost();
                }
                if (c) c->SetVelocity(Vector(15.0 + boost, 0.0, 0.0));
            });
        }
    }

    Ptr<NrPointToPointEpcHelper> epc = CreateObject<NrPointToPointEpcHelper>();
    Ptr<IdealBeamformingHelper>  bfh = CreateObject<IdealBeamformingHelper>();
    Ptr<NrHelper> nrh = CreateObject<NrHelper>();
    nrh->SetBeamformingHelper(bfh);
    nrh->SetEpcHelper(epc);

    CcBwpCreator cc;
    // Access band: cars are ground-level UEs in a street canyon -- UMi is correct.
    auto accessBand = cc.CreateOperationBandContiguousCc(
        CcBwpCreator::SimpleOperationBandConf(
            accessFrequency, accessBandwidth, 1,
            BandwidthPartInfo::UMi_StreetCanyon));  // street-level car environment
    // Backhaul band: the UAV hovers at 100 m AGL (ConstantPositionMobilityModel)
    // and connects to the road-side gNB at 10 m.  UMa (Urban Macro) is the
    // 3GPP TR 38.901 sec 7.2 recommended channel scenario for elevated aerial
    // nodes (above rooftop height) and is standard in IAB / UAV-relay
    // literature.  UMi_StreetCanyon, which models ground-level propagation,
    // would be physically incorrect here.
    auto backhaulBand = cc.CreateOperationBandContiguousCc(
        CcBwpCreator::SimpleOperationBandConf(
            backhaulFrequency, backhaulBandwidth, 1,
            BandwidthPartInfo::UMa_LoS));  // UAV backhaul: LOS to ground gNB
    nrh->InitializeOperationBand(&accessBand);
    nrh->InitializeOperationBand(&backhaulBand);
    auto accessBwps   = CcBwpCreator::GetAllBwps({accessBand});
    auto backhaulBwps = CcBwpCreator::GetAllBwps({backhaulBand});

    bfh->SetAttribute("BeamformingMethod",
                       TypeIdValue(DirectPathBeamforming::GetTypeId()));
    // [ITEM-1a] S1-U link delay set to 5 ms — realistic for a 5G EPC backplane.
    // The original 0 ms is an idealization; 5 ms matches typical 3GPP TS 23.501
    // N3 interface round-trip budgets for local EPC deployments.
    epc->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(5)));

    nrh->SetUeAntennaAttribute("NumRows",        UintegerValue(2));
    nrh->SetUeAntennaAttribute("NumColumns",     UintegerValue(4));
    nrh->SetUeAntennaAttribute("AntennaElement",
                                PointerValue(CreateObject<IsotropicAntennaModel>()));
    nrh->SetGnbAntennaAttribute("NumRows",       UintegerValue(4));
    nrh->SetGnbAntennaAttribute("NumColumns",    UintegerValue(8));
    nrh->SetGnbAntennaAttribute("AntennaElement",
                                 PointerValue(CreateObject<IsotropicAntennaModel>()));

    // Backhaul side: UAV acts as NR UE attached to the fixed ground gNB.
    // FIX-47: Increase SRS periodicity to support nCars>40 per cell
    Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity", UintegerValue(320));
    auto groundGnbDev = nrh->InstallGnbDevice(groundGnbNodes, backhaulBwps);
    auto uavBackhaulUeDev  = nrh->InstallUeDevice(uavNodes, backhaulBwps);

    // Access side: UAV acts as NR gNB serving all cars as NR UEs.
    auto uavAccessGnbDev = nrh->InstallGnbDevice(uavNodes, accessBwps);
    auto carAccessUeDev  = nrh->InstallUeDevice(carNodes, accessBwps);

    int64_t rs  = 1;
    rs += nrh->AssignStreams(groundGnbDev, rs);
    rs += nrh->AssignStreams(uavBackhaulUeDev, rs);
    rs += nrh->AssignStreams(uavAccessGnbDev, rs);
    rs += nrh->AssignStreams(carAccessUeDev, rs);

    // Configure PHY attributes for the ground gNB and all UAV devices.  In
    // multi‑UAV mode each UAV has its own backhaul UE and access gNB; loop
    // over these containers rather than assuming a single element.
    nrh->GetGnbPhy(groundGnbDev.Get(0), 0)->SetAttribute("Numerology", UintegerValue(backhaulNumerology));
    nrh->GetGnbPhy(groundGnbDev.Get(0), 0)->SetAttribute("TxPower",    DoubleValue(backhaulTxPowerDbm));
    for (uint32_t u = 0; u < uavBackhaulUeDev.GetN(); ++u) {
        nrh->GetUePhy(uavBackhaulUeDev.Get(u), 0)->SetAttribute("TxPower", DoubleValue(30.0));
    }
    for (uint32_t g = 0; g < uavAccessGnbDev.GetN(); ++g) {
        nrh->GetGnbPhy(uavAccessGnbDev.Get(g), 0)->SetAttribute("Numerology", UintegerValue(accessNumerology));
        nrh->GetGnbPhy(uavAccessGnbDev.Get(g), 0)->SetAttribute("TxPower",    DoubleValue(accessTxPowerDbm));
    }
    for (uint32_t i = 0; i < carAccessUeDev.GetN(); ++i) {
        nrh->GetUePhy(carAccessUeDev.Get(i), 0)->SetAttribute("TxPower", DoubleValue(23.0));
    }
    // Apply configuration updates after attributes are set.
    DynamicCast<NrGnbNetDevice>(groundGnbDev.Get(0))->UpdateConfig();
    for (uint32_t u = 0; u < uavBackhaulUeDev.GetN(); ++u) {
        DynamicCast<NrUeNetDevice>(uavBackhaulUeDev.Get(u))->UpdateConfig();
    }
    for (uint32_t g = 0; g < uavAccessGnbDev.GetN(); ++g) {
        DynamicCast<NrGnbNetDevice>(uavAccessGnbDev.Get(g))->UpdateConfig();
    }
    for (uint32_t i = 0; i < carAccessUeDev.GetN(); ++i) {
        DynamicCast<NrUeNetDevice>(carAccessUeDev.Get(i))->UpdateConfig();
    }

    InternetStackHelper inet;
    inet.Install(uavNodes);
    inet.Install(carNodes);

    Ptr<Node>     pgw = epc->GetPgwNode();
    NodeContainer rHost; rHost.Create(1); inet.Install(rHost);

    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate("10Gb/s")));
    p2p.SetDeviceAttribute("Mtu",      UintegerValue(2500));
    // [ITEM-1b] P2P propagation delay set to 5 ms — models the WAN segment
    // between the PGW and the cloud/edge server rack.  The original 0 ms gave
    // the rHost instant reachability, understating end-to-end trust latency.
    p2p.SetChannelAttribute("Delay",   TimeValue(MilliSeconds(5)));
    auto iDev = p2p.Install(pgw, rHost.Get(0));

    Ipv4AddressHelper ip4;
    ip4.SetBase("1.0.0.0", "255.0.0.0");
    auto hostIp = ip4.Assign(iDev);

    NetDeviceContainer allNrUeDevs;
    allNrUeDevs.Add(uavBackhaulUeDev);
    allNrUeDevs.Add(carAccessUeDev);
    auto allNrIps = epc->AssignUeIpv4Address(allNrUeDevs);

    // IP layout after AssignUeIpv4Address(allNrUeDevs):
    //   index 0 -> UAV backhaul UE address
    //   indices 1..nCars -> car UE addresses
    // Split assigned UE IPs: first nUAVs entries correspond to UAV backhaul UEs;
    // remaining entries correspond to car UEs.
    Ipv4InterfaceContainer uavWan;
    for (uint32_t u = 0; u < uavBackhaulUeDev.GetN(); ++u) {
        uavWan.Add(allNrIps.Get(u));
    }
    Ipv4InterfaceContainer carIps;
    for (uint32_t i = uavBackhaulUeDev.GetN(); i < allNrIps.GetN(); ++i) {
        carIps.Add(allNrIps.Get(i));
    }

    Ipv4StaticRoutingHelper srh;
    // Set default route on each UAV’s backhaul UE to reach the PGW via gNB.
    for (uint32_t u = 0; u < uavNodes.GetN(); ++u) {
        srh.GetStaticRouting(uavNodes.Get(u)->GetObject<Ipv4>())
            ->SetDefaultRoute(epc->GetUeDefaultGatewayAddress(), 1);
    }
    for (uint32_t i = 0; i < nCars; i++) {
        srh.GetStaticRouting(carNodes.Get(i)->GetObject<Ipv4>())
            ->SetDefaultRoute(epc->GetUeDefaultGatewayAddress(), 1);
    }
    srh.GetStaticRouting(rHost.Get(0)->GetObject<Ipv4>())
        ->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

    // Explicit attachment: use AttachToEnb() which is the correct API name in this
    // 5G-LENA / ns3-nr build.  Each UAV acts as a UE on the backhaul and
    // attaches to the single ground gNB.  The first UAV also hosts a gNB
    // serving all cars.  For simplicity we continue to attach all cars to
    // the first UAV's gNB; extending handover of the access link is beyond
    // the scope of this prototype.
    for (uint32_t bIdx = 0; bIdx < uavBackhaulUeDev.GetN(); ++bIdx) {
        nrh->AttachToEnb(uavBackhaulUeDev.Get(bIdx), groundGnbDev.Get(0));
    }
    for (uint32_t i = 0; i < carAccessUeDev.GetN(); ++i) {
        nrh->AttachToEnb(carAccessUeDev.Get(i), uavAccessGnbDev.Get(0));
    }

    // [ITEM-3] RNG-based malicious assignment.
    // The original deterministic index-based selector always placed attackers
    // at the same car IDs regardless of --RngRun, making every seed produce
    // the same spatial attacker configuration.  We now build a shuffled index
    // vector seeded by rngRun so that different seeds produce different attacker
    // positions — essential for statistically valid multi-seed evaluation.
    uint32_t nMalicious = (uint32_t)std::round((double)nCars * attackRate / 100.0);
    std::set<uint32_t> malSet;
    {
        std::vector<uint32_t> indices(nCars);
        std::iota(indices.begin(), indices.end(), 0);
        // Seeded Fisher-Yates shuffle using rngRun for reproducibility
        std::mt19937 rng_shuffle(rngRun * 31337u + attackRate * 97u);
        std::shuffle(indices.begin(), indices.end(), rng_shuffle);
        for (uint32_t i = 0; i < nMalicious && i < nCars; ++i)
            malSet.insert(indices[i]);
    }

    // Cloud host (rHost)
    Ptr<UnifiedApp> hostApp = CreateObject<UnifiedApp>();
    hostApp->Setup(ROLE_HOST, Ipv4Address::GetAny(), 9000);
    hostApp->SetUavCtrlAddr(uavWan.GetAddress(0));
    hostApp->SetCloudAddr(cloudAddr);
    hostApp->SetCloudPort(cloudPort);
    hostApp->SetEdgePort(edgePort);
    hostApp->SetEdgePortZ2(edgePortZ2);
    hostApp->SetEdgeAddr(edgeAddr);
    // [COMPAT-FIX-4] pass bridge-mode flag to hostApp
    hostApp->SetUseInternalCloud(useInternalCloud);
    rHost.Get(0)->AddApplication(hostApp);
    hostApp->SetStartTime(Seconds(0.1));
    hostApp->SetStopTime(simTime);

    // UAV
    Ptr<UnifiedApp> uavApp = CreateObject<UnifiedApp>();
    uavApp->Setup(ROLE_UAV, hostIp.GetAddress(1), 9000);
    uavApp->SetPktDropRate(pktDropRate);  // [FIX-A2]
    uavApp->SetEdgePort(edgePort);
    uavApp->SetEdgePortZ2(edgePortZ2);
    uavApp->SetEdgeAddr(edgeAddr);
    uavNodes.Get(0)->AddApplication(uavApp);
    uavApp->SetStartTime(Seconds(0.5));
    uavApp->SetStopTime(simTime);

    // Cars
    std::vector<Ptr<UnifiedApp>> carApps;  // [PAYOFF] collect for post-Run() summary
    for (uint32_t i = 0; i < nCars; i++) {
        uint32_t lane = i % LANES;
        Ptr<UnifiedApp> ca = CreateObject<UnifiedApp>();
        ca->Setup(ROLE_CAR, uavWan.GetAddress(0), 9000,
                  i, (int)(lane + 1), carNodes.Get(i));
        ca->SetAttackRate(attackRate);
        ca->SetMalicious(malSet.count(i) > 0);
        ca->SetSpeedNormal(speedNormal);   // [CLI] applies --SpeedNormal override
        ca->SetSpeedAttack(speedAttack);   // [CLI] applies --SpeedAttack override
        if (malSet.count(i) > 0) {
            ca->SetAttackType(attackType);
            ca->SetTsOffset(tsOffset);
            ca->SetSpdFactor(spdFactor);
            // [TEMPTATION-T] Draw T_i ~ Uniform(0.5, 2.5) per malicious car.
            // Different seeds -> different temptation profiles -> natural
            // variance in DR/FPR across RngRun seeds (multi-seed paper plots).
            // Seed is independent of malSet shuffle: rngRun*53 + carId*99991.
            std::mt19937 rng_t(rngRun * 53u + i * 99991u);
            std::uniform_real_distribution<double> tdist(temptationMin, temptationMax);
            double t_i = tdist(rng_t);
            ca->SetTemptation(t_i);
                ca->SetTemptationFixed(temptationFixed);
                ca->SetSimDuration(simTime.GetSeconds());
                if (temptationFixed > 0.0)
                    std::cout << "[TEMPTATION-FIXED] CID:" << i
                              << " T_FIXED=" << temptationFixed
                              << " (per-packet T_i=" << t_i << " ignored)\n";
            std::cout << "[TEMPTATION-T] CID:" << i
                      << " T_i=" << std::fixed << std::setprecision(3) << t_i
                      << " break-even_p*="
                      << std::setprecision(3) << (0.5 / (t_i + 0.5)) << "\n";
        }
        carNodes.Get(i)->AddApplication(ca);
        carApps.push_back(ca);  // [PAYOFF] keep reference for post-Run() print
        const uint32_t pos = i / LANES;
        const uint32_t boundedRow = pos % startWaveRows;
        const double carStartTime = 1.0 + lane * perLaneStartSkew + boundedRow * perWaveStartSkew;
        ca->SetStartTime(Seconds(carStartTime));
        ca->SetStopTime(simTime);
    }

    // [ITEM-5] Late-entry attackers: position-aware (UsePosFlip=1) or time-based (0).
    // Position-aware: polls pos every 1s, flips when ZoneLength-pos.x <= ZoneExitThreshM.
    // Models attacker that rationally waits until physically near zone boundary.
    {
        uint32_t nLateMalicious = (uint32_t)std::ceil((double)nMalicious * 0.25);
        uint32_t lateCnt        = 0;
        double effectiveZoneLen = (zoneLength > 0.0)
            ? zoneLength
            : (speedNormal * simTime.GetSeconds());
        for (uint32_t i = 0; i < nCars && lateCnt < nLateMalicious; ++i) {
            if (malSet.count(i)) continue;
            Ptr<UnifiedApp> ca = DynamicCast<UnifiedApp>(
                carNodes.Get(i)->GetApplication(0));
            if (!ca) continue;
            if (usePosFlip) {
                Simulator::Schedule(Seconds(1.0),
                                    &UnifiedApp::PollAndFlipIfNearExit, ca,
                                    (AttackType)attackType, tsOffset, spdFactor,
                                    effectiveZoneLen, zoneExitThreshM);
                std::cout << "[LATE-ATTACK] CID:" << i
                          << " position-aware flip armed"
                          << " ZoneLen=" << effectiveZoneLen
                          << "m threshold=" << zoneExitThreshM << "m\n";
            } else {
                double tFlip = simTime.GetSeconds() * lateFlipFraction;
                Simulator::Schedule(Seconds(tFlip),
                                    &UnifiedApp::ActivateMaliciousLate, ca,
                                    (AttackType)attackType, tsOffset, spdFactor);
                std::cout << "[LATE-ATTACK] CID:" << i
                          << " time-based flip at t=" << tFlip << "s\n";
            }
            lateCnt++;
        }
        std::cout << "[LATE-ATTACK] Scheduled " << lateCnt
                  << (usePosFlip ? " position-aware" : " time-based")
                  << " late-entry attackers"
                  << " ZoneLen=" << effectiveZoneLen
                  << "m ThreshM=" << zoneExitThreshM << "m\n";
    }

    // [MU] Schedule trust handover polls for each adjacent UAV-zone transition.
    // For nUAVs=2 this is the original Zone1->Zone2 experiment. For nUAVs>2,
    // the same app now arms Zone2->Zone3, Zone3->Zone4, ... without rewriting.
    if (nUAVs >= 2) {
        double _muZoneLen = (zoneLength > 0.0)
            ? zoneLength
            : (speedNormal * simTime.GetSeconds());
        for (uint32_t fromZone = 1; fromZone < nUAVs; ++fromZone) {
            uint32_t toZone = fromZone + 1;
            double zoneEndX = _muZoneLen * static_cast<double>(fromZone);
            double triggerDist = zoneEndX - handoverLeadM;
            double tStart = triggerDist / speedNormal;
            if (tStart < 0.0) tStart = 0.0;
            for (uint32_t ci = 0; ci < carApps.size(); ++ci) {
                Ptr<UnifiedApp> ca = carApps[ci];
                Simulator::Schedule(Seconds(tStart),
                                    &UnifiedApp::PollAndHandoverIfNearBoundary, ca,
                                    fromZone, toZone, zoneEndX, handoverLeadM, edgeAddr, edgePort);
            }
            std::cout << "[HANDOVER] Armed " << carApps.size()
                      << " triggers for Z" << fromZone << "->Z" << toZone
                      << " at t=" << tStart << " s (zoneEndX=" << zoneEndX
                      << ", leadM=" << handoverLeadM << ")\n";
        }
    }

    EpsBearer bearer(EpsBearer::NGBR_LOW_LAT_EMBB);
    Ptr<EpcTft> tft = EpcTft::Default();
    // Attach a dedicated bearer to each UAV backhaul UE.  Previously this
    // activated only the first UAV, which was incorrect when nUAVs>1.
    for (uint32_t b = 0; b < uavBackhaulUeDev.GetN(); ++b) {
        nrh->ActivateDedicatedEpsBearer(uavBackhaulUeDev.Get(b), bearer, tft);
    }
    // Cars still connect to a single UAV gNB (index 0) for access; each car
    // therefore receives one dedicated bearer on its access UE.
    for (uint32_t i = 0; i < carAccessUeDev.GetN(); ++i) {
        nrh->ActivateDedicatedEpsBearer(carAccessUeDev.Get(i), bearer, tft);
    }

    std::cout << "\n--------------------------------------------------\n"
              << " UNIFIED SIMULATION v90-multiUAV (adaptive edge-cloud, bridge mode only)\n"
              << "--------------------------------------------------\n"
              << " Cars      : " << nCars
              << " (" << LANES << " lanes x " << CARS_PER_LANE << ")\n"
              << " RngRun    : " << rngRun << "\n"
              << " Attack    : " << attackRate << "%  (" << nMalicious << " malicious) [";
    { bool f = true; for (uint32_t id : malSet) { if (!f) std::cout << ","; std::cout << id; f = false; } }
    std::cout << "]\n"
              << " AttackType: " << attackType
              << " (0=composite,1=TS-only,2=GPS-only,3=speed-only,"
              << "4=stealthy,5=adaptive)\n"
              << " TsOffset  : " << tsOffset   << "s\n"
              << " SpdFactor : " << spdFactor  << "x\n"
              << " Nash p*   : " << NASH_P_STAR << " (BAN_REWARD=" << BAN_REWARD << ")\n"
              << " ZONE_SAFE : " << ZONE_SAFE << "\n"
              << " ZONE_MALICIOUS : " << ZONE_MALICIOUS << "\n"
              << " LEGACY_WIRE_ALIASES : " << (LEGACY_WIRE_ALIASES ? 1 : 0) << "\n"
              << " SCR_ALERT : " << CLOUD_SCR_ALERT << "\n"
              << " GAME_Cf   : " << GAME_Cf << "\n"
              << " CloudTrig : [unused in bridge mode] SCR<" << CLOUD_SCR_ALERT
              << " && >=" << CLOUD_MIN_ALERT_PKTS
              << " | TIME>=" << CLOUD_WINDOW_S << "s"
              << " | COUNT>=" << CLOUD_MAX_PKTS << "\n"
              << " EdgePortZ1: " << edgeAddr << ":" << edgePort << "\n"
              << " EdgePortZ2: " << edgeAddr << ":" << edgePortZ2 << "\n"
              << " Cloud     : " << cloudAddr << ":" << cloudPort << "\n"
              << " CloudMode : " << (useInternalCloud
                  ? "INTERNAL [DEPRECATED — cloud no longer judges per vehicle]"
                  : "BRIDGE (adaptive batch calibration — cloud tunes edge params only)") << "\n"
              << " LedgerFile: " << LEDGER_FILE << "\n"
              << " EdgeLatencyMs : " << EdgeLatencyMs  << " ms\n"
              << " CloudLatencyMs: " << CloudLatencyMs << " ms\n"
              << " NashP* mode   : adaptive (warmup=5 pkts, rho_hat-driven)\n"
              << " S1uDelay      : 5 ms  |  PGW-rHost delay: 5 ms\n"
              << " PktDropRate   : " << pktDropRate << "%  |  EdgeJitter: 30%  |  LateAttackers: 25% of mal\n"
              << " BgTraffic     : " << nCars << " cars x 500 kbps UDP\n"
              << " Mobility      : WaypointMobility (3-phase speed profile per lane)\n"
              << " Duration  : " << simTime.GetSeconds() << "s\n"
              << "--------------------------------------------------\n\n";

    // [ITEM-6] Background UDP traffic — OnOff application on each car.
    // Each car generates 500 kbps of UDP traffic toward rHost, modelling
    // non-telemetry V2X payloads (map updates, video, infotainment).
    // This exercises the NR scheduler under realistic channel load and
    // introduces queuing delay variability that the trust protocol must tolerate.
    {
        uint16_t bgPort = 5000;
        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), bgPort));
        sink.Install(rHost.Get(0));

        OnOffHelper onoff("ns3::UdpSocketFactory",
                          InetSocketAddress(hostIp.GetAddress(1), bgPort));
        onoff.SetConstantRate(DataRate("500kbps"), 1400);
        onoff.SetAttribute("OnTime",  StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        for (uint32_t i = 0; i < nCars; ++i) {
            ApplicationContainer bgApp = onoff.Install(carNodes.Get(i));
            bgApp.Start(Seconds(1.0));
            bgApp.Stop(simTime);
        }
        std::cout << "[BG-TRAFFIC] " << nCars
                  << " cars x 500 kbps UDP background flow to rHost installed\n";
    }

    Simulator::Stop(simTime);
    Simulator::Run();

    // [PAYOFF] Print per-car summary immediately after Run() completes.
    // Printing here (not in StopApplication) guarantees ordering and flush —
    // NS3 may suppress or reorder std::cout during the shutdown sequence.
    std::cout << "\n── PAYOFF SUMMARY ─────────────────────────────────\n";
    for (auto& ca : carApps) {
        std::cout << "[PAYOFF] CID:" << ca->GetCarId()
                  << " cumulative_payoff=" << std::fixed << std::setprecision(3)
                  << ca->GetCumulativePayoff()
                  << " honest_wins=" << ca->GetHonestSafeWins()
                  << " warn_count=" << ca->GetWarnCount()
                  << " adverse_count=" << ca->GetAdverseCount()
                  << " demoted=" << (ca->GetDemoted() ? "YES" : "NO")
                  << " return_threshold=" << ca->GetReturnThreshold()
                  << " lane_upgraded=" << (ca->GetLaneUpgraded() ? "YES" : "NO")
                  << " scrutiny_reduced=" << (ca->GetScrutinyReduced() ? "YES" : "NO")
                  << " malicious=" << (ca->GetIsMalicious() ? "YES" : "NO")
                  << "\n";
    }
    std::cout << std::flush;

    std::cout << "\n--------------------------------------------------\n"
              << " SIMULATION COMPLETE v90-multiuav (adaptive edge-cloud, bridge mode only)"
              << "  nCars=" << nCars
              << "  attackRate=" << attackRate << "%"
              << "  attackType=" << attackType
              << "  RngRun=" << rngRun << "\n"
              << "--------------------------------------------------\n";

    Simulator::Destroy();
    return 0;
}
