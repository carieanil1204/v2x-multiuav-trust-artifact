/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-centrality.cc
 *
 * Faithful C++ translation of the SLIC Python implementation.
 * Each method documents the original Python code it replaces.
 */

#include "slic-centrality.h"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <cassert>
#include <limits>
#include <iostream>   // DEBUG: for std::cout

namespace ns3 {
namespace slic {

SLICCentrality::SLICCentrality (double alpha1, double alpha2, double alpha3,
                                double beta, uint32_t semiLocalRadius,
                                uint32_t laspRadius, uint32_t iscRadius)
  : m_alpha1 (alpha1),
    m_alpha2 (alpha2),
    m_alpha3 (alpha3),
    m_beta (beta),
    m_semiLocalRadius (semiLocalRadius),
    m_laspRadius (laspRadius),
    m_iscRadius (iscRadius),
    m_normalize (true)   // default: normalization enabled
{
}

void
SLICCentrality::SetWeights (double a1, double a2, double a3)
{
  m_alpha1 = a1;
  m_alpha2 = a2;
  m_alpha3 = a3;
}

void
SLICCentrality::SetBeta (double beta)
{
  m_beta = beta;
}

void
SLICCentrality::SetRadii (uint32_t semiLocal, uint32_t lasp, uint32_t isc)
{
  m_semiLocalRadius = semiLocal;
  m_laspRadius = lasp;
  m_iscRadius = isc;
}

// ═══════════════════════════════════════════════════════════════
// ISC (Influential Spreading Capability)
// ═══════════════════════════════════════════════════════════════
//
// Original Python:
//   def isc(hop):
//     ISC_FN = []
//     for j in G.nodes():
//       N = 0                          # BUG: shadows global N
//       for l in LN(j, int(hop)):
//         if G.degree(l) == S_del and l != j:
//           N += 1
//       ISC_FN.append(N * G.degree(j))
//
// Where S_del = min degree in graph, hop = 1
//
double
SLICCentrality::ComputeISC (const LocalGraph& G, uint32_t v) const
{
  uint32_t minDeg = G.GetMinDegree ();
  uint32_t degV = G.GetDegree (v);

  if (degV == 0)
    return 0.0;

  // Get L-hop neighborhood (fixed: no list mutation)
  auto neighborhood = G.BFS (v, m_iscRadius);

  uint32_t minDegCount = 0;
  for (const auto& kv : neighborhood)
    {
      uint32_t node = kv.first;
      if (node != v && G.GetDegree (node) == minDeg)
        {
          minDegCount++;
        }
    }

  return static_cast<double> (minDegCount * degV);
}

// ═══════════════════════════════════════════════════════════════
// Edge Weights (Neighbor Degree policy)
// ═══════════════════════════════════════════════════════════════
//
// Original Python:
//   for i in range(N):
//     for j in range(N):                    # BUG: O(n^2) instead of O(m)
//       if G.has_edge(node_i, node_j):
//         K_Ni = DC[Ni_indices].sum()
//         K_Nj = DC[Nj_indices].sum()
//         W[i,j] = (K_Ni/DC[i] + K_Nj/DC[j])
//
// Fixed: iterate over edges only (O(m))
//
std::map<std::pair<uint32_t, uint32_t>, double>
SLICCentrality::ComputeEdgeWeights (const LocalGraph& G) const
{
  std::map<std::pair<uint32_t, uint32_t>, double> W;
  auto nodes = G.GetNodes ();

  for (uint32_t u : nodes)
    {
      uint32_t degU = G.GetDegree (u);
      if (degU == 0)
        continue;

      for (uint32_t v : G.GetNeighbors (u))
        {
          if (v <= u)
            continue; // process each edge once

          uint32_t degV = G.GetDegree (v);
          if (degV == 0)
            continue;

          // Sum of degrees of u's neighbors
          double sumDegNeighU = 0.0;
          for (uint32_t nu : G.GetNeighbors (u))
            {
              sumDegNeighU += G.GetDegree (nu);
            }

          // Sum of degrees of v's neighbors
          double sumDegNeighV = 0.0;
          for (uint32_t nv : G.GetNeighbors (v))
            {
              sumDegNeighV += G.GetDegree (nv);
            }

          double w = (sumDegNeighU / degU) + (sumDegNeighV / degV);

          // Store both directions for lookup convenience
          W[{u, v}] = w;
          W[{v, u}] = w;
        }
    }
  return W;
}

// ═══════════════════════════════════════════════════════════════
// WW (Weighted Path Product)
// ═══════════════════════════════════════════════════════════════
//
// Original Python:
//   P = nx.shortest_path(G, source=i, target=j)
//   for k in range(len(P)-1):
//     WW[i,j] *= W[P[k]][P[k+1]]     # BUG: numerical instability
//
// Fixed: log-space computation
//
double
SLICCentrality::ComputeWW (const LocalGraph& G, uint32_t src, uint32_t dst,
                           const std::map<std::pair<uint32_t, uint32_t>, double>& W) const
{
  if (src == dst)
    return 0.0;

  auto path = G.ShortestPath (src, dst);
  if (path.size () < 2)
    return 0.0; // unreachable

  // Product in log-space for numerical stability
  double logProduct = 0.0;
  for (size_t k = 0; k + 1 < path.size (); ++k)
    {
      auto edgeKey = std::make_pair (path[k], path[k + 1]);
      auto it = W.find (edgeKey);
      if (it != W.end () && it->second > 0.0)
        {
          logProduct += std::log (it->second);
        }
      else
        {
          return 0.0; // edge weight missing or zero
        }
    }

  return std::exp (logProduct);
}

// ═══════════════════════════════════════════════════════════════
// Semi-Local Influence
// ═══════════════════════════════════════════════════════════════
//
// Original Python:
//   L = 3; beta = 0.5
//   for i in range(N):
//     sum_val = 0; c = 0
//     for l in range(1, L+1):
//       tmp = 0
//       Ni = [nodes at distance l from node_i]
//       c += len(Ni)
//       for k in Ni:
//         tmp += sqrt(WW[k,i] * DC[i]) / (l * (DC[i] + DC[k]))
//       sum_val += (beta**l) * tmp
//     I_Semi_Local[i] = (1/(c+1)) * sum_val
//
double
SLICCentrality::ComputeSemiLocal (const LocalGraph& G, uint32_t v) const
{
  uint32_t degV = G.GetDegree (v);
  if (degV == 0)
    return 0.0;

  // Compute edge weights for this graph
  auto W = ComputeEdgeWeights (G);

  // BFS to find nodes at each distance level up to semiLocalRadius
  auto distMap = G.BFS (v, m_semiLocalRadius);

  double sumVal = 0.0;
  uint32_t totalCount = 0;

  for (uint32_t l = 1; l <= m_semiLocalRadius; ++l)
    {
      double levelSum = 0.0;

      for (const auto& kv : distMap)
        {
          uint32_t node = kv.first;
          uint32_t dist = kv.second;

          if (dist != l)
            continue;

          totalCount++;

          uint32_t degU = G.GetDegree (node);
          double denominator = static_cast<double> (l) * (degV + degU);
          if (denominator <= 0.0)
            continue;

          double ww = ComputeWW (G, node, v, W);
          double numerator = std::sqrt (ww * static_cast<double> (degV));

          levelSum += numerator / denominator;
        }

      sumVal += std::pow (m_beta, static_cast<double> (l)) * levelSum;
    }

  return sumVal / (totalCount + 1);
}

// ═══════════════════════════════════════════════════════════════
// Semi-Local Influence (Fast — with precomputed edge weights)
// ═══════════════════════════════════════════════════════════════

double
SLICCentrality::ComputeSemiLocalFast (const LocalGraph& G, uint32_t v,
  const std::map<std::pair<uint32_t, uint32_t>, double>& W) const
{
  uint32_t degV = G.GetDegree (v);
  if (degV == 0)
    return 0.0;

  auto distMap = G.BFS (v, m_semiLocalRadius);

  double sumVal = 0.0;
  uint32_t totalCount = 0;

  for (uint32_t l = 1; l <= m_semiLocalRadius; ++l)
    {
      double levelSum = 0.0;

      for (const auto& kv : distMap)
        {
          uint32_t node = kv.first;
          uint32_t dist = kv.second;

          if (dist != l)
            continue;

          totalCount++;

          uint32_t degU = G.GetDegree (node);
          double denominator = static_cast<double> (l) * (degV + degU);
          if (denominator <= 0.0)
            continue;

          double ww = ComputeWW (G, node, v, W);
          double numerator = std::sqrt (ww * static_cast<double> (degV));

          levelSum += numerator / denominator;
        }

      sumVal += std::pow (m_beta, static_cast<double> (l)) * levelSum;
    }

  return sumVal / (totalCount + 1);
}

// ═══════════════════════════════════════════════════════════════
// LASP (Local Average Shortest Path disruption)
// ═══════════════════════════════════════════════════════════════
//
// Original Python:
//   H = G.subgraph(2-hop neighborhood of v)
//   ASP = nx.average_shortest_path_length(H)
//   newH = copy of H without v
//   for all pairs in newH:
//     try: sum += shortest_path_length
//     except: sum += D                    # BUG: bare except, uses diameter
//   ASPR = sum / (n * (n-1))
//   AC = abs(ASPR - ASP) / ASP
//
// Fixed: explicit unreachable handling with diameter+1 penalty
//
double
SLICCentrality::ComputeLASP (const LocalGraph& G, uint32_t v) const
{
  // Build 2-hop neighborhood subgraph
  auto distMap = G.BFS (v, m_laspRadius);
  std::set<uint32_t> nhoodNodes;
  for (const auto& kv : distMap)
    {
      nhoodNodes.insert (kv.first);
    }
  nhoodNodes.insert (v);

  if (nhoodNodes.size () < 3) // need at least 3 nodes for meaningful LASP
    return 0.5;               // neutral score — avoids penalizing edge nodes

  LocalGraph H = G.Subgraph (nhoodNodes);

  // Compute ASP of H (with v present)
  double aspBefore = H.AverageShortestPathLength ();
  if (aspBefore <= 0.0)
    return 0.0;

  // Remove v and compute ASP of remaining graph
  LocalGraph Hv = H.WithoutNode (v);
  uint32_t nRemaining = Hv.GetNodeCount ();
  if (nRemaining < 2)
    return 1.0; // v was the only bridge; maximum disruption

  // Compute all-pairs shortest paths in H without v
  auto apsp = Hv.AllPairsShortestPaths ();
  auto remainingNodes = Hv.GetNodes ();

  // Find local diameter for unreachable-pair penalty
  int localDiameter = 0;
  for (const auto& row : apsp)
    {
      for (int d : row)
        {
          if (d > 0 && d < INF_DIST && d > localDiameter)
            localDiameter = d;
        }
    }
  int unreachablePenalty = localDiameter + 1; // penalty > diameter

  // Compute average shortest path with penalty for unreachable pairs
  double pathLengthSum = 0.0;
  uint32_t pairCount = 0;

  for (size_t i = 0; i < remainingNodes.size (); ++i)
    {
      for (size_t j = i + 1; j < remainingNodes.size (); ++j)
        {
          int dist = apsp[i][j];
          if (dist >= INF_DIST)
            pathLengthSum += unreachablePenalty;
          else
            pathLengthSum += dist;
          pairCount++;
        }
    }

  if (pairCount == 0)
    return 0.0;

  double aspAfter = pathLengthSum / pairCount;
  return std::abs (aspAfter - aspBefore) / aspBefore;
}

// ═══════════════════════════════════════════════════════════════
// Normalization
// ═══════════════════════════════════════════════════════════════

void
SLICCentrality::Normalize (std::vector<double>& values)
{
  if (values.empty ())
    return;

  double minVal = *std::min_element (values.begin (), values.end ());
  double maxVal = *std::max_element (values.begin (), values.end ());
  double range = maxVal - minVal;

  if (range < 1e-12)
    {
      // All values equal: set to 0.5
      std::fill (values.begin (), values.end (), 0.5);
      return;
    }

  for (double& val : values)
    {
      val = (val - minVal) / range;
    }
}

// ═══════════════════════════════════════════════════════════════
// Composite: Total Influence
// ═══════════════════════════════════════════════════════════════
//
// Original Python:
//   a1, a2, a3 = 0.05, 0.5, 0.45
//   total_influence = [a1*isc + a2*semi_local + a3*lasp
//                      for isc, semi_local, lasp in zip(...)]
//
// FIX: Added normalization of each sub-metric to [0,1] before combining
//
double
SLICCentrality::ComputeTotalInfluence (const LocalGraph& G, uint32_t v) const
{
  auto results = ComputeAllCentralities (G);
  auto it = results.find (v);
  if (it == results.end ())
    return 0.0;
  return it->second.totalInfluence;
}

std::map<uint32_t, CentralityResult>
SLICCentrality::ComputeAllCentralities (const LocalGraph& G) const
{
  auto nodes = G.GetNodes ();
  uint32_t n = static_cast<uint32_t> (nodes.size ());

  if (n == 0)
    return {};

  // FIX: Precompute edge weights ONCE (was recomputed k times inside ComputeSemiLocal)
  auto W = ComputeEdgeWeights (G);

  // Compute raw sub-metrics for all nodes
  std::vector<double> iscVals (n);
  std::vector<double> slVals (n);
  std::vector<double> laspVals (n);

  for (uint32_t i = 0; i < n; ++i)
    {
      iscVals[i] = ComputeISC (G, nodes[i]);
      slVals[i] = ComputeSemiLocalFast (G, nodes[i], W);
      laspVals[i] = ComputeLASP (G, nodes[i]);
    }

  // ─────────────────────────────────────────────────────────────────
  // DEBUG: Print raw values before normalization (if any)
  // ─────────────────────────────────────────────────────────────────
  std::cout << "\n=== RAW CENTRALITY VALUES (NormalizeMetrics=" 
            << (m_normalize ? "true" : "false") << ") ===\n";
  for (uint32_t i = 0; i < n; ++i)
    {
      double totalRaw = m_alpha1 * iscVals[i] 
                     + m_alpha2 * slVals[i] 
                     + m_alpha3 * laspVals[i];
      std::cout << "Node " << nodes[i] 
                << " | ISC=" << iscVals[i]
                << " | SemiLocal=" << slVals[i]
                << " | LASP=" << laspVals[i]
                << " | TotalRaw=" << totalRaw
                << std::endl;
    }
  std::cout << "=========================================\n" << std::endl;
  // ─────────────────────────────────────────────────────────────────

  // Normalize each sub-metric to [0,1] (CRITICAL FIX) - only if flag is true
  if (m_normalize)
    {
      Normalize (iscVals);
      Normalize (slVals);
      Normalize (laspVals);
    }

  // Compute weighted composite
  std::map<uint32_t, CentralityResult> results;
  for (uint32_t i = 0; i < n; ++i)
    {
      CentralityResult cr;
      cr.nodeId = nodes[i];
      cr.isc = iscVals[i];
      cr.semiLocal = slVals[i];
      cr.lasp = laspVals[i];
      cr.totalInfluence = m_alpha1 * iscVals[i]
                        + m_alpha2 * slVals[i]
                        + m_alpha3 * laspVals[i];
      // Floor: prevent zero-weight nodes from causing routing voids
      if (cr.totalInfluence < 0.05) cr.totalInfluence = 0.05;
      results[nodes[i]] = cr;
    }

  return results;
}

} // namespace slic
} // namespace ns3