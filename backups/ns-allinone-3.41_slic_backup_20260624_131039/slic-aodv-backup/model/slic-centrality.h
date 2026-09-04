/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-centrality.h
 *
 * SLIC (Semi-Local Influence-based Centrality) computation engine.
 * Faithfully implements all three sub-metrics from the original Python:
 *   - ISC  (Influential Spreading Capability)
 *   - Semi-Local Influence (with WW weighted path product)
 *   - LASP (Local Average Shortest Path disruption)
 *
 * Bug fixes applied from original Python code:
 *   - N(v) linear scan replaced with O(1) adjacency lookup
 *   - LN() list mutation fixed with separate BFS levels
 *   - Variable shadowing (N, sum) eliminated
 *   - Bare except replaced with explicit unreachable-pair handling
 *   - Min-max normalization added before weighted combination
 *   - WW computed in log-space for numerical stability
 */

#ifndef SLIC_CENTRALITY_H
#define SLIC_CENTRALITY_H

#include "slic-local-graph.h"
#include <map>
#include <vector>
#include <utility>

namespace ns3 {
namespace slic {

/**
 * \brief Result of centrality computation for a single node.
 */
struct CentralityResult
{
  uint32_t nodeId;
  double isc;           ///< ISC sub-metric (raw, before normalization)
  double semiLocal;     ///< Semi-Local Influence (raw)
  double lasp;          ///< LASP (raw)
  double totalInfluence; ///< Weighted composite after normalization

  CentralityResult ()
    : nodeId (0), isc (0), semiLocal (0), lasp (0), totalInfluence (0)
  {
  }
};

/**
 * \brief SLIC centrality computation engine.
 *
 * Computes the composite Total Influence metric on a LocalGraph.
 * Thread-safe: operates only on passed-in graph, no shared state.
 */
class SLICCentrality
{
public:
  /**
   * \param alpha1 Weight for ISC (default 0.05)
   * \param alpha2 Weight for Semi-Local Influence (default 0.50)
   * \param alpha3 Weight for LASP (default 0.45)
   * \param beta   Distance decay for Semi-Local (default 0.5)
   * \param semiLocalRadius Hop radius for Semi-Local (default 3)
   * \param laspRadius Hop radius for LASP subgraph (default 2)
   * \param iscRadius Hop radius for ISC neighbor count (default 1)
   */
  SLICCentrality (double alpha1 = 0.05,
                  double alpha2 = 0.50,
                  double alpha3 = 0.45,
                  double beta = 0.5,
                  uint32_t semiLocalRadius = 3,
                  uint32_t laspRadius = 2,
                  uint32_t iscRadius = 1);

  // --- Individual sub-metrics ---

  /**
   * \brief ISC: degree(v) * count of minimum-degree nodes in hop neighborhood.
   *
   * Original Python:
   *   ISC_FN.append(N * G.degree(j))
   *   where N counts neighbors with degree == min_degree
   */
  double ComputeISC (const LocalGraph& G, uint32_t v) const;

  /**
   * \brief Semi-Local Influence incorporating WW weighted path products.
   *
   * Original Python:
   *   I_Semi_Local[i] = (1/(c+1)) * sum over L levels of
   *     beta^l * sum_over_level_nodes(sqrt(WW*DC) / (l*(DC_i+DC_k)))
   */
  double ComputeSemiLocal (const LocalGraph& G, uint32_t v) const;

  /**
   * \brief Semi-Local Influence with precomputed edge weights (avoids O(k) recomputation).
   */
  double ComputeSemiLocalFast (const LocalGraph& G, uint32_t v,
    const std::map<std::pair<uint32_t, uint32_t>, double>& W) const;

  /**
   * \brief LASP: relative change in ASP when node is removed from 2-hop subgraph.
   *
   * Original Python:
   *   AC = abs(ASPR - ASP) / ASP
   */
  double ComputeLASP (const LocalGraph& G, uint32_t v) const;

  // --- Composite metric ---

  /**
   * \brief Compute Total Influence for a single node.
   *
   * Computes all three sub-metrics for ALL nodes in G (needed for
   * normalization), normalizes to [0,1], then returns the weighted
   * composite for the requested node.
   */
  double ComputeTotalInfluence (const LocalGraph& G, uint32_t v) const;

  /**
   * \brief Batch computation for all nodes in the local graph.
   * More efficient than calling ComputeTotalInfluence per node.
   * \return Map of nodeId -> CentralityResult
   */
  std::map<uint32_t, CentralityResult> ComputeAllCentralities (
    const LocalGraph& G) const;

  // --- Configuration ---
  void SetWeights (double a1, double a2, double a3);
  void SetBeta (double beta);
  void SetRadii (uint32_t semiLocal, uint32_t lasp, uint32_t isc);
  double GetAlpha1 () const { return m_alpha1; }
  double GetAlpha2 () const { return m_alpha2; }
  double GetAlpha3 () const { return m_alpha3; }
  double GetBeta () const { return m_beta; }

  /**
   * \brief Enable/disable min-max normalization of sub-metrics.
   * Default is true (normalization enabled).
   */
  void SetNormalize (bool normalize) { m_normalize = normalize; }
  bool GetNormalize () const { return m_normalize; }

private:
  /**
   * \brief Compute edge weights using Neighbor Degree (ND) policy.
   *
   * W(i,j) = sum(degrees of i's neighbors)/degree(i)
   *         + sum(degrees of j's neighbors)/degree(j)
   *
   * Only computed for existing edges (O(m) not O(n^2)).
   */
  std::map<std::pair<uint32_t, uint32_t>, double> ComputeEdgeWeights (
    const LocalGraph& G) const;

  /**
   * \brief Weighted path product WW(src, dst) in log-space.
   *
   * WW = product of W(e) for all edges e on shortest path from src to dst.
   * Computed as exp(sum(log(W(e)))) for numerical stability.
   */
  double ComputeWW (const LocalGraph& G, uint32_t src, uint32_t dst,
                    const std::map<std::pair<uint32_t, uint32_t>, double>& W) const;

  /**
   * \brief Min-max normalization of a vector to [0,1].
   * If all values are equal, sets all to 0.5.
   */
  static void Normalize (std::vector<double>& values);

  double m_alpha1;          ///< ISC weight
  double m_alpha2;          ///< Semi-Local weight
  double m_alpha3;          ///< LASP weight
  double m_beta;            ///< Distance decay
  uint32_t m_semiLocalRadius; ///< L for Semi-Local
  uint32_t m_laspRadius;      ///< Hop radius for LASP subgraph
  uint32_t m_iscRadius;       ///< Hop radius for ISC
  bool m_normalize;           ///< Whether to normalize sub-metrics (default true)
};

} // namespace slic
} // namespace ns3

#endif /* SLIC_CENTRALITY_H */