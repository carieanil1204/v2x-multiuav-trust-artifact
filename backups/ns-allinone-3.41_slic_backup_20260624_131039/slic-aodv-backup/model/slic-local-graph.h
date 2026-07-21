/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-local-graph.h
 *
 * Lightweight adjacency-list graph for SLIC centrality computation.
 * Replaces all NetworkX functionality used in the original Python code.
 * Designed for small local subgraphs (20-50 nodes within 3-hop neighborhood).
 */

#ifndef SLIC_LOCAL_GRAPH_H
#define SLIC_LOCAL_GRAPH_H

#include <cstdint>
#include <map>
#include <set>
#include <vector>
#include <utility>
#include <limits>

namespace ns3 {
namespace slic {

static const int INF_DIST = std::numeric_limits<int>::max() / 2;

/**
 * \brief Lightweight undirected graph for SLIC centrality computation.
 *
 * Stores topology as adjacency sets. Provides BFS, all-pairs shortest paths,
 * subgraph extraction, and node removal — all operations required by the
 * three SLIC sub-metrics (ISC, Semi-Local, LASP).
 */
class LocalGraph
{
public:
  LocalGraph ();

  // --- Graph construction ---
  void AddNode (uint32_t nodeId);
  void AddEdge (uint32_t u, uint32_t v);
  void RemoveNode (uint32_t v);
  void RemoveEdge (uint32_t u, uint32_t v);
  void Clear ();

  // --- Queries ---
  bool HasNode (uint32_t v) const;
  bool HasEdge (uint32_t u, uint32_t v) const;
  uint32_t GetNodeCount () const;
  uint32_t GetEdgeCount () const;
  uint32_t GetDegree (uint32_t v) const;
  uint32_t GetMinDegree () const;
  uint32_t GetMaxDegree () const;
  std::vector<uint32_t> GetNodes () const;
  const std::set<uint32_t>& GetNeighbors (uint32_t v) const;

  // --- Algorithms ---

  /**
   * \brief BFS from source up to maxHops.
   * \return Map of nodeId -> distance from source.
   */
  std::map<uint32_t, uint32_t> BFS (uint32_t source, uint32_t maxHops) const;

  /**
   * \brief Shortest path between src and dst (BFS for unweighted).
   * \return Vector of node IDs forming the path. Empty if unreachable.
   */
  std::vector<uint32_t> ShortestPath (uint32_t src, uint32_t dst) const;

  /**
   * \brief Shortest path length between src and dst.
   * \return Path length, or INF_DIST if unreachable.
   */
  int ShortestPathLength (uint32_t src, uint32_t dst) const;

  /**
   * \brief All-pairs shortest paths using BFS from each node.
   *
   * Returns a 2D matrix indexed by position in GetNodes() ordering.
   * apsp[i][j] = shortest distance between nodes[i] and nodes[j].
   * INF_DIST if unreachable. 0 on diagonal.
   */
  std::vector<std::vector<int>> AllPairsShortestPaths () const;

  /**
   * \brief Average shortest path length over all reachable pairs.
   * Unreachable pairs are excluded from the average.
   * Returns 0 if fewer than 2 nodes.
   */
  double AverageShortestPathLength () const;

  /**
   * \brief Diameter: maximum shortest path length among all reachable pairs.
   */
  int Diameter () const;

  /**
   * \brief Extract subgraph induced by the given node set.
   * Includes only edges where both endpoints are in nodeSet.
   */
  LocalGraph Subgraph (const std::set<uint32_t>& nodeSet) const;

  /**
   * \brief Return a copy of this graph with node v and all its edges removed.
   */
  LocalGraph WithoutNode (uint32_t v) const;

private:
  std::map<uint32_t, std::set<uint32_t>> m_adjList;
  static const std::set<uint32_t> EMPTY_SET;
};

} // namespace slic
} // namespace ns3

#endif /* SLIC_LOCAL_GRAPH_H */
