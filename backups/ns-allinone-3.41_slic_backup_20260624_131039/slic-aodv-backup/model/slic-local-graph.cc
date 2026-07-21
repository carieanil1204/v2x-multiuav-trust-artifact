/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * slic-local-graph.cc
 *
 * Implementation of lightweight graph for SLIC centrality.
 * All algorithms are O(k^2) or O(k^3) where k is local subgraph size.
 */

#include "slic-local-graph.h"
#include <queue>
#include <algorithm>
#include <cmath>
#include <cassert>

namespace ns3 {
namespace slic {

const std::set<uint32_t> LocalGraph::EMPTY_SET = {};

LocalGraph::LocalGraph ()
{
}

void
LocalGraph::AddNode (uint32_t nodeId)
{
  if (m_adjList.find (nodeId) == m_adjList.end ())
    {
      m_adjList[nodeId] = std::set<uint32_t> ();
    }
}

void
LocalGraph::AddEdge (uint32_t u, uint32_t v)
{
  AddNode (u);
  AddNode (v);
  if (u != v)
    {
      m_adjList[u].insert (v);
      m_adjList[v].insert (u);
    }
}

void
LocalGraph::RemoveNode (uint32_t v)
{
  auto it = m_adjList.find (v);
  if (it == m_adjList.end ())
    return;

  // Remove v from all neighbors' adjacency sets
  for (uint32_t neighbor : it->second)
    {
      m_adjList[neighbor].erase (v);
    }
  m_adjList.erase (it);
}

void
LocalGraph::RemoveEdge (uint32_t u, uint32_t v)
{
  auto itU = m_adjList.find (u);
  auto itV = m_adjList.find (v);
  if (itU != m_adjList.end ())
    itU->second.erase (v);
  if (itV != m_adjList.end ())
    itV->second.erase (u);
}

void
LocalGraph::Clear ()
{
  m_adjList.clear ();
}

bool
LocalGraph::HasNode (uint32_t v) const
{
  return m_adjList.find (v) != m_adjList.end ();
}

bool
LocalGraph::HasEdge (uint32_t u, uint32_t v) const
{
  auto it = m_adjList.find (u);
  if (it == m_adjList.end ())
    return false;
  return it->second.count (v) > 0;
}

uint32_t
LocalGraph::GetNodeCount () const
{
  return static_cast<uint32_t> (m_adjList.size ());
}

uint32_t
LocalGraph::GetEdgeCount () const
{
  uint32_t count = 0;
  for (const auto& kv : m_adjList)
    {
      count += static_cast<uint32_t> (kv.second.size ());
    }
  return count / 2; // each edge counted twice
}

uint32_t
LocalGraph::GetDegree (uint32_t v) const
{
  auto it = m_adjList.find (v);
  if (it == m_adjList.end ())
    return 0;
  return static_cast<uint32_t> (it->second.size ());
}

uint32_t
LocalGraph::GetMinDegree () const
{
  if (m_adjList.empty ())
    return 0;
  uint32_t minDeg = std::numeric_limits<uint32_t>::max ();
  for (const auto& kv : m_adjList)
    {
      uint32_t deg = static_cast<uint32_t> (kv.second.size ());
      if (deg < minDeg)
        minDeg = deg;
    }
  return minDeg;
}

uint32_t
LocalGraph::GetMaxDegree () const
{
  uint32_t maxDeg = 0;
  for (const auto& kv : m_adjList)
    {
      uint32_t deg = static_cast<uint32_t> (kv.second.size ());
      if (deg > maxDeg)
        maxDeg = deg;
    }
  return maxDeg;
}

std::vector<uint32_t>
LocalGraph::GetNodes () const
{
  std::vector<uint32_t> nodes;
  nodes.reserve (m_adjList.size ());
  for (const auto& kv : m_adjList)
    {
      nodes.push_back (kv.first);
    }
  return nodes;
}

const std::set<uint32_t>&
LocalGraph::GetNeighbors (uint32_t v) const
{
  auto it = m_adjList.find (v);
  if (it == m_adjList.end ())
    return EMPTY_SET;
  return it->second;
}

// ─── BFS ─────────────────────────────────────────────────────

std::map<uint32_t, uint32_t>
LocalGraph::BFS (uint32_t source, uint32_t maxHops) const
{
  std::map<uint32_t, uint32_t> dist;
  if (!HasNode (source))
    return dist;

  std::queue<uint32_t> q;
  dist[source] = 0;
  q.push (source);

  while (!q.empty ())
    {
      uint32_t curr = q.front ();
      q.pop ();
      uint32_t currDist = dist[curr];

      if (currDist >= maxHops)
        continue;

      for (uint32_t neighbor : GetNeighbors (curr))
        {
          if (dist.find (neighbor) == dist.end ())
            {
              dist[neighbor] = currDist + 1;
              q.push (neighbor);
            }
        }
    }
  return dist;
}

std::vector<uint32_t>
LocalGraph::ShortestPath (uint32_t src, uint32_t dst) const
{
  if (!HasNode (src) || !HasNode (dst))
    return {};
  if (src == dst)
    return {src};

  std::map<uint32_t, uint32_t> parent;
  std::queue<uint32_t> q;
  parent[src] = src;
  q.push (src);

  while (!q.empty ())
    {
      uint32_t curr = q.front ();
      q.pop ();

      if (curr == dst)
        {
          // Reconstruct path
          std::vector<uint32_t> path;
          uint32_t node = dst;
          while (node != src)
            {
              path.push_back (node);
              node = parent[node];
            }
          path.push_back (src);
          std::reverse (path.begin (), path.end ());
          return path;
        }

      for (uint32_t neighbor : GetNeighbors (curr))
        {
          if (parent.find (neighbor) == parent.end ())
            {
              parent[neighbor] = curr;
              q.push (neighbor);
            }
        }
    }
  return {}; // unreachable
}

int
LocalGraph::ShortestPathLength (uint32_t src, uint32_t dst) const
{
  if (src == dst)
    return 0;
  auto path = ShortestPath (src, dst);
  if (path.empty ())
    return INF_DIST;
  return static_cast<int> (path.size () - 1);
}

std::vector<std::vector<int>>
LocalGraph::AllPairsShortestPaths () const
{
  auto nodes = GetNodes ();
  uint32_t n = static_cast<uint32_t> (nodes.size ());
  std::map<uint32_t, uint32_t> nodeIndex;
  for (uint32_t i = 0; i < n; ++i)
    {
      nodeIndex[nodes[i]] = i;
    }

  // Initialize distance matrix
  std::vector<std::vector<int>> dist (n, std::vector<int> (n, INF_DIST));
  for (uint32_t i = 0; i < n; ++i)
    {
      dist[i][i] = 0;
    }

  // Set edge distances
  for (uint32_t i = 0; i < n; ++i)
    {
      for (uint32_t neighbor : GetNeighbors (nodes[i]))
        {
          auto it = nodeIndex.find (neighbor);
          if (it != nodeIndex.end ())
            {
              dist[i][it->second] = 1;
            }
        }
    }

  // Floyd-Warshall (O(k^3), k = local subgraph size, typically 20-50)
  for (uint32_t k = 0; k < n; ++k)
    {
      for (uint32_t i = 0; i < n; ++i)
        {
          for (uint32_t j = 0; j < n; ++j)
            {
              if (dist[i][k] < INF_DIST && dist[k][j] < INF_DIST)
                {
                  int through_k = dist[i][k] + dist[k][j];
                  if (through_k < dist[i][j])
                    dist[i][j] = through_k;
                }
            }
        }
    }
  return dist;
}

double
LocalGraph::AverageShortestPathLength () const
{
  auto apsp = AllPairsShortestPaths ();
  uint32_t n = static_cast<uint32_t> (apsp.size ());
  if (n < 2)
    return 0.0;

  double totalDist = 0.0;
  uint32_t reachablePairs = 0;

  for (uint32_t i = 0; i < n; ++i)
    {
      for (uint32_t j = i + 1; j < n; ++j)
        {
          if (apsp[i][j] < INF_DIST)
            {
              totalDist += apsp[i][j];
              reachablePairs++;
            }
        }
    }

  if (reachablePairs == 0)
    return 0.0;
  return totalDist / reachablePairs;
}

int
LocalGraph::Diameter () const
{
  auto apsp = AllPairsShortestPaths ();
  int maxDist = 0;
  for (const auto& row : apsp)
    {
      for (int d : row)
        {
          if (d < INF_DIST && d > maxDist)
            maxDist = d;
        }
    }
  return maxDist;
}

LocalGraph
LocalGraph::Subgraph (const std::set<uint32_t>& nodeSet) const
{
  LocalGraph sub;
  for (uint32_t v : nodeSet)
    {
      if (HasNode (v))
        {
          sub.AddNode (v);
        }
    }
  for (uint32_t v : nodeSet)
    {
      if (!HasNode (v))
        continue;
      for (uint32_t u : GetNeighbors (v))
        {
          if (nodeSet.count (u) > 0 && u > v) // add each edge once
            {
              sub.AddEdge (v, u);
            }
        }
    }
  return sub;
}

LocalGraph
LocalGraph::WithoutNode (uint32_t v) const
{
  std::set<uint32_t> remaining;
  for (const auto& kv : m_adjList)
    {
      if (kv.first != v)
        remaining.insert (kv.first);
    }
  return Subgraph (remaining);
}

} // namespace slic
} // namespace ns3
