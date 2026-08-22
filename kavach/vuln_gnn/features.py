"""
features.py — Extract node feature vectors from CodeGraph for VulnGNN.

Converts the symbolic CodeGraph representation into numeric feature vectors
that a GNN can process. Each node becomes a fixed-size vector encoding:
  - Node type (one-hot)
  - Danger level (ordinal)
  - Vulnerability count
  - Call depth estimate
  - Whether it's a known dangerous API
"""

from typing import Any


NODE_TYPES  = ["FUNCTION", "CALL", "IMPORT", "ASSIGN", "CLASS", "OTHER"]
DANGER_LEVELS = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "": 0}


def node_to_features(node: Any) -> list[float]:
    """
    Convert a CodeNode to a numeric feature vector.

    Feature vector (16 dimensions):
      [0-5]  : Node type (one-hot over NODE_TYPES)
      [6-8]  : Danger level (ordinal: 0-3) + normalized
      [9]    : Has vulnerability annotation (0/1)
      [10]   : Number of vulnerability types (normalized)
      [11]   : Risk score (normalized 0-1)
      [12]   : Is a known API call (0/1)
      [13]   : Has dangerous import (0/1)
      [14]   : Is user-facing (0/1) — placeholder
      [15]   : Graph connectivity (degree, normalized) — placeholder
    """
    vec = [0.0] * 16

    # One-hot node type
    node_type = getattr(node, "node_type", "OTHER")
    if node_type in NODE_TYPES:
        vec[NODE_TYPES.index(node_type)] = 1.0
    else:
        vec[5] = 1.0   # OTHER

    # Danger level
    danger  = getattr(node, "danger_level", "") or ""
    danger_val = DANGER_LEVELS.get(danger.upper(), 0)
    vec[6]  = danger_val / 3.0   # normalize

    # Has vuln annotation
    vuln_types = getattr(node, "vuln_types", []) or []
    vec[9]  = 1.0 if vuln_types else 0.0

    # Vuln type count (normalized — max 5)
    vec[10] = min(len(vuln_types), 5) / 5.0

    # Risk score
    risk = getattr(node, "risk_score", 0.0) or 0.0
    vec[11] = min(float(risk), 10.0) / 10.0

    # Is a call node
    vec[12] = 1.0 if node_type == "CALL" else 0.0

    # Has dangerous import
    vec[13] = 1.0 if (node_type == "IMPORT" and danger_val > 0) else 0.0

    return vec


def graph_to_feature_matrix(code_graph: Any) -> tuple[list[list[float]], list[str]]:
    """
    Convert a full CodeGraph to a feature matrix.

    Returns:
        (feature_matrix, node_names):
            feature_matrix: List of feature vectors, one per node
            node_names    : Node names in same order
    """
    nodes       = list(code_graph.nodes.values())
    node_names  = [n.name for n in nodes]
    feat_matrix = [node_to_features(n) for n in nodes]
    return feat_matrix, node_names


def graph_to_adjacency(code_graph: Any) -> list[list[int]]:
    """
    Build adjacency list representation of the code graph.

    Returns:
        adj[i] = list of node indices that node i connects to.
    """
    nodes      = list(code_graph.nodes.values())
    name_to_idx = {n.name: i for i, n in enumerate(nodes)}
    adj        = [[] for _ in nodes]

    for edge in getattr(code_graph, "edges", []):
        src = name_to_idx.get(edge.get("src", ""), -1)
        dst = name_to_idx.get(edge.get("dst", ""), -1)
        if src >= 0 and dst >= 0:
            adj[src].append(dst)

    return adj
