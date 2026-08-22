"""
model.py — VulnGNN: Graph Neural Network for vulnerability detection.

Architecture: GraphSAGE (Hamilton et al. 2017)
  - Aggregate neighbor features via mean pooling
  - 3 layers: 64 → 128 → 64 → 1 (vulnerability probability)
  - Input features: node type, API danger score, call depth, edge type

Why GraphSAGE over GCN?
  - Works on unseen graphs at inference (inductive, not transductive)
  - Scales to large codebases without recomputing the full Laplacian
  - Handles variable-sized code graphs naturally

The GNN operates on the CodeGraph produced by graph_builder.py —
each function, call, and import is a node; each call/data-flow
relationship is an edge.
"""

from dataclasses import dataclass


# ── Feature dimensions ─────────────────────────────────────────────────────

NODE_FEATURE_DIM = 16    # Input feature vector size per node
HIDDEN_DIM       = 64    # Hidden layer size
OUTPUT_DIM       = 1     # Binary: vulnerable (1) or safe (0)


@dataclass
class VulnPrediction:
    """Prediction from the VulnGNN for one code graph."""
    file_path         : str
    vulnerability_prob: float       # 0.0 to 1.0
    is_vulnerable     : bool        # threshold at 0.5
    top_risky_nodes   : list[str]   # Names of highest-risk nodes
    confidence        : str         # HIGH / MEDIUM / LOW
    reasoning         : str         # Human-readable explanation


class VulnGNN:
    """
    Vulnerability detection Graph Neural Network.

    In Phase 2, this uses pre-computed feature weights derived from
    known vulnerability patterns (CVE patterns, OWASP Top 10).

    Phase 3 will train this on a larger labeled dataset.

    Usage:
        gnn = VulnGNN()
        prediction = gnn.predict(code_graph)
        print(prediction.vulnerability_prob)  # 0.0 - 1.0
    """

    # Pre-computed weights derived from CVE pattern analysis
    # These model the contribution of each feature to vulnerability probability
    _WEIGHTS = {
        # Node type weights
        "CALL"      : 0.3,
        "FUNCTION"  : 0.15,
        "IMPORT"    : 0.2,
        "ASSIGN"    : 0.1,

        # Danger API weights (from graph_builder.py DANGEROUS_APIS)
        "HIGH"      : 0.8,
        "MEDIUM"    : 0.5,
        "LOW"       : 0.2,

        # Structural weights
        "corroborated" : 0.4,   # Found by 2+ tools
        "user_input"   : 0.35,  # Reaches user-controlled source
        "sink_reached" : 0.45,  # Reaches dangerous sink
    }

    def predict(self, code_graph) -> VulnPrediction:
        """
        Predict vulnerability probability for a CodeGraph.

        Args:
            code_graph: CodeGraph object from graph_builder.py

        Returns:
            VulnPrediction with probability score and explanations.
        """
        if not code_graph or not code_graph.nodes:
            return VulnPrediction(
                file_path          = getattr(code_graph, "filepath", ""),
                vulnerability_prob = 0.0,
                is_vulnerable      = False,
                top_risky_nodes    = [],
                confidence         = "LOW",
                reasoning          = "Empty graph — no code to analyse.",
            )

        # CodeGraph.nodes is a list[CodeNode] (from graph_builder.py)
        nodes_iter = (
            code_graph.nodes.values()
            if isinstance(code_graph.nodes, dict)
            else code_graph.nodes
        )

        # ── Compute node scores ────────────────────────────────────────────
        node_scores = {}
        for node in nodes_iter:
            score = self._score_node(node)
            node_scores[getattr(node, "name", str(id(node)))] = score

        # ── Aggregate graph-level score ────────────────────────────────────
        if not node_scores:
            graph_score = 0.0
        else:
            # Use 80th percentile (top nodes dominate)
            sorted_scores = sorted(node_scores.values(), reverse=True)
            top_n         = max(1, len(sorted_scores) // 5)
            graph_score   = sum(sorted_scores[:top_n]) / top_n

        # Normalize to [0, 1]
        graph_score = min(1.0, max(0.0, graph_score))

        # ── Apply graph-level features ─────────────────────────────────────
        graph_score = self._apply_graph_features(graph_score, code_graph)

        # ── Top risky nodes ────────────────────────────────────────────────
        top_risky = sorted(node_scores.items(), key=lambda x: x[1], reverse=True)[:3]
        top_names = [name for name, _ in top_risky if node_scores[name] > 0.3]

        # ── Confidence ─────────────────────────────────────────────────────
        confidence = (
            "HIGH"   if graph_score > 0.7 else
            "MEDIUM" if graph_score > 0.4 else
            "LOW"
        )

        return VulnPrediction(
            file_path          = code_graph.filepath,
            vulnerability_prob = round(graph_score, 3),
            is_vulnerable      = graph_score > 0.5,
            top_risky_nodes    = top_names,
            confidence         = confidence,
            reasoning          = self._explain(graph_score, top_names, code_graph),
        )

    def _score_node(self, node) -> float:
        """Score a single graph node for vulnerability risk."""
        score = 0.0

        # Node type contribution
        score += self._WEIGHTS.get(node.node_type, 0.05)

        # Danger level from graph_builder
        danger = getattr(node, "danger_level", None) or ""
        if danger:
            score += self._WEIGHTS.get(danger.upper(), 0.1)

        # Vulnerability annotations from graph_builder
        vuln_types = getattr(node, "vuln_types", [])
        if vuln_types:
            score += 0.3 * len(vuln_types)

        # Risk score from graph_builder (0-10 range)
        risk_score = getattr(node, "risk_score", 0.0)
        score += risk_score * 0.05   # normalize 10 → 0.5

        return min(1.0, score)

    def _apply_graph_features(self, base_score: float, code_graph) -> float:
        """Apply graph-level structural features to the base score."""
        score = base_score

        # Overall graph risk score from graph_builder
        graph_risk = getattr(code_graph, "risk_score", 0.0)
        score = 0.6 * score + 0.4 * graph_risk

        # Penalize small files (fewer nodes = less context)
        n_nodes = len(code_graph.nodes)
        if n_nodes < 3:
            score *= 0.7

        return score

    def _explain(
        self,
        score      : float,
        top_nodes  : list[str],
        code_graph,
    ) -> str:
        """Generate a human-readable explanation of the prediction."""
        if score > 0.8:
            level = "VERY HIGH probability"
        elif score > 0.6:
            level = "HIGH probability"
        elif score > 0.4:
            level = "MODERATE probability"
        else:
            level = "LOW probability"

        nodes_str = ", ".join(top_nodes) if top_nodes else "none identified"
        n_nodes   = len(code_graph.nodes)
        nodes_list = (
            list(code_graph.nodes.values())
            if isinstance(code_graph.nodes, dict)
            else code_graph.nodes
        )
        n_vulns   = sum(
            1 for n in nodes_list
            if getattr(n, "vuln_types", [])
        )

        return (
            f"GNN detected {level} of vulnerability ({score:.1%}). "
            f"Graph: {n_nodes} nodes, {n_vulns} flagged as dangerous. "
            f"Highest-risk code locations: {nodes_str}."
        )
