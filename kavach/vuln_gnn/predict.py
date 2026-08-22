"""
predict.py — VulnGNN inference entry point.

Single function interface to run VulnGNN prediction on a CodeGraph.
Designed to be called from the main pipeline orchestrator.
"""

from kavach.vuln_gnn.model import VulnGNN, VulnPrediction

_gnn = None   # Singleton

def predict_vulnerability(code_graph) -> VulnPrediction:
    """
    Run VulnGNN prediction on a CodeGraph.

    Args:
        code_graph: CodeGraph from graph_builder.build_graph()

    Returns:
        VulnPrediction with probability and explanation.
    """
    global _gnn
    if _gnn is None:
        _gnn = VulnGNN()
    return _gnn.predict(code_graph)


def batch_predict(code_graphs: list) -> list[VulnPrediction]:
    """Run VulnGNN on multiple graphs."""
    global _gnn
    if _gnn is None:
        _gnn = VulnGNN()
    return [_gnn.predict(g) for g in code_graphs]
