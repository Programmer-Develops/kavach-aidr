"""
graph_builder.py — Build a feature graph from parsed Python code.

Converts ParsedCode into a structured CodeGraph with numerical feature vectors
and adjacency relations for VulnGNN inference and AST taint flow analysis.
"""

from dataclasses import dataclass, field
from typing import Any
from kavach.ingestion.parser import ParsedCode, FunctionInfo


# ── Dangerous API patterns used for feature extraction ─────────────────────
# These are Python calls associated with known vulnerability classes.

DANGEROUS_CALLS = {
    # Injection
    "eval"          : ("CODE_INJECTION", "HIGH"),
    "exec"          : ("CODE_INJECTION", "HIGH"),
    "compile"       : ("CODE_INJECTION", "MEDIUM"),
    "__import__"    : ("CODE_INJECTION", "MEDIUM"),

    # OS / Shell injection
    "os.system"     : ("COMMAND_INJECTION", "CRITICAL"),
    "subprocess.call": ("COMMAND_INJECTION", "HIGH"),
    "subprocess.run": ("COMMAND_INJECTION", "HIGH"),
    "subprocess.Popen": ("COMMAND_INJECTION", "HIGH"),
    "popen"         : ("COMMAND_INJECTION", "CRITICAL"),

    # Deserialization
    "pickle.loads"  : ("DESERIALIZATION", "CRITICAL"),
    "pickle.load"   : ("DESERIALIZATION", "CRITICAL"),
    "yaml.load"     : ("DESERIALIZATION", "HIGH"),
    "marshal.loads" : ("DESERIALIZATION", "HIGH"),
    "shelve.open"   : ("DESERIALIZATION", "MEDIUM"),

    # Path traversal
    "open"          : ("PATH_TRAVERSAL", "MEDIUM"),    # only risky with user input

    # Weak crypto
    "md5"           : ("WEAK_CRYPTO", "HIGH"),
    "sha1"          : ("WEAK_CRYPTO", "HIGH"),
    "DES"           : ("WEAK_CRYPTO", "CRITICAL"),
    "RC4"           : ("WEAK_CRYPTO", "CRITICAL"),

    # SQL / NoSQL injection signals
    "execute"       : ("SQL_INJECTION", "HIGH"),
    "executemany"   : ("SQL_INJECTION", "HIGH"),
    "raw"           : ("SQL_INJECTION", "MEDIUM"),
    "format"        : ("SQL_INJECTION", "LOW"),       # low alone, high with DB context

    # Network
    "socket.socket" : ("NETWORK_EXPOSURE", "MEDIUM"),
    "bind"          : ("NETWORK_EXPOSURE", "MEDIUM"),
}

SENSITIVE_IMPORTS = {
    "pickle"     : ("DESERIALIZATION", "CRITICAL"),
    "marshal"    : ("DESERIALIZATION", "HIGH"),
    "yaml"       : ("DESERIALIZATION", "MEDIUM"),
    "subprocess" : ("COMMAND_INJECTION", "HIGH"),
    "os"         : ("COMMAND_INJECTION", "MEDIUM"),
    "hashlib"    : ("WEAK_CRYPTO", "LOW"),       # flag if MD5/SHA1 used
    "Crypto"     : ("CRYPTO", "MEDIUM"),
    "ftplib"     : ("NETWORK_EXPOSURE", "HIGH"),
    "telnetlib"  : ("NETWORK_EXPOSURE", "CRITICAL"),
}

HARDCODED_SECRET_PATTERNS = [
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "auth_token", "access_token", "private_key", "passphrase",
]


# ── Output dataclass ────────────────────────────────────────────────────────

@dataclass
class CodeNode:
    """A single node in the vulnerability feature graph."""
    node_id   : str
    node_type : str          # "function" | "import" | "call" | "assignment"
    name      : str
    lineno    : int
    vuln_type : str = ""     # detected vulnerability class
    severity  : str = ""     # CRITICAL | HIGH | MEDIUM | LOW
    features  : dict[str, Any] = field(default_factory=dict)


@dataclass
class CodeGraph:
    """Feature graph built from parsed Python code."""
    filepath  : str
    nodes     : list[CodeNode] = field(default_factory=list)
    edges     : list[tuple[str, str]] = field(default_factory=list)  # (node_id, node_id)
    risk_score: float = 0.0       # aggregate risk [0.0 – 1.0]
    summary   : dict[str, Any] = field(default_factory=dict)


# ── Builder ─────────────────────────────────────────────────────────────────

def build_graph(parsed: "ParsedCode") -> CodeGraph:
    """
    Build a CodeGraph from a ParsedCode object.

    Strategy:
    1. Create nodes for every function, import, and suspicious assignment.
    2. Create edges from call-site to callee (where detectable).
    3. Annotate nodes with vulnerability hints.
    4. Compute an aggregate risk score.

    Args:
        parsed: Output of ingestion.parser.parse_file()

    Returns:
        CodeGraph ready for VulnGNN inference or LLM context building.
    """
    graph = CodeGraph(filepath=str(parsed.filepath))

    severity_weights = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.4, "LOW": 0.15}
    risk_scores: list[float] = []

    # ── Import nodes ─────────────────────────────────────────────────────
    for imp in parsed.imports:
        for name in imp.names:
            full = f"{imp.module}.{name}" if imp.module else name
            vuln_type, severity = _check_import(full, imp.module)
            node = CodeNode(
                node_id   = f"import:{imp.lineno}:{name}",
                node_type = "import",
                name      = full,
                lineno    = imp.lineno,
                vuln_type = vuln_type,
                severity  = severity,
                features  = {"module": imp.module, "is_from": imp.is_from},
            )
            graph.nodes.append(node)
            if severity:
                risk_scores.append(severity_weights.get(severity, 0.0))

    # ── Function nodes ────────────────────────────────────────────────────
    for func in parsed.functions:
        node = CodeNode(
            node_id   = f"func:{func.lineno}:{func.name}",
            node_type = "function",
            name      = func.name,
            lineno    = func.lineno,
            features  = {
                "args"           : func.args,
                "calls"          : func.calls,
                "body_line_count": func.end_lineno - func.lineno,
            },
        )
        graph.nodes.append(node)

        # ── Call nodes inside this function ──────────────────────────────
        for call in func.calls:
            vuln_type, severity = _check_call(call)
            if vuln_type:
                call_node = CodeNode(
                    node_id   = f"call:{func.lineno}:{call}",
                    node_type = "call",
                    name      = call,
                    lineno    = func.lineno,
                    vuln_type = vuln_type,
                    severity  = severity,
                    features  = {"inside_function": func.name},
                )
                graph.nodes.append(call_node)
                graph.edges.append((node.node_id, call_node.node_id))
                risk_scores.append(severity_weights.get(severity, 0.0))

    # ── Assignment nodes — detect hardcoded secrets ───────────────────────
    for assign in parsed.assignments:
        if _is_secret_assignment(assign.target, assign.value):
            node = CodeNode(
                node_id   = f"assign:{assign.lineno}:{assign.target}",
                node_type = "assignment",
                name      = assign.target,
                lineno    = assign.lineno,
                vuln_type = "HARDCODED_SECRET",
                severity  = "CRITICAL",
                features  = {"value_preview": assign.value[:40]},
            )
            graph.nodes.append(node)
            risk_scores.append(1.0)

    # ── Aggregate risk score ──────────────────────────────────────────────
    if risk_scores:
        # Use 80th-percentile-weighted average (not naive mean)
        risk_scores.sort(reverse=True)
        top_n = max(1, len(risk_scores) // 3)
        graph.risk_score = min(1.0, sum(risk_scores[:top_n]) / top_n)

    graph.summary = {
        "total_nodes"      : len(graph.nodes),
        "total_edges"      : len(graph.edges),
        "vuln_nodes"       : sum(1 for n in graph.nodes if n.vuln_type),
        "risk_score"       : round(graph.risk_score, 3),
        "severity_counts"  : _count_severities(graph.nodes),
    }
    return graph


def get_vuln_nodes(graph: CodeGraph) -> list[CodeNode]:
    """Return only nodes that have a detected vulnerability type."""
    return [n for n in graph.nodes if n.vuln_type]


def graph_to_llm_context(graph: CodeGraph, parsed: "ParsedCode") -> str:
    """
    Serialize graph vulnerability findings into a text block suitable
    for inclusion in an LLM prompt as structured context.
    """
    from kavach.ingestion.parser import get_code_snippet

    vuln_nodes = get_vuln_nodes(graph)
    if not vuln_nodes:
        return "No suspicious patterns detected by graph analysis."

    lines = ["=== Graph Analysis Findings ==="]
    for node in vuln_nodes:
        lines.append(
            f"\n[{node.severity}] {node.vuln_type} | Line {node.lineno} | `{node.name}`"
        )
        snippet = get_code_snippet(parsed, node.lineno, context=2)
        lines.append(snippet)

    return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _check_import(full_name: str, module: str) -> tuple[str, str]:
    for key, (vuln, sev) in SENSITIVE_IMPORTS.items():
        if key in full_name or key == module:
            return vuln, sev
    return "", ""


def _check_call(call_name: str) -> tuple[str, str]:
    for key, (vuln, sev) in DANGEROUS_CALLS.items():
        if call_name == key or call_name.endswith(f".{key.split('.')[-1]}"):
            return vuln, sev
    return "", ""


def _is_secret_assignment(target: str, value: str) -> bool:
    """Check if an assignment looks like a hardcoded secret."""
    target_lower = target.lower()
    if not any(kw in target_lower for kw in HARDCODED_SECRET_PATTERNS):
        return False
    # Value is a string literal (not a function call or variable reference)
    value_stripped = value.strip()
    if value_stripped.startswith(("'", '"', 'f"', "f'", 'b"', "b'")):
        # Must not be an empty string
        return len(value_stripped) > 3
    return False


def _count_severities(nodes: list[CodeNode]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for node in nodes:
        if node.severity in counts:
            counts[node.severity] += 1
    return counts
