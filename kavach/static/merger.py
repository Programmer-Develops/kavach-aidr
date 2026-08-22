"""
merger.py — Merge, deduplicate, and rank findings from all static analysis tools.

Takes findings from Semgrep + Bandit + Graph analysis and produces a single,
ranked, deduplicated list of vulnerabilities for the LLM Reasoner to process.

Deduplication strategy:
  - Two findings are duplicates if they point to the same file + same line
    range AND share the same vulnerability type.
  - When duplicates are found, the higher-severity version wins.
  - Confidence is boosted when multiple tools agree on the same issue
    (cross-tool corroboration → "CONFIRMED" status).
"""

from dataclasses import dataclass, field
from typing import Optional
from kavach.static.semgrep_runner import Finding


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEVERITY_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class MergedFinding:
    """A deduplicated, cross-corroborated vulnerability finding."""
    finding_id   : str              # Unique ID: "{vuln_type}:{filepath}:{lineno}"
    vuln_type    : str
    severity     : str
    message      : str
    filepath     : str
    lineno       : int
    end_lineno   : int
    code_snippet : str
    fix_hint     : str
    cwe          : list[str]
    sources      : list[str]        # Which tools found this ("semgrep", "bandit", "graph")
    rule_ids     : list[str]        # All rule IDs that triggered
    corroborated : bool = False     # True if 2+ tools found the same issue
    confidence   : str = "MEDIUM"
    score        : float = 0.0      # Numeric priority score for ranking


def merge_findings(
    semgrep_findings : list[Finding],
    bandit_findings  : list[Finding],
    graph_findings   : Optional[list[Finding]] = None,
) -> list[MergedFinding]:
    """
    Merge findings from all tools, deduplicate, and rank by priority.

    Args:
        semgrep_findings : Output from semgrep_runner.run_semgrep()
        bandit_findings  : Output from bandit_runner.run_bandit()
        graph_findings   : Optional output from graph analysis
                           (use graph_to_findings() to convert CodeGraph)

    Returns:
        Sorted list of MergedFinding (highest priority first).
    """
    all_findings: list[Finding] = (
        semgrep_findings + bandit_findings + (graph_findings or [])
    )

    # ── Group by deduplication key ────────────────────────────────────────
    bucket: dict[str, list[Finding]] = {}
    for f in all_findings:
        key = _dedup_key(f)
        bucket.setdefault(key, []).append(f)

    # ── Merge each group into a single MergedFinding ──────────────────────
    merged: list[MergedFinding] = []
    for key, group in bucket.items():
        mf = _merge_group(key, group)
        merged.append(mf)

    # ── Sort by priority score ────────────────────────────────────────────
    merged.sort(key=lambda m: m.score, reverse=True)
    return merged


def graph_to_findings(graph: "CodeGraph") -> list[Finding]:
    """
    Convert CodeGraph vuln nodes to Finding objects for merging.
    Import CodeGraph from kavach.ingestion.graph_builder.
    """
    findings = []
    for node in graph.nodes:
        if not node.vuln_type:
            continue
        findings.append(Finding(
            tool        = "graph",
            rule_id     = f"GRAPH:{node.vuln_type}",
            severity    = node.severity or "MEDIUM",
            vuln_type   = node.vuln_type,
            message     = f"Suspicious pattern detected: {node.name}",
            filepath    = graph.filepath,
            lineno      = node.lineno,
            end_lineno  = node.lineno,
            code_snippet= "",
            confidence  = "MEDIUM",
        ))
    return findings


def get_top_findings(merged: list[MergedFinding], n: int = 5) -> list[MergedFinding]:
    """Return the top-N highest-priority findings."""
    return merged[:n]


def findings_summary(merged: list[MergedFinding]) -> dict:
    """Return a summary dict suitable for logging and display."""
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for mf in merged:
        sev_counts[mf.severity] = sev_counts.get(mf.severity, 0) + 1

    return {
        "total"       : len(merged),
        "corroborated": sum(1 for m in merged if m.corroborated),
        "severity"    : sev_counts,
        "vuln_types"  : list({m.vuln_type for m in merged}),
    }


# ── Internal helpers ─────────────────────────────────────────────────────────

def _dedup_key(f: Finding) -> str:
    """
    Build a deduplication key for a finding.
    Two findings share a key if they point to the same location
    AND the same vulnerability class.
    """
    # Normalise line to a 5-line window to catch off-by-one between tools
    line_bucket = (f.lineno // 5) * 5
    return f"{f.vuln_type}:{f.filepath}:{line_bucket}"


def _merge_group(key: str, group: list[Finding]) -> MergedFinding:
    """Merge a list of duplicate findings into one MergedFinding."""
    # Use the highest-severity finding as the representative
    group.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    best = group[0]

    sources  = sorted({f.tool for f in group})
    rule_ids = [f.rule_id for f in group]
    cwe      = list({c for f in group for c in f.cwe})

    # Boost confidence if multiple tools agree
    corroborated = len(sources) > 1
    confidence   = "HIGH" if corroborated else best.confidence

    # Numeric score: base severity + corroboration bonus + confidence boost
    base_score    = _SEVERITY_SCORE.get(best.severity, 0)
    corr_bonus    = 1.5 if corroborated else 0.0
    conf_bonus    = {"HIGH": 0.5, "MEDIUM": 0.25, "LOW": 0.0}.get(confidence, 0.0)
    score         = base_score + corr_bonus + conf_bonus

    # Best available snippet
    snippet = next((f.code_snippet for f in group if f.code_snippet), "")
    fix_hint= next((f.fix_hint for f in group if f.fix_hint), "")

    return MergedFinding(
        finding_id   = key,
        vuln_type    = best.vuln_type,
        severity     = best.severity,
        message      = best.message,
        filepath     = best.filepath,
        lineno       = best.lineno,
        end_lineno   = best.end_lineno,
        code_snippet = snippet,
        fix_hint     = fix_hint,
        cwe          = cwe,
        sources      = sources,
        rule_ids     = rule_ids,
        corroborated = corroborated,
        confidence   = confidence,
        score        = score,
    )
