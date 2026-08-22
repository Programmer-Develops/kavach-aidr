"""
siem_exporter.py — Export KAVACH-AIDR audit data to SIEM-compatible formats.

Supports:
  - CEF (Common Event Format) — used by ArcSight, Splunk
  - Syslog RFC5424 format
  - Plain JSON (for custom SIEM integrations)

This allows the Indian Army Security Operations Centre (SOC) to ingest
KAVACH-AIDR findings directly into their existing SIEM infrastructure.
"""

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# CEF severity mapping
_SEV_TO_CEF = {
    "CRITICAL": 10,
    "HIGH"    : 7,
    "MEDIUM"  : 5,
    "LOW"     : 3,
    "INFO"    : 1,
}


def export_cef(
    findings   : list[Any],
    run_id     : str,
    output_path: str | Path,
) -> Path:
    """
    Export findings as CEF (Common Event Format) lines.
    CEF is the standard format for ArcSight, IBM QRadar, Splunk.

    CEF line format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions

    Args:
        findings   : List of MergedFinding objects.
        run_id     : KAVACH-AIDR run UUID.
        output_path: Output .cef file path.

    Returns:
        Path to written file.
    """
    lines = []
    timestamp = datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S")
    hostname  = socket.gethostname()

    for finding in findings:
        severity_int = _SEV_TO_CEF.get(finding.severity, 5)
        cwe_str      = ",".join(finding.cwe) if finding.cwe else "unknown"
        sources_str  = ",".join(finding.sources)

        # CEF header
        header = (
            f"CEF:0|KAVACH-AIDR|CyberReasoningEngine|1.0|"
            f"{finding.vuln_type}|{finding.message[:50]}|{severity_int}|"
        )

        # CEF extension (key=value pairs)
        ext = (
            f"rt={timestamp} "
            f"dhost={hostname} "
            f"fname={finding.filepath} "
            f"spt={finding.lineno} "
            f"cat={finding.vuln_type} "
            f"cs1={finding.severity} cs1Label=Severity "
            f"cs2={cwe_str} cs2Label=CWE "
            f"cs3={sources_str} cs3Label=Tools "
            f"cs4={run_id} cs4Label=RunID "
            f"flexNumber1={finding.score:.2f} flexNumber1Label=RiskScore "
            f"msg={finding.message[:200].replace('=', '-').replace('|', '/')}"
        )

        lines.append(header + ext)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_syslog(
    findings   : list[Any],
    run_id     : str,
    output_path: str | Path,
    facility   : int = 13,   # 13 = log audit (auth)
) -> Path:
    """
    Export findings as RFC5424 Syslog format.

    Args:
        findings   : List of MergedFinding objects.
        run_id     : KAVACH-AIDR run UUID.
        output_path: Output .log file path.
        facility   : Syslog facility number.

    Returns:
        Path to written file.
    """
    lines = []
    hostname = socket.gethostname()
    now      = datetime.now(timezone.utc).isoformat()

    for finding in findings:
        sev_syslog = _sev_to_syslog(finding.severity)
        pri        = (facility * 8) + sev_syslog
        msg        = (
            f"KAVACH-AIDR: run={run_id} "
            f"vuln={finding.vuln_type} "
            f"severity={finding.severity} "
            f"file={finding.filepath} "
            f"line={finding.lineno} "
            f"score={finding.score:.2f} "
            f"sources={','.join(finding.sources)}"
        )
        # RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
        line = f"<{pri}>1 {now} {hostname} kavach-aidr - {finding.vuln_type} - {msg}"
        lines.append(line)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_json_findings(
    findings   : list[Any],
    run_id     : str,
    output_path: str | Path,
) -> Path:
    """
    Export findings as clean JSON — for custom SIEM / REST API integration.
    """
    data = {
        "run_id"       : run_id,
        "exported_at"  : datetime.now(timezone.utc).isoformat(),
        "total"        : len(findings),
        "findings"     : [
            {
                "id"          : f.finding_id,
                "vuln_type"   : f.vuln_type,
                "severity"    : f.severity,
                "message"     : f.message,
                "filepath"    : f.filepath,
                "lineno"      : f.lineno,
                "sources"     : f.sources,
                "corroborated": f.corroborated,
                "score"       : round(f.score, 3),
                "cwe"         : f.cwe,
                "code_snippet": f.code_snippet,
            }
            for f in findings
        ],
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sev_to_syslog(severity: str) -> int:
    """Map KAVACH severity to RFC5424 syslog severity."""
    return {
        "CRITICAL": 2,   # Critical
        "HIGH"    : 3,   # Error
        "MEDIUM"  : 4,   # Warning
        "LOW"     : 6,   # Informational
        "INFO"    : 7,   # Debug
    }.get(severity, 4)
