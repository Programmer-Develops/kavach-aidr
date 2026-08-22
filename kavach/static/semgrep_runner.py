"""
semgrep_runner.py — Run Semgrep static analysis on Python source files.

Semgrep uses pattern-matching rules written in YAML to find security issues
in source code. It operates on the AST level (not just regex), so it has
very few false positives.

This module:
  1. Invokes semgrep as a subprocess (safe — no internet, all local)
  2. Collects findings from both built-in rulesets and our custom rules
  3. Returns a normalised list of Finding objects
"""

import json
import subprocess
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
CUSTOM_RULES_DIR = DATA_DIR / "semgrep_rules"


@dataclass
class Finding:
    """A single security finding from any analysis tool."""
    tool        : str              # "semgrep" | "bandit" | "graph"
    rule_id     : str
    severity    : str              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    vuln_type   : str              # e.g. "SQL_INJECTION"
    message     : str
    filepath    : str
    lineno      : int
    col         : int = 0
    end_lineno  : int = 0
    code_snippet: str = ""
    fix_hint    : str = ""
    cwe         : list[str] = field(default_factory=list)
    confidence  : str = "MEDIUM"   # HIGH | MEDIUM | LOW


def run_semgrep(
    target_path: str | Path,
    extra_rules : Optional[list[str]] = None,
    timeout     : int = 120,
) -> list[Finding]:
    """
    Run Semgrep on target_path and return a list of normalised Finding objects.

    Args:
        target_path : File or directory to scan.
        extra_rules : Additional rule paths or registry IDs.
        timeout     : Max seconds to wait for semgrep.

    Returns:
        List of Finding objects, sorted by severity (CRITICAL first).
    """
    if not shutil.which("semgrep"):
        raise EnvironmentError(
            "semgrep not found. Install with: pip install semgrep"
        )

    target = Path(target_path)

    # ── Build semgrep command ─────────────────────────────────────────────
    cmd = [
        "semgrep",
        "--json",          # Machine-readable output
        "--quiet",         # Suppress banner
        "--no-git-ignore", # Don't skip files based on .gitignore
    ]

    # Add our custom military-context rules if they exist
    if CUSTOM_RULES_DIR.exists():
        for rule_file in CUSTOM_RULES_DIR.glob("*.yml"):
            cmd += ["--config", str(rule_file)]

    # Python security ruleset (built-in, offline — packed with semgrep)
    cmd += ["--config", "p/python"]

    # Add any extra rules passed in
    if extra_rules:
        for r in extra_rules:
            cmd += ["--config", r]

    cmd.append(str(target))

    # ── Execute ───────────────────────────────────────────────────────────
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return []
    except FileNotFoundError:
        raise EnvironmentError("semgrep binary not found on PATH.")

    # Semgrep exits 1 when findings exist — that's normal
    if result.returncode not in (0, 1):
        return []

    # ── Parse JSON output ─────────────────────────────────────────────────
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for item in data.get("results", []):
        meta     = item.get("extra", {})
        severity = _map_severity(meta.get("severity", "WARNING"))
        message  = meta.get("message", "").strip()
        metadata = meta.get("metadata", {})

        # Extract CWE tags
        cwe = []
        for tag in metadata.get("cwe", []):
            cwe.append(str(tag))

        finding = Finding(
            tool        = "semgrep",
            rule_id     = item.get("check_id", "unknown"),
            severity    = severity,
            vuln_type   = _infer_vuln_type(item.get("check_id", ""), message),
            message     = message,
            filepath    = item.get("path", ""),
            lineno      = item.get("start", {}).get("line", 0),
            col         = item.get("start", {}).get("col", 0),
            end_lineno  = item.get("end", {}).get("line", 0),
            code_snippet= meta.get("lines", ""),
            fix_hint    = meta.get("fix", ""),
            cwe         = cwe,
            confidence  = _map_confidence(metadata.get("confidence", "MEDIUM")),
        )
        findings.append(finding)

    return _sort_findings(findings)


# ── Helpers ──────────────────────────────────────────────────────────────────

_SEV_MAP = {
    "ERROR"  : "CRITICAL",
    "WARNING": "HIGH",
    "INFO"   : "MEDIUM",
}

def _map_severity(raw: str) -> str:
    return _SEV_MAP.get(raw.upper(), "MEDIUM")

def _map_confidence(raw: str) -> str:
    return raw.upper() if raw.upper() in ("HIGH", "MEDIUM", "LOW") else "MEDIUM"

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

def _infer_vuln_type(rule_id: str, message: str) -> str:
    """Guess the vulnerability class from rule ID / message text."""
    rule_lower = rule_id.lower()
    msg_lower  = message.lower()
    combined   = rule_lower + " " + msg_lower

    mapping = {
        "sql"          : "SQL_INJECTION",
        "injection"    : "INJECTION",
        "xss"          : "XSS",
        "csrf"         : "CSRF",
        "pickle"       : "DESERIALIZATION",
        "deserializ"   : "DESERIALIZATION",
        "yaml.load"    : "DESERIALIZATION",
        "hardcode"     : "HARDCODED_SECRET",
        "secret"       : "HARDCODED_SECRET",
        "password"     : "HARDCODED_SECRET",
        "token"        : "HARDCODED_SECRET",
        "path"         : "PATH_TRAVERSAL",
        "traversal"    : "PATH_TRAVERSAL",
        "exec"         : "CODE_INJECTION",
        "eval"         : "CODE_INJECTION",
        "command"      : "COMMAND_INJECTION",
        "shell"        : "COMMAND_INJECTION",
        "subprocess"   : "COMMAND_INJECTION",
        "os.system"    : "COMMAND_INJECTION",
        "weak"         : "WEAK_CRYPTO",
        "md5"          : "WEAK_CRYPTO",
        "sha1"         : "WEAK_CRYPTO",
        "tls"          : "INSECURE_TLS",
        "ssl"          : "INSECURE_TLS",
        "auth"         : "AUTH_BYPASS",
        "ldap"         : "LDAP_INJECTION",
        "xxe"          : "XXE",
        "idor"         : "IDOR",
        "race"         : "RACE_CONDITION",
        "overflow"     : "BUFFER_OVERFLOW",
        "format"       : "FORMAT_STRING",
    }
    for keyword, vtype in mapping.items():
        if keyword in combined:
            return vtype
    return "SECURITY_ISSUE"
