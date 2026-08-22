"""
bandit_runner.py — Run Bandit security linter on Python source files.

Bandit is Python's most widely-used security linter. It uses AST analysis
to detect common security issues without network access.

This module:
  1. Invokes bandit as a subprocess (fully offline)
  2. Parses its JSON output
  3. Returns normalised Finding objects compatible with semgrep_runner
"""

import json
import subprocess
import shutil
from pathlib import Path
from kavach.static.semgrep_runner import Finding, _sort_findings


def run_bandit(
    target_path : str | Path,
    confidence  : str = "LOW",    # Report ALL confidence levels
    timeout     : int = 120,
) -> list[Finding]:
    """
    Run Bandit on target_path and return normalised Finding objects.

    Args:
        target_path : File or directory to scan.
        confidence  : Minimum confidence level (LOW | MEDIUM | HIGH).
        timeout     : Max seconds.

    Returns:
        List of Finding objects sorted by severity.
    """
    if not shutil.which("bandit"):
        raise EnvironmentError(
            "bandit not found. Install with: pip install bandit"
        )

    target = Path(target_path)

    cmd = [
        "bandit",
        "--format", "json",
        "--confidence-level", confidence.lower(),
        "--severity-level", "low",   # Report all severity levels
        "--recursive" if target.is_dir() else "--skip", "",
    ]

    # Remove blank --skip arg if scanning a file
    if target.is_file():
        cmd = ["bandit", "--format", "json",
               "--confidence-level", confidence.lower(),
               "--severity-level", "low",
               str(target)]
    else:
        cmd = ["bandit", "--format", "json",
               "--confidence-level", confidence.lower(),
               "--severity-level", "low",
               "--recursive", str(target)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return []

    # Bandit exits 1 when issues found — normal
    if result.returncode not in (0, 1):
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for item in data.get("results", []):
        severity   = _map_bandit_severity(item.get("issue_severity", "MEDIUM"))
        confidence = _map_bandit_confidence(item.get("issue_confidence", "MEDIUM"))
        test_id    = item.get("test_id", "B000")
        test_name  = item.get("test_name", "unknown")
        message    = item.get("issue_text", "").strip()

        finding = Finding(
            tool        = "bandit",
            rule_id     = test_id,
            severity    = severity,
            vuln_type   = _bandit_vuln_type(test_id, test_name),
            message     = message,
            filepath    = item.get("filename", ""),
            lineno      = item.get("line_number", 0),
            col         = item.get("col_offset", 0),
            end_lineno  = item.get("line_range", [0])[-1],
            code_snippet= item.get("code", "").strip(),
            cwe         = _bandit_cwe(test_id),
            confidence  = confidence,
        )
        findings.append(finding)

    return _sort_findings(findings)


# ── Bandit test ID → metadata mappings ──────────────────────────────────────

_BANDIT_VULN_MAP: dict[str, str] = {
    "B101": "ASSERT_USED",
    "B102": "EXEC_USED",
    "B103": "SETTING_PERMISSION",
    "B104": "HARDCODED_BIND_ALL",
    "B105": "HARDCODED_SECRET",
    "B106": "HARDCODED_SECRET",
    "B107": "HARDCODED_SECRET",
    "B108": "PROBABLE_TMPNAM",
    "B110": "TRY_EXCEPT_PASS",
    "B112": "TRY_EXCEPT_CONTINUE",
    "B201": "FLASK_DEBUG_TRUE",
    "B301": "DESERIALIZATION",     # pickle
    "B302": "DESERIALIZATION",     # marshal
    "B303": "WEAK_CRYPTO",         # MD5/SHA1
    "B304": "WEAK_CRYPTO",         # DES/RC4
    "B305": "WEAK_CRYPTO",         # cipher modes
    "B306": "DESERIALIZATION",     # mktemp
    "B307": "CODE_INJECTION",      # eval
    "B311": "WEAK_CRYPTO",         # random
    "B312": "NETWORK_EXPOSURE",    # telnetlib
    "B313": "XXE",
    "B314": "XXE",
    "B315": "XXE",
    "B316": "XXE",
    "B317": "XXE",
    "B318": "XXE",
    "B319": "XXE",
    "B320": "XXE",
    "B321": "NETWORK_EXPOSURE",    # FTP
    "B322": "CODE_INJECTION",      # input() py2
    "B323": "INSECURE_TLS",
    "B324": "WEAK_CRYPTO",         # hashlib MD5/SHA1
    "B325": "DESERIALIZATION",     # tempnam
    "B401": "NETWORK_EXPOSURE",    # telnetlib import
    "B402": "NETWORK_EXPOSURE",    # ftplib import
    "B403": "DESERIALIZATION",     # pickle import
    "B404": "COMMAND_INJECTION",   # subprocess import
    "B405": "DESERIALIZATION",     # xml.etree import
    "B406": "XXE",                 # xml.sax import
    "B407": "XXE",                 # xml.expat import
    "B408": "XXE",                 # xml.dom import
    "B409": "XXE",                 # xml.pulldom import
    "B410": "XXE",                 # lxml import
    "B411": "DESERIALIZATION",     # xmlrpclib
    "B412": "NETWORK_EXPOSURE",    # httpoxy
    "B413": "WEAK_CRYPTO",         # pycrypto
    "B501": "INSECURE_TLS",
    "B502": "INSECURE_TLS",
    "B503": "INSECURE_TLS",
    "B504": "INSECURE_TLS",
    "B505": "WEAK_CRYPTO",
    "B506": "DESERIALIZATION",     # yaml.load
    "B507": "INSECURE_SSH",
    "B601": "COMMAND_INJECTION",   # paramiko
    "B602": "COMMAND_INJECTION",   # subprocess shell=True
    "B603": "COMMAND_INJECTION",   # subprocess without shell
    "B604": "COMMAND_INJECTION",   # function call with shell
    "B605": "COMMAND_INJECTION",   # os.system
    "B606": "COMMAND_INJECTION",   # os.popen
    "B607": "COMMAND_INJECTION",   # partial executable path
    "B608": "SQL_INJECTION",       # hardcoded SQL
    "B609": "COMMAND_INJECTION",   # wildcard injection
    "B610": "SQL_INJECTION",       # Django extra()
    "B611": "SQL_INJECTION",       # Django RawSQL()
    "B701": "TEMPLATE_INJECTION",  # jinja2 autoescaping
    "B702": "TEMPLATE_INJECTION",  # use of mako
    "B703": "TEMPLATE_INJECTION",  # Django mark_safe
}

_BANDIT_CWE_MAP: dict[str, list[str]] = {
    "B301": ["CWE-502"],
    "B302": ["CWE-502"],
    "B303": ["CWE-326"],
    "B307": ["CWE-78"],
    "B506": ["CWE-502"],
    "B602": ["CWE-78"],
    "B605": ["CWE-78"],
    "B608": ["CWE-89"],
}

def _bandit_vuln_type(test_id: str, test_name: str) -> str:
    return _BANDIT_VULN_MAP.get(test_id, test_name.upper().replace(" ", "_"))

def _bandit_cwe(test_id: str) -> list[str]:
    return _BANDIT_CWE_MAP.get(test_id, [])

def _map_bandit_severity(raw: str) -> str:
    m = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return m.get(raw.upper(), "MEDIUM")

def _map_bandit_confidence(raw: str) -> str:
    m = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return m.get(raw.upper(), "MEDIUM")
