"""
crash_triager.py — Classify and deduplicate fuzzer crashes.

Takes raw Python exceptions from fuzzing and classifies them into:
  - EXPLOITABLE: likely indicates a real security issue
  - CRASH: unexpected termination / error
  - EXPECTED: handled exception (not a bug)

Also deduplicates crashes by bucketing on exception type + call stack signature.
"""

import hashlib
import traceback
from dataclasses import dataclass, field
from kavach.fuzzer.mutation_engine import Payload


# Exceptions that strongly indicate a security vulnerability was triggered
EXPLOITABLE_EXCEPTIONS = {
    "sqlite3.OperationalError"     : "SQL_INJECTION",
    "sqlite3.ProgrammingError"     : "SQL_INJECTION",
    "PermissionError"              : "PATH_TRAVERSAL",
    "IsADirectoryError"            : "PATH_TRAVERSAL",
    "FileNotFoundError"            : "PATH_TRAVERSAL",
    "OSError"                      : "COMMAND_INJECTION",
    "pickle.UnpicklingError"       : "DESERIALIZATION",
    "yaml.constructor.ConstructorError": "DESERIALIZATION",
    "SyntaxError"                  : "CODE_INJECTION",
    "MemoryError"                  : "BUFFER_OVERFLOW",
    "RecursionError"               : "LOGIC_ERROR",
    "OverflowError"                : "INTEGER_OVERFLOW",
    "KeyError"                     : "LOGIC_ERROR",
    "IndexError"                   : "LOGIC_ERROR",
    "UnicodeDecodeError"           : "ENCODING_ISSUE",
}

# Exceptions that are expected/handled and NOT indicative of a bug
EXPECTED_EXCEPTIONS = {
    "ValueError",
    "TypeError",
    "AttributeError",
    "NotImplementedError",
    "StopIteration",
}


@dataclass
class CrashReport:
    """A single unique crash from fuzzing."""
    crash_id       : str     # Hash of (exception_type + traceback)
    exception_type : str     # e.g. "sqlite3.OperationalError"
    exception_msg  : str
    traceback_str  : str
    payload        : Payload
    function_name  : str
    is_exploitable : bool
    implied_vuln   : str     # e.g. "SQL_INJECTION"
    severity       : str     # CRITICAL | HIGH | MEDIUM


def triage_crash(
    exception     : Exception,
    payload       : Payload,
    function_name : str,
) -> "CrashReport":
    """
    Classify a Python exception from fuzzing into a CrashReport.

    Args:
        exception     : The caught exception
        payload       : The input that caused it
        function_name : Which function was being fuzzed

    Returns:
        CrashReport with exploitability classification.
    """
    exc_type    = type(exception).__name__
    full_type   = f"{type(exception).__module__}.{exc_type}"
    exc_msg     = str(exception)[:300]
    tb_str      = traceback.format_exc()[:500]

    # Generate crash ID (for deduplication)
    crash_hash  = hashlib.md5(f"{exc_type}:{tb_str[:100]}".encode()).hexdigest()[:8]

    # Determine exploitability
    is_exploitable = False
    implied_vuln   = payload.vuln_type
    severity       = "MEDIUM"

    # Check known exploitable exception types
    for pattern, vuln in EXPLOITABLE_EXCEPTIONS.items():
        if pattern in full_type or pattern in exc_type:
            is_exploitable = True
            implied_vuln   = vuln
            severity       = "HIGH"
            break

    # Expected exceptions are NOT exploitable
    if exc_type in EXPECTED_EXCEPTIONS:
        is_exploitable = False
        severity       = "LOW"

    # Critical: SQL errors with injection-style inputs are almost certainly SQLi
    if "SQL" in implied_vuln.upper() and ("syntax" in exc_msg.lower() or
                                           "no such" in exc_msg.lower()):
        is_exploitable = True
        severity       = "CRITICAL"

    return CrashReport(
        crash_id       = crash_hash,
        exception_type = exc_type,
        exception_msg  = exc_msg,
        traceback_str  = tb_str,
        payload        = payload,
        function_name  = function_name,
        is_exploitable = is_exploitable,
        implied_vuln   = implied_vuln,
        severity       = severity,
    )


def deduplicate_crashes(crashes: list[CrashReport]) -> list[CrashReport]:
    """
    Remove duplicate crashes (same exception + same call site).
    Returns unique crashes sorted by severity.
    """
    seen    = set()
    unique  = []
    sev_ord = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

    for crash in sorted(crashes, key=lambda c: sev_ord.get(c.severity, 99)):
        if crash.crash_id not in seen:
            seen.add(crash.crash_id)
            unique.append(crash)

    return unique


def crashes_summary(crashes: list[CrashReport]) -> dict:
    """Summarize crash list."""
    return {
        "total"        : len(crashes),
        "exploitable"  : sum(1 for c in crashes if c.is_exploitable),
        "critical"     : sum(1 for c in crashes if c.severity == "CRITICAL"),
        "high"         : sum(1 for c in crashes if c.severity == "HIGH"),
        "vuln_types"   : list({c.implied_vuln for c in crashes}),
    }
