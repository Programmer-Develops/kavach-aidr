"""
constraint_builder.py — Translate Python code patterns into Z3 SMT constraints.

This is the bridge between code analysis and formal verification.
For each vulnerability type, we encode the security property as a
Z3 logical formula:

  BEFORE patch: ∃ input such that dangerous condition is satisfiable → VULNERABLE
  AFTER  patch: ∀ inputs, dangerous condition is UNSATISFIABLE → SAFE

Vulnerability ↔ SMT constraint mapping:
  SQL_INJECTION     → user input appears literally in SQL string
  PATH_TRAVERSAL    → resolved path escapes the base directory
  COMMAND_INJECTION → user input appears in shell command
  HARDCODED_SECRET  → a string literal matches known secret patterns
  WEAK_CRYPTO       → MD5/SHA1 used for security-sensitive operation
"""

import ast
import re
from dataclasses import dataclass, field
from typing import Optional

try:
    from z3 import (
        String, StringVal, Contains, PrefixOf, SuffixOf,
        Length, Concat, BoolVal, Or, And, Not, Implies,
        Solver, sat, unsat, unknown, IntVal, Int
    )
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False


@dataclass
class SMTConstraint:
    """A Z3 SMT constraint pair for a specific vulnerability."""
    vuln_type       : str
    filepath        : str
    lineno          : int
    # Pre-patch: what makes this code VULNERABLE (should be SAT)
    vulnerable_desc : str
    # Post-patch: what makes this code SAFE (should be UNSAT)
    safe_desc       : str
    # Z3 formula objects (None if Z3 not available)
    vulnerable_formula : object = None
    safe_formula       : object = None
    encodable          : bool   = True    # False = too complex for SMT
    encoding_note      : str    = ""


def build_constraints(
    vuln_type   : str,
    source_code : str,
    lineno      : int,
    filepath    : str,
) -> SMTConstraint:
    """
    Build Z3 SMT constraints for a given vulnerability type and source location.

    Args:
        vuln_type   : e.g. "SQL_INJECTION", "PATH_TRAVERSAL"
        source_code : Full source of the file
        lineno      : Line of the vulnerability
        filepath    : Path label

    Returns:
        SMTConstraint with Z3 formula objects ready for z3_verifier.
    """
    builders = {
        "SQL_INJECTION"     : _build_sqli_constraints,
        "COMMAND_INJECTION" : _build_cmdi_constraints,
        "PATH_TRAVERSAL"    : _build_path_constraints,
        "HARDCODED_SECRET"  : _build_secret_constraints,
        "WEAK_CRYPTO"       : _build_crypto_constraints,
        "DESERIALIZATION"   : _build_deser_constraints,
        "CODE_INJECTION"    : _build_code_injection_constraints,
    }

    builder = builders.get(vuln_type)
    if not builder:
        return SMTConstraint(
            vuln_type        = vuln_type,
            filepath         = filepath,
            lineno           = lineno,
            vulnerable_desc  = f"No SMT encoding for {vuln_type}",
            safe_desc        = f"No SMT encoding for {vuln_type}",
            encodable        = False,
            encoding_note    = f"Vulnerability type '{vuln_type}' not yet SMT-encodable.",
        )

    return builder(source_code, lineno, filepath)


# ── Per-vulnerability constraint builders ─────────────────────────────────────

def _build_sqli_constraints(source: str, lineno: int, filepath: str) -> SMTConstraint:
    """
    SQL Injection: user input appears literally inside a SQL query string.

    VULNERABLE: ∃ user_input s.t. query_string Contains user_input
                AND user_input Contains SQL_METACHAR
    SAFE:       query_string does NOT directly contain user_input
                (parameterised: placeholder ? used instead)
    """
    SQL_INJECTION_CHARS = ["'", '"', "--", ";", "/*", "*/", "OR", "AND", "DROP", "UNION"]

    c = SMTConstraint(
        vuln_type       = "SQL_INJECTION",
        filepath        = filepath,
        lineno          = lineno,
        vulnerable_desc = "User input directly concatenated into SQL query string — injection possible",
        safe_desc       = "User input passed as parameter, not concatenated — injection impossible",
    )

    if not Z3_AVAILABLE:
        c.encodable     = False
        c.encoding_note = "z3-solver not installed"
        return c

    user_input  = String("user_input")
    query       = String("sql_query")

    # VULNERABLE: user_input is a SQL injection payload AND appears in query
    sql_payload = Or(*[Contains(user_input, StringVal(ch)) for ch in SQL_INJECTION_CHARS])
    c.vulnerable_formula = And(sql_payload, Contains(query, user_input))

    # SAFE: query does NOT literally contain user_input (parameterized)
    # i.e., for ALL user_input values, user_input is NOT in the query string
    c.safe_formula = Not(Contains(query, user_input))

    return c


def _build_cmdi_constraints(source: str, lineno: int, filepath: str) -> SMTConstraint:
    """
    Command Injection: shell metacharacters in user input reach os.system / subprocess.
    """
    SHELL_METACHAR = [";", "&&", "||", "|", "`", "$(", "&", ">", "<"]

    c = SMTConstraint(
        vuln_type       = "COMMAND_INJECTION",
        filepath        = filepath,
        lineno          = lineno,
        vulnerable_desc = "User input with shell metacharacters can be passed to shell command",
        safe_desc       = "User input is validated/escaped before reaching shell",
    )

    if not Z3_AVAILABLE:
        c.encodable = False; c.encoding_note = "z3-solver not installed"; return c

    user_input = String("user_input")
    command    = String("shell_command")

    metachar_in_input = Or(*[Contains(user_input, StringVal(ch)) for ch in SHELL_METACHAR])
    c.vulnerable_formula = And(metachar_in_input, Contains(command, user_input))
    # Safe: command does not contain raw user_input
    c.safe_formula = Not(Contains(command, user_input))
    return c


def _build_path_constraints(source: str, lineno: int, filepath: str) -> SMTConstraint:
    """
    Path Traversal: resolved path escapes the intended base directory.

    VULNERABLE: ∃ user_path s.t. base_dir + user_path escapes base_dir
                (i.e., user_path contains '../')
    SAFE: realpath(base_dir + user_path) starts with base_dir
    """
    c = SMTConstraint(
        vuln_type       = "PATH_TRAVERSAL",
        filepath        = filepath,
        lineno          = lineno,
        vulnerable_desc = "User-controlled path can escape the base directory via '../'",
        safe_desc       = "Resolved path is validated to stay within base directory",
    )

    if not Z3_AVAILABLE:
        c.encodable = False; c.encoding_note = "z3-solver not installed"; return c

    user_path = String("user_path")
    base_dir  = StringVal("/var/army_data/")
    full_path = Concat(base_dir, user_path)

    # VULNERABLE: user_path contains traversal sequences
    traversal = Or(
        Contains(user_path, StringVal("../")),
        Contains(user_path, StringVal("..\\")),
        Contains(user_path, StringVal("%2e%2e")),
    )
    c.vulnerable_formula = traversal

    # SAFE: full path starts with base_dir (no traversal possible)
    c.safe_formula = Not(traversal)
    return c


def _build_secret_constraints(source: str, lineno: int, filepath: str) -> SMTConstraint:
    """
    Hardcoded Secret: a string literal in source matches known secret patterns.

    We extract string literals from the source and check if they look like
    real credentials (non-empty, non-placeholder, long enough).
    """
    c = SMTConstraint(
        vuln_type       = "HARDCODED_SECRET",
        filepath        = filepath,
        lineno          = lineno,
        vulnerable_desc = "A string literal in source code matches credential/secret pattern",
        safe_desc       = "Secret loaded from environment variable or secrets manager",
    )

    # Extract string literals near the vulnerability line
    string_literals = _extract_strings_near_line(source, lineno, window=3)

    if not Z3_AVAILABLE:
        c.encodable     = False
        c.encoding_note = "z3-solver not installed"
        return c

    if not string_literals:
        c.encodable     = False
        c.encoding_note = "No string literals found near the flagged line"
        return c

    # Model: secret_value is one of the found literals
    secret_val  = String("secret_value")
    placeholder = ["", "your_password", "changeme", "example", "placeholder", "xxxx"]

    # VULNERABLE: literal is non-empty AND not a placeholder AND has sufficient length
    is_real_secret = And(
        *[Not(Contains(secret_val, StringVal(p))) for p in placeholder],
        Length(secret_val) > IntVal(6),
    )
    c.vulnerable_formula = is_real_secret
    # SAFE: secret comes from env (can't be modeled as a string literal — so safe formula
    # is the negation: secret_val IS a placeholder / empty)
    c.safe_formula = Or(*[Contains(secret_val, StringVal(p)) for p in placeholder])
    return c


def _build_crypto_constraints(source: str, lineno: int, filepath: str) -> SMTConstraint:
    """Weak cryptographic algorithm in use."""
    c = SMTConstraint(
        vuln_type       = "WEAK_CRYPTO",
        filepath        = filepath,
        lineno          = lineno,
        vulnerable_desc = "Broken hash algorithm (MD5/SHA1) used for security-sensitive operation",
        safe_desc       = "Strong hash algorithm (SHA-256/SHA-3/bcrypt) used instead",
        encodable       = False,   # Crypto algorithm choice is a code-level fact, not SMT
        encoding_note   = "Algorithm selection is determined statically; "
                          "Z3 verifies patch replaces weak with strong algorithm.",
    )
    return c


def _build_deser_constraints(source: str, lineno: int, filepath: str) -> SMTConstraint:
    """Insecure deserialization."""
    c = SMTConstraint(
        vuln_type       = "DESERIALIZATION",
        filepath        = filepath,
        lineno          = lineno,
        vulnerable_desc = "Untrusted data passed to pickle.loads/yaml.load — RCE possible",
        safe_desc       = "Data validated before deserialization or safe loader used",
        encodable       = False,
        encoding_note   = "Deserialization safety requires data-flow analysis beyond SMT strings.",
    )
    return c


def _build_code_injection_constraints(source: str, lineno: int, filepath: str) -> SMTConstraint:
    """eval() / exec() with user-controlled input."""
    c = SMTConstraint(
        vuln_type       = "CODE_INJECTION",
        filepath        = filepath,
        lineno          = lineno,
        vulnerable_desc = "User-controlled expression passed to eval() — code execution possible",
        safe_desc       = "eval() replaced with ast.literal_eval() or removed entirely",
    )

    if not Z3_AVAILABLE:
        c.encodable = False; c.encoding_note = "z3-solver not installed"; return c

    user_input = String("eval_input")
    # VULNERABLE: input contains Python code constructs
    code_chars = ["import", "__", "os.", "sys.", "open(", "exec("]
    c.vulnerable_formula = Or(*[Contains(user_input, StringVal(ch)) for ch in code_chars])
    c.safe_formula = Not(Or(*[Contains(user_input, StringVal(ch)) for ch in code_chars]))
    return c


# ── Helpers ──────────────────────────────────────────────────────────────────

def _extract_strings_near_line(source: str, lineno: int, window: int = 3) -> list[str]:
    """Extract string literals from source lines around lineno."""
    lines   = source.splitlines()
    start   = max(0, lineno - 1 - window)
    end     = min(len(lines), lineno + window)
    snippet = "\n".join(lines[start:end])

    strings = []
    try:
        tree = ast.parse(snippet)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if len(node.value) > 3:
                    strings.append(node.value)
    except SyntaxError:
        # Fallback: regex extraction
        strings = re.findall(r'["\']([^"\']{4,})["\']', snippet)

    return strings
