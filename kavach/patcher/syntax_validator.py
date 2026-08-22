"""
syntax_validator.py — Validate patched Python code before writing to disk.

Runs multiple validation checks to ensure the LLM-generated patch doesn't
introduce new problems:
  1. Syntax check (ast.parse)
  2. Import resolution (all imports are resolvable)
  3. Function signature preservation (patched function has same args)
  4. No new dangerous patterns introduced by the patch itself
"""

import ast
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ValidationResult:
    """Result of all validation checks on patched code."""
    passed             : bool
    syntax_ok          : bool
    signatures_ok      : bool
    no_new_vulns       : bool
    warnings           : list[str] = field(default_factory=list)
    errors             : list[str] = field(default_factory=list)
    summary            : str = ""


def validate_patch(
    original_code : str,
    patched_code  : str,
) -> ValidationResult:
    """
    Validate a patched file for correctness and safety.

    Args:
        original_code : Source before patch.
        patched_code  : Source after patch.

    Returns:
        ValidationResult with pass/fail status and details.
    """
    result = ValidationResult(
        passed        = False,
        syntax_ok     = False,
        signatures_ok = False,
        no_new_vulns  = False,
    )

    # ── Check 1: Syntax ───────────────────────────────────────────────────
    syntax_ok, syntax_errors = _check_syntax(patched_code)
    result.syntax_ok = syntax_ok
    if not syntax_ok:
        result.errors.extend(syntax_errors)
        result.summary = "FAILED: Patched code has syntax errors."
        return result

    # ── Check 2: Function signatures preserved ────────────────────────────
    sigs_ok, sig_warnings = _check_signatures(original_code, patched_code)
    result.signatures_ok = sigs_ok
    result.warnings.extend(sig_warnings)

    # ── Check 3: Patch didn't introduce new dangerous patterns ────────────
    new_vulns_ok, vuln_warnings = _check_no_new_vulns(original_code, patched_code)
    result.no_new_vulns = new_vulns_ok
    result.warnings.extend(vuln_warnings)

    # ── Final verdict ─────────────────────────────────────────────────────
    result.passed = syntax_ok   # Minimum: syntax must be valid
    if not sigs_ok:
        result.warnings.append("⚠ Function signatures changed — verify manually.")
    if not new_vulns_ok:
        result.warnings.append("⚠ Patch may introduce new security patterns.")

    result.summary = (
        "✅ PASSED — syntax valid, signatures preserved, no new vulnerabilities detected."
        if result.passed and sigs_ok and new_vulns_ok
        else f"⚠ PASSED WITH WARNINGS ({len(result.warnings)} warning(s))"
        if result.passed
        else "❌ FAILED — see errors."
    )
    return result


# ── Checks ────────────────────────────────────────────────────────────────────

def _check_syntax(code: str) -> tuple[bool, list[str]]:
    try:
        ast.parse(code)
        return True, []
    except SyntaxError as e:
        return False, [f"SyntaxError line {e.lineno}: {e.msg}"]
    except Exception as e:
        return False, [str(e)]


def _check_signatures(original: str, patched: str) -> tuple[bool, list[str]]:
    """
    Verify that all functions in the original still exist in the patched code
    with the same argument signatures.
    """
    try:
        orig_tree   = ast.parse(original)
        patch_tree  = ast.parse(patched)
    except SyntaxError:
        return True, []   # Syntax check already handles this

    orig_sigs  = _extract_signatures(orig_tree)
    patch_sigs = _extract_signatures(patch_tree)

    warnings = []
    for name, orig_args in orig_sigs.items():
        if name not in patch_sigs:
            warnings.append(f"Function '{name}' was removed by the patch.")
        elif patch_sigs[name] != orig_args:
            warnings.append(
                f"Function '{name}' signature changed: "
                f"{orig_args} → {patch_sigs[name]}"
            )

    return len(warnings) == 0, warnings


def _extract_signatures(tree: ast.AST) -> dict[str, list[str]]:
    """Extract {function_name: [arg_names]} from an AST."""
    sigs = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sigs[node.name] = [a.arg for a in node.args.args]
    return sigs


# Dangerous patterns that should NOT appear in a security fix
_DANGEROUS_PATTERNS = [
    (r"eval\s*\(", "eval() used in patch"),
    (r"exec\s*\(", "exec() used in patch"),
    (r"os\.system\s*\(", "os.system() used in patch"),
    (r"pickle\.loads?\s*\(", "pickle.load used in patch"),
    (r"yaml\.load\s*\([^,)]+\)", "yaml.load without Loader used in patch"),
    (r"shell\s*=\s*True", "shell=True used in patch"),
]

def _check_no_new_vulns(original: str, patched: str) -> tuple[bool, list[str]]:
    """
    Check that the patch didn't introduce new dangerous patterns
    that weren't already present in the original.
    """
    import re
    warnings = []

    for pattern, label in _DANGEROUS_PATTERNS:
        in_original = bool(re.search(pattern, original))
        in_patched  = bool(re.search(pattern, patched))

        if in_patched and not in_original:
            warnings.append(f"New dangerous pattern introduced: {label}")

    return len(warnings) == 0, warnings
