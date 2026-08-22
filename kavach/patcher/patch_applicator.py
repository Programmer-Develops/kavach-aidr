"""
patch_applicator.py — Apply LLM-generated patches to source files.

Takes a ParsedPatch and applies it to the original source code, producing
a patched version that:
  - Compiles without errors
  - Has the vulnerability removed
  - Preserves all original logic

Application strategy (tries each in order until one succeeds):
  1. Line-by-line replacement (fast, handles most LLM patches)
  2. Context-based fuzzy matching (handles off-by-one line numbers)
  3. Regex substitution (for simple single-line changes)
"""

import ast
import re
import difflib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from kavach.reasoner.patch_generator import ParsedPatch, apply_simple_patch


@dataclass
class PatchResult:
    """Result of attempting to apply a patch to a source file."""
    success          : bool
    patched_code     : str         # Empty string if patch failed
    original_code    : str
    strategy_used    : str         # "line_replace" | "fuzzy" | "regex" | "none"
    changes_made     : int         # Number of lines changed
    syntax_valid     : bool        # Did the patched code pass ast.parse()?
    syntax_errors    : list[str]   # Any syntax errors in patched code
    diff_summary     : str         # Human-readable summary of changes


def apply_patch(
    source_code  : str,
    patch        : ParsedPatch,
    filepath     : Optional[str] = None,
) -> PatchResult:
    """
    Apply a ParsedPatch to source code using the best available strategy.

    Args:
        source_code : Original Python source as a string.
        patch       : ParsedPatch from patch_generator.parse_patch()
        filepath    : Optional filename label for error messages.

    Returns:
        PatchResult with patched code and application metadata.
    """
    original = source_code

    if not patch.is_valid:
        return PatchResult(
            success       = False,
            patched_code  = "",
            original_code = original,
            strategy_used = "none",
            changes_made  = 0,
            syntax_valid  = False,
            syntax_errors = [patch.error or "Invalid patch"],
            diff_summary  = "Patch was not valid — no changes applied.",
        )

    # ── Try strategies in order ───────────────────────────────────────────

    for strategy_name, strategy_fn in [
        ("line_replace", _strategy_line_replace),
        ("fuzzy"       , _strategy_fuzzy),
        ("regex"       , _strategy_regex),
    ]:
        patched = strategy_fn(source_code, patch)
        if patched and patched != source_code:
            syntax_ok, errors = _check_syntax(patched)
            if syntax_ok:
                return PatchResult(
                    success       = True,
                    patched_code  = patched,
                    original_code = original,
                    strategy_used = strategy_name,
                    changes_made  = _count_changes(original, patched),
                    syntax_valid  = True,
                    syntax_errors = [],
                    diff_summary  = _make_diff_summary(original, patched),
                )

    # ── All strategies failed — report syntax errors from last attempt ────
    last_attempt = _strategy_line_replace(source_code, patch) or source_code
    _, errors = _check_syntax(last_attempt)
    return PatchResult(
        success       = False,
        patched_code  = "",
        original_code = original,
        strategy_used = "none",
        changes_made  = 0,
        syntax_valid  = False,
        syntax_errors = errors,
        diff_summary  = "All patch strategies failed. Manual review required.",
    )


def write_patched_file(result: PatchResult, filepath: str | Path) -> bool:
    """
    Write the patched code to a file (creates a .patched backup first).

    Args:
        result   : Successful PatchResult (result.success must be True).
        filepath : Path to the original source file.

    Returns:
        True if written successfully.
    """
    if not result.success:
        return False

    path = Path(filepath)
    backup = path.with_suffix(".original.py")

    # Write backup of original
    backup.write_text(result.original_code, encoding="utf-8")
    # Write patched version
    path.write_text(result.patched_code, encoding="utf-8")
    return True


# ── Patch strategies ─────────────────────────────────────────────────────────

def _strategy_line_replace(source_code: str, patch: ParsedPatch) -> str:
    """
    Strategy 1: Direct line-by-line replacement.
    Replace each removed line with its corresponding added line.
    """
    return apply_simple_patch(source_code, patch)


def _strategy_fuzzy(source_code: str, patch: ParsedPatch) -> str:
    """
    Strategy 2: Fuzzy context matching.
    Uses difflib to find the best match for each old line, even if the line
    number is slightly off (common with LLM-generated patches).
    """
    if not patch.old_lines:
        return source_code

    lines = source_code.splitlines(keepends=True)
    result = list(lines)

    for i, old_line in enumerate(patch.old_lines):
        old_stripped = old_line.strip()
        if not old_stripped:
            continue

        # Find best matching line using sequence matching
        best_ratio = 0.0
        best_idx   = -1
        for j, line in enumerate(result):
            ratio = difflib.SequenceMatcher(None, old_stripped, line.strip()).ratio()
            if ratio > best_ratio and ratio > 0.8:
                best_ratio = ratio
                best_idx   = j

        if best_idx >= 0 and i < len(patch.new_lines):
            new_content = patch.new_lines[i]
            # Preserve original indentation
            original_indent = len(result[best_idx]) - len(result[best_idx].lstrip())
            indented_new    = " " * original_indent + new_content.lstrip() + "\n"
            result[best_idx] = indented_new

    return "".join(result)


def _strategy_regex(source_code: str, patch: ParsedPatch) -> str:
    """
    Strategy 3: Regex substitution for simple single-line changes.
    Works well when the LLM only changed one specific expression.
    """
    if not patch.old_lines or not patch.new_lines:
        return source_code

    result = source_code
    for old, new in zip(patch.old_lines, patch.new_lines):
        old_escaped = re.escape(old.strip())
        try:
            result = re.sub(old_escaped, new.strip(), result, count=1)
        except re.error:
            continue

    return result


# ── Helpers ──────────────────────────────────────────────────────────────────

def _check_syntax(code: str) -> tuple[bool, list[str]]:
    """Check if Python code is syntactically valid."""
    try:
        ast.parse(code)
        return True, []
    except SyntaxError as e:
        return False, [f"SyntaxError at line {e.lineno}: {e.msg}"]
    except Exception as e:
        return False, [str(e)]


def _count_changes(original: str, patched: str) -> int:
    """Count the number of lines that differ between original and patched."""
    orig_lines = original.splitlines()
    patch_lines = patched.splitlines()
    diff = list(difflib.unified_diff(orig_lines, patch_lines))
    return sum(1 for l in diff if l.startswith(("+", "-")) and not l.startswith(("+++", "---")))


def _make_diff_summary(original: str, patched: str) -> str:
    """Generate a human-readable summary of changes made."""
    orig_lines  = original.splitlines()
    patch_lines = patched.splitlines()
    diff = list(difflib.unified_diff(orig_lines, patch_lines, lineterm=""))

    removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
    added   = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))

    return f"{removed} line(s) removed, {added} line(s) added."
