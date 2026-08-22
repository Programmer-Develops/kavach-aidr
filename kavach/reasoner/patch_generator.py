"""
patch_generator.py — Parse LLM output and produce an applicable code patch.

Takes the raw LLM response text, extracts the patch diff, and produces
a clean unified diff that can be applied to the source file by patch_applicator.

Handles messy LLM output: the model sometimes wraps code in markdown,
uses inconsistent formatting, or produces non-standard diffs. This module
normalises all of those cases.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedPatch:
    """A parsed, normalised code patch ready for application."""
    raw_diff    : str           # Original diff text from LLM
    clean_diff  : str           # Normalised unified diff
    old_lines   : list[str]     # Lines being removed
    new_lines   : list[str]     # Lines being added
    hunks       : int           # Number of @@ ... @@ blocks
    is_valid    : bool
    error       : Optional[str] = None


def parse_patch(raw_llm_output: str) -> ParsedPatch:
    """
    Parse raw LLM output and extract a clean, applicable patch.

    Args:
        raw_llm_output: The full text response from the LLM.

    Returns:
        ParsedPatch with clean_diff ready for patch_applicator.
    """
    # ── Step 1: Extract the diff block ───────────────────────────────────
    diff_text = _extract_diff_block(raw_llm_output)

    if not diff_text:
        return ParsedPatch(
            raw_diff   = raw_llm_output,
            clean_diff = "",
            old_lines  = [],
            new_lines  = [],
            hunks      = 0,
            is_valid   = False,
            error      = "No patch diff found in LLM output",
        )

    # ── Step 2: Normalise the diff ────────────────────────────────────────
    clean = _normalise_diff(diff_text)

    # ── Step 3: Extract individual lines ─────────────────────────────────
    old_lines = [l[1:] for l in clean.splitlines() if l.startswith("-") and not l.startswith("---")]
    new_lines = [l[1:] for l in clean.splitlines() if l.startswith("+") and not l.startswith("+++")]
    hunks     = len(re.findall(r"^@@", clean, re.MULTILINE))

    # ── Step 4: Basic validity check ──────────────────────────────────────
    is_valid = bool(old_lines or new_lines) and (hunks > 0 or bool(old_lines))
    error    = None if is_valid else "Patch has no meaningful changes"

    return ParsedPatch(
        raw_diff   = diff_text,
        clean_diff = clean,
        old_lines  = old_lines,
        new_lines  = new_lines,
        hunks      = hunks,
        is_valid   = is_valid,
        error      = error,
    )


def apply_simple_patch(source_code: str, patch: ParsedPatch) -> str:
    """
    Apply a simple line-replacement patch to source code.

    This is a lightweight applier for cases where the standard `patch`
    command is not available. Replaces old lines with new lines sequentially.

    For robust unified diff application, use patcher.patch_applicator instead.

    Args:
        source_code : Original source code string.
        patch       : ParsedPatch from parse_patch().

    Returns:
        Patched source code string.
    """
    if not patch.is_valid:
        return source_code

    lines = source_code.splitlines(keepends=True)
    result = list(lines)

    # Create a mapping: old_line_content → new_line_content
    replacements = {}
    for old, new in zip(patch.old_lines, patch.new_lines):
        replacements[old.rstrip("\n")] = new

    for i, line in enumerate(result):
        stripped = line.rstrip("\n")
        if stripped in replacements:
            # Preserve original indentation if the new line has none
            new_content = replacements[stripped]
            if new_content.strip():
                result[i] = new_content + "\n"
            del replacements[stripped]   # Apply each replacement once

    return "".join(result)


# ── Internal helpers ─────────────────────────────────────────────────────────

def _extract_diff_block(text: str) -> str:
    """Try multiple strategies to extract a diff block from LLM output."""

    # Strategy 1: PATCH_START / PATCH_END markers (our structured format)
    m = re.search(r"PATCH_START\s*(.*?)\s*PATCH_END", text, re.DOTALL)
    if m:
        return m.group(1).strip()

    # Strategy 2: Fenced diff code block (```diff ... ```)
    m = re.search(r"```(?:diff|patch)\s*\n(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()

    # Strategy 3: Any fenced code block that contains diff markers
    m = re.search(r"```\s*\n((?:[\+\-@ ].*\n)+)```", text, re.DOTALL)
    if m:
        block = m.group(1)
        if any(line.startswith(("+", "-", "@")) for line in block.splitlines()):
            return block.strip()

    # Strategy 4: Raw unified diff markers in the text
    m = re.search(
        r"(---\s+\S+.*?\n\+\+\+\s+\S+.*?\n(?:@@.*?\n(?:[+\- ].*\n?)+)+)",
        text, re.DOTALL
    )
    if m:
        return m.group(1).strip()

    # Strategy 5: Just lines starting with + or - (simplest fallback)
    diff_lines = []
    for line in text.splitlines():
        if line.startswith(("+", "-", " ", "@")):
            diff_lines.append(line)
    if diff_lines:
        return "\n".join(diff_lines)

    return ""


def _normalise_diff(diff_text: str) -> str:
    """
    Normalise diff text into standard unified diff format.
    Handles LLM quirks like extra spaces, wrong header formats, etc.
    """
    lines = diff_text.splitlines()
    normalised = []

    for line in lines:
        # Strip trailing whitespace but preserve leading (important for diffs)
        line = line.rstrip()

        # Skip blank lines that aren't meaningful in a diff context
        if not line and not normalised:
            continue

        normalised.append(line)

    return "\n".join(normalised)
