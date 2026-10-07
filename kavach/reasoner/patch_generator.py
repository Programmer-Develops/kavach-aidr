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
    Apply a patch to source code using block matching and line replacement.
    Handles unequal counts of old and new lines (e.g., multi-line removals).
    """
    if not patch.is_valid:
        return source_code

    if not patch.old_lines and not patch.new_lines:
        return source_code

    lines = source_code.splitlines(keepends=True)

    # Strategy 1: Contiguous block match (stripped)
    if patch.old_lines:
        n_old = len(patch.old_lines)
        old_stripped = [l.strip() for l in patch.old_lines]
        for i in range(len(lines) - n_old + 1):
            if all(lines[i + j].strip() == old_stripped[j] for j in range(n_old)):
                orig_indent = len(lines[i]) - len(lines[i].lstrip())
                formatted_new = []
                for nl in patch.new_lines:
                    if nl and not nl.endswith("\n"):
                        nl = nl + "\n"
                    if nl and len(nl) - len(nl.lstrip()) == 0:
                        nl = " " * orig_indent + nl
                    formatted_new.append(nl)
                return "".join(lines[:i] + formatted_new + lines[i + n_old:])

    # Strategy 2: Line-by-line matching with proper handling of unequal counts
    result = list(lines)
    matched_indices = []
    for old in patch.old_lines:
        target = old.strip()
        if not target:
            continue
        for idx, line in enumerate(result):
            if idx not in matched_indices and line.strip() == target:
                matched_indices.append(idx)
                break

    if matched_indices:
        matched_indices.sort()
        formatted_new = []
        for nl in patch.new_lines:
            if nl and not nl.endswith("\n"):
                nl = nl + "\n"
            formatted_new.append(nl)

        if len(patch.new_lines) <= len(matched_indices):
            for k, idx in enumerate(matched_indices):
                if k < len(formatted_new):
                    result[idx] = formatted_new[k]
                else:
                    result[idx] = ""  # Delete excess old lines
        else:
            for k in range(len(matched_indices) - 1):
                result[matched_indices[k]] = formatted_new[k]
            last_idx = matched_indices[-1]
            result[last_idx] = "".join(formatted_new[len(matched_indices) - 1:])

        return "".join(result)

    return source_code


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
