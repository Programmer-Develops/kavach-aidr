"""
prompt_builder.py — Build structured prompts for the KAVACH-AIDR LLM reasoner.

Each vulnerability gets a carefully crafted, structured prompt that guides
the LLM to produce:
  1. A root-cause explanation
  2. An actual code patch (unified diff format)
  3. A real-world exploit scenario (for Army risk assessment)
  4. Remediation recommendations

Prompts are short and focused — keeps inference fast on Phi-3-mini.
"""

from kavach.static.merger import MergedFinding


# ── System prompt (sent once as the "system" role) ──────────────────────────

SYSTEM_PROMPT = """You are KAVACH-AIDR, an autonomous cyber-security reasoning engine deployed for the Indian Armed Forces.

Your job is to:
1. Analyse security vulnerabilities in software systems
2. Generate precise, minimal code patches that fix the vulnerability
3. Verify that the patch does not break functionality
4. Explain the risk in terms of operational impact

Rules:
- Be concise and precise. No filler text.
- Always output patches as unified diffs (--- original / +++ patched format)
- Mark every patch section clearly with PATCH_START and PATCH_END markers
- Never suggest cloud-based or subscription tools
- Think step by step before writing the patch
"""


# ── Prompt templates ─────────────────────────────────────────────────────────

def build_analysis_prompt(
    finding     : MergedFinding,
    source_code : str,
    file_path   : str,
) -> str:
    """
    Build a prompt asking the LLM to analyse a vulnerability and generate a patch.

    Args:
        finding     : The merged vulnerability finding.
        source_code : Full source code of the affected file.
        file_path   : Path to the file (for context).

    Returns:
        Formatted prompt string ready for LLM inference.
    """
    # Truncate source code to avoid exceeding context window
    # Focus on the area around the vulnerability
    focused_code = _focus_code(source_code, finding.lineno, window=30)

    cwe_str = ", ".join(finding.cwe) if finding.cwe else "Unknown"
    sources_str = " + ".join(finding.sources)

    prompt = f"""## VULNERABILITY ANALYSIS REQUEST

**File**: `{file_path}`
**Line**: {finding.lineno}
**Severity**: {finding.severity}
**Type**: {finding.vuln_type}
**CWE**: {cwe_str}
**Detected by**: {sources_str}
**Corroborated**: {"YES — multiple tools agree" if finding.corroborated else "Single tool"}

**Finding Message**:
{finding.message}

**Vulnerable Code** (lines around {finding.lineno}):
```python
{focused_code}
```

---

## YOUR TASK

Perform the following analysis steps:

### STEP 1 — ROOT CAUSE
Explain in 2-3 sentences: what exactly is the vulnerability, why is it dangerous, and how could an attacker exploit it?

### STEP 2 — EXPLOIT SCENARIO
In 1-2 sentences: describe a realistic attack scenario relevant to a military/defence software system.

### STEP 3 — PATCH
Write the minimal code fix. Use ONLY the following format:

PATCH_START
--- original
+++ patched
@@ -line,count +line,count @@
 [unchanged context line]
-[removed line]
+[added line]
 [unchanged context line]
PATCH_END

The patch must:
- Fix ONLY the vulnerability (no refactoring)
- Preserve all existing functionality
- Be as minimal as possible

### STEP 4 — VERIFICATION
In 1 sentence: how can we confirm the fix works?

---

Begin your analysis:
"""
    return prompt


def build_patch_refinement_prompt(
    original_patch  : str,
    syntax_errors   : list[str],
    source_code     : str,
) -> str:
    """
    Build a prompt to ask the LLM to fix a broken patch.
    Called when the patch produced by the first round has syntax errors.
    """
    return f"""## PATCH REFINEMENT REQUEST

The following patch produced syntax errors when applied. Please fix it.

**Syntax errors**:
{chr(10).join(f"- {e}" for e in syntax_errors)}

**Original patch**:
```
{original_patch}
```

**Source file context**:
```python
{source_code[:2000]}
```

Output ONLY the corrected patch in this format:
PATCH_START
--- original
+++ patched
@@ ... @@
[patch content]
PATCH_END
"""


def build_verification_prompt(
    finding      : MergedFinding,
    patched_code : str,
) -> str:
    """
    Build a prompt to verify that a patch actually fixes the vulnerability.
    The LLM checks its own output for correctness.
    """
    return f"""## PATCH VERIFICATION

The following code has been patched to fix a {finding.vuln_type} vulnerability.

**Patched code**:
```python
{patched_code[:2000]}
```

Answer ONLY:
1. Is the {finding.vuln_type} vulnerability fixed? (YES/NO)
2. Could the fix introduce new vulnerabilities? (YES/NO, explain briefly)
3. Is the fix complete or partial? (COMPLETE/PARTIAL)

Be direct. No explanations beyond what is asked.
"""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _focus_code(source: str, lineno: int, window: int = 30) -> str:
    """
    Extract a focused window of lines around the vulnerability location.
    Keeps the prompt small to fit within Phi-3-mini's 4096-token context.
    """
    lines = source.splitlines()
    start = max(0, lineno - 1 - window)
    end   = min(len(lines), lineno + window)
    focused = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == lineno else "   "
        focused.append(f"{marker}{i:4d}: {line}")
    return "\n".join(focused)
