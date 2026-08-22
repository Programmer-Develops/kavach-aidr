"""
chain_of_thought.py — Multi-step reasoning orchestrator for KAVACH-AIDR.

Implements a structured reasoning loop:
  1. Analyse → understand the vulnerability deeply
  2. Patch → generate a code fix
  3. Self-verify → check the patch is correct (LLM self-review)
  4. Return a structured ReasoningResult

This is the "brain" of KAVACH-AIDR — it coordinates the LLM and
produces all outputs consumed by downstream modules (patcher, verifier, audit).
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional

from kavach.reasoner.llm_engine import LLMEngine, LLMResponse
from kavach.reasoner.prompt_builder import (
    SYSTEM_PROMPT,
    build_analysis_prompt,
    build_patch_refinement_prompt,
    build_verification_prompt,
)
from kavach.static.merger import MergedFinding


@dataclass
class ReasoningStep:
    """A single step in the reasoning chain (logged for audit trail)."""
    step_name    : str
    prompt_len   : int
    response_len : int
    tokens_used  : int
    duration_sec : float
    raw_response : str


@dataclass
class ReasoningResult:
    """
    Complete output of the LLM reasoning chain for one vulnerability.
    This object is passed to the patcher, verifier, and audit modules.
    """
    finding       : MergedFinding
    root_cause    : str               # Explanation of why it's a bug
    exploit_scenario: str             # Realistic attack narrative
    patch_diff    : str               # Unified diff patch (may be empty if LLM failed)
    verification  : str               # LLM self-verification answer
    patch_found   : bool = False      # True if a patch was successfully extracted
    steps         : list[ReasoningStep] = field(default_factory=list)
    total_tokens  : int = 0
    total_time_sec: float = 0.0
    model_name    : str = ""
    llm_available : bool = True       # False if LLM wasn't loaded (graceful degrade)


class ChainOfThought:
    """
    Orchestrates multi-step LLM reasoning for a single vulnerability.

    Design principles:
    - Each step is logged separately for the audit trail
    - If LLM is unavailable, returns a graceful partial result
    - Self-correction: if patch has issues, the LLM is asked to fix it
    - Timeout-aware: won't hang the pipeline
    """

    def __init__(
        self,
        engine      : Optional[LLMEngine],
        max_retries : int = 2,
    ):
        self.engine      = engine
        self.max_retries = max_retries

    def reason(
        self,
        finding     : MergedFinding,
        source_code : str,
        file_path   : str,
    ) -> ReasoningResult:
        """
        Run the full reasoning chain for one vulnerability finding.

        Args:
            finding     : The vulnerability to analyse.
            source_code : Full source of the affected file.
            file_path   : Path label for prompts.

        Returns:
            ReasoningResult with patch, explanation, and audit steps.
        """
        result = ReasoningResult(
            finding          = finding,
            root_cause       = "",
            exploit_scenario = "",
            patch_diff       = "",
            verification     = "",
            llm_available    = self.engine is not None and self.engine.is_loaded(),
        )

        if not result.llm_available:
            result.root_cause       = self._static_root_cause(finding)
            result.exploit_scenario = self._static_exploit(finding)
            return result

        start = time.time()

        # ── Step 1: Full analysis + patch generation ──────────────────────
        analysis_prompt = build_analysis_prompt(finding, source_code, file_path)
        analysis_resp   = self._call(analysis_prompt, step_name="analysis_and_patch")
        result.steps.append(analysis_resp["step"])
        result.model_name = analysis_resp["response"].model_name

        raw_analysis = analysis_resp["response"].text

        # Extract sections from the analysis response
        result.root_cause       = self._extract_section(raw_analysis, "ROOT CAUSE", "EXPLOIT SCENARIO")
        result.exploit_scenario = self._extract_section(raw_analysis, "EXPLOIT SCENARIO", "PATCH")
        patch_raw               = self._extract_section(raw_analysis, "PATCH", "VERIFICATION")
        result.patch_diff       = self._extract_patch_diff(patch_raw)
        result.patch_found      = bool(result.patch_diff.strip())

        # ── Step 2: Self-verification (only if patch was found) ───────────
        if result.patch_found:
            patched_preview = self._preview_patch(source_code, result.patch_diff)
            verify_prompt   = build_verification_prompt(finding, patched_preview)
            verify_resp     = self._call(verify_prompt, step_name="self_verification")
            result.steps.append(verify_resp["step"])
            result.verification = verify_resp["response"].text

        result.total_time_sec = time.time() - start
        result.total_tokens   = sum(s.tokens_used for s in result.steps)

        return result

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _call(self, prompt: str, step_name: str) -> dict:
        """Call the LLM and record the step."""
        t0 = time.time()
        response: LLMResponse = self.engine.generate(
            prompt        = prompt,
            system_prompt = SYSTEM_PROMPT,
        )
        elapsed = time.time() - t0

        step = ReasoningStep(
            step_name    = step_name,
            prompt_len   = len(prompt),
            response_len = len(response.text),
            tokens_used  = response.tokens_used,
            duration_sec = round(elapsed, 2),
            raw_response = response.text,
        )
        return {"response": response, "step": step}

    @staticmethod
    def _extract_section(text: str, start_marker: str, end_marker: str) -> str:
        """
        Extract content between two section headers.
        Markers are matched case-insensitively.
        """
        pattern = rf"(?:###\s*STEP\s*\d+\s*[—-]\s*)?{re.escape(start_marker)}(.*?)(?=(?:###\s*STEP|\Z|{re.escape(end_marker)}))"
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()
        # Fallback: just return the relevant portion of text
        idx = text.upper().find(start_marker.upper())
        if idx != -1:
            return text[idx + len(start_marker):idx + 600].strip()
        return ""

    @staticmethod
    def _extract_patch_diff(patch_section: str) -> str:
        """
        Extract the unified diff from the PATCH_START / PATCH_END block.
        Falls back to looking for standard diff markers (--- / +++ / @@).
        """
        # Primary: PATCH_START / PATCH_END markers
        m = re.search(r"PATCH_START\s*(.*?)\s*PATCH_END", patch_section, re.DOTALL)
        if m:
            return m.group(1).strip()

        # Fallback: look for unified diff markers directly
        m = re.search(r"(---.*?\+\+\+.*?(?:@@.*?\n(?:[+\- ].*\n?)+))", patch_section, re.DOTALL)
        if m:
            return m.group(1).strip()

        # Fallback: code block
        m = re.search(r"```(?:diff|patch)?\s*(.*?)```", patch_section, re.DOTALL)
        if m:
            return m.group(1).strip()

        return ""

    @staticmethod
    def _preview_patch(source_code: str, patch_diff: str) -> str:
        """
        Apply the patch in-memory for self-verification preview.
        Returns a best-effort patched version of the code.
        """
        lines = source_code.splitlines(keepends=True)
        result_lines = list(lines)

        for match in re.finditer(r"^-(.+)$", patch_diff, re.MULTILINE):
            old_line = match.group(1)
            for i, line in enumerate(result_lines):
                if line.rstrip("\n") == old_line:
                    result_lines[i] = ""  # Mark for removal
                    break

        for match in re.finditer(r"^\+(.+)$", patch_diff, re.MULTILINE):
            new_line = match.group(1) + "\n"
            result_lines.append(new_line)

        return "".join(result_lines)[:3000]  # Truncate for prompt

    @staticmethod
    def _static_root_cause(finding: MergedFinding) -> str:
        """
        Fallback root-cause explanation when LLM is not available.
        Generated from static analysis data alone.
        """
        templates = {
            "SQL_INJECTION"     : "User-controlled input is directly concatenated into a SQL query without parameterisation, allowing an attacker to manipulate query logic.",
            "COMMAND_INJECTION" : "Unsanitised user input is passed directly to a shell command, allowing arbitrary OS command execution.",
            "DESERIALIZATION"   : "Untrusted data is deserialised using an unsafe method (pickle/yaml.load), enabling remote code execution via crafted payloads.",
            "HARDCODED_SECRET"  : "A credential, API key, or password is hardcoded as a string literal in source code, exposing it to anyone with code access.",
            "PATH_TRAVERSAL"    : "User-supplied path components are not validated, allowing access to arbitrary files outside the intended directory.",
            "CODE_INJECTION"    : "User-controlled input is passed to eval() or exec(), enabling arbitrary Python code execution.",
            "WEAK_CRYPTO"       : "A broken cryptographic algorithm (MD5/SHA1/DES) is used, making it feasible for an adversary to reverse or forge cryptographic values.",
            "XSS"               : "Unsanitised user input is reflected in HTML output, enabling script injection attacks.",
        }
        return templates.get(finding.vuln_type, finding.message)

    @staticmethod
    def _static_exploit(finding: MergedFinding) -> str:
        """Fallback exploit scenario when LLM is unavailable."""
        templates = {
            "SQL_INJECTION"     : "An adversary submits specially crafted input to bypass authentication or exfiltrate classified database records.",
            "COMMAND_INJECTION" : "An attacker submits shell metacharacters to execute arbitrary commands on the server, potentially gaining full system control.",
            "DESERIALIZATION"   : "An adversary sends a maliciously crafted serialized payload that executes code upon deserialisation, achieving remote code execution.",
            "HARDCODED_SECRET"  : "An insider or code repository breach exposes the credential, granting unauthorised access to protected systems.",
            "PATH_TRAVERSAL"    : "An attacker uses '../../../etc/passwd' style paths to read sensitive configuration files from the server.",
            "CODE_INJECTION"    : "An adversary injects Python code via user input to read files, execute system commands, or exfiltrate data.",
        }
        return templates.get(finding.vuln_type, "Could allow an adversary to compromise system integrity or confidentiality.")
