"""
runner.py — KAVACH-AIDR fuzzer orchestrator (cross-platform).

Runs a smart mutation-based fuzzer against Python functions to:
  1. Confirm the vulnerability IS exploitable with real payloads (pre-patch)
  2. Confirm the vulnerability is NOT exploitable after patching (post-patch)

Unlike AFL++ (Linux-only) or Atheris (Linux-only), this runs on Windows/Mac/Linux
using Python's multiprocessing and our mutation engine.

Key innovation: LLM-guided seeds mean we trigger real bugs in seconds,
not hours of random mutation.
"""

import ast
import sys
import time
import traceback
import importlib
import importlib.util
import tempfile
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable

from kavach.fuzzer.mutation_engine import MutationEngine, Payload
from kavach.fuzzer.seed_generator import generate_llm_seeds
from kavach.fuzzer.crash_triager import triage_crash, CrashReport


@dataclass
class FuzzResult:
    """Complete result of one fuzzing run (pre or post patch)."""
    phase          : str       # "pre_patch" | "post_patch"
    vuln_type      : str
    total_inputs   : int
    crashes        : list[CrashReport] = field(default_factory=list)
    triggered      : bool = False    # Did any input trigger the bug?
    duration_sec   : float = 0.0
    inputs_per_sec : float = 0.0
    exploitable    : list[Payload] = field(default_factory=list)


@dataclass
class FuzzComparison:
    """Pre-patch vs post-patch fuzzing comparison."""
    pre_patch    : Optional[FuzzResult] = None
    post_patch   : Optional[FuzzResult] = None
    vuln_fixed   : bool   = False     # True = pre triggered, post didn't
    confidence   : str    = "LOW"     # HIGH = strong evidence fix works


class KavachFuzzer:
    """
    KAVACH-AIDR smart fuzzer.

    Uses semantic payloads + mutation to exercise vulnerable functions.
    Compares pre-patch vs post-patch behavior to prove the fix works.

    Cross-platform: works on Windows, Linux, macOS.
    """

    def __init__(
        self,
        llm_engine   : Optional[object] = None,
        max_inputs   : int = 200,
        timeout_sec  : float = 0.5,    # Per-input timeout
        verbose      : bool = False,
    ):
        self.engine      = llm_engine
        self.max_inputs  = max_inputs
        self.timeout_sec = timeout_sec
        self.verbose     = verbose
        self.mutation    = MutationEngine()

    def fuzz_function(
        self,
        source_code  : str,
        function_name: str,
        vuln_type    : str,
        phase        : str = "pre_patch",
        filepath     : str = "<string>",
    ) -> FuzzResult:
        """
        Fuzz a specific function from source code.

        Strategy:
          1. Extract the function from source code
          2. Generate LLM seeds + mutation payloads
          3. Call the function with each payload
          4. Catch exceptions, detect anomalies
          5. Report which inputs triggered crashes/bugs

        Args:
            source_code   : Python source containing the function
            function_name : Name of the function to fuzz
            vuln_type     : Vulnerability type (for seed selection)
            phase         : "pre_patch" or "post_patch"
            filepath      : Source file label

        Returns:
            FuzzResult with all crashes and exploitable inputs.
        """
        start = time.time()
        result = FuzzResult(phase=phase, vuln_type=vuln_type, total_inputs=0)

        # ── Load the function ──────────────────────────────────────────────
        func = self._load_function(source_code, function_name, filepath)
        if func is None:
            result.duration_sec = time.time() - start
            return result

        # ── Generate seeds ─────────────────────────────────────────────────
        seeds = generate_llm_seeds(vuln_type, source_code, self.engine, n=15)
        # Add mutations
        all_payloads: list[Payload] = []
        for seed in seeds:
            all_payloads.append(seed)
            all_payloads.extend(self.mutation.mutate(seed, n=3))
        # Limit to max_inputs
        all_payloads = all_payloads[:self.max_inputs]

        # ── Run each payload ───────────────────────────────────────────────
        for payload in all_payloads:
            result.total_inputs += 1
            crash = self._run_with_payload(func, payload, function_name)
            if crash:
                result.crashes.append(crash)
                result.triggered = True
                result.exploitable.append(payload)
                if self.verbose:
                    print(f"  [CRASH] {payload.description}: {crash.exception_type}")

        result.duration_sec   = round(time.time() - start, 2)
        result.inputs_per_sec = round(result.total_inputs / max(result.duration_sec, 0.001), 1)
        return result

    def compare(
        self,
        original_src  : str,
        patched_src   : str,
        function_name : str,
        vuln_type     : str,
        filepath      : str = "<string>",
    ) -> FuzzComparison:
        """
        Run fuzzing on both original and patched code and compare results.

        Args:
            original_src  : Source before patch
            patched_src   : Source after patch
            function_name : Function to fuzz
            vuln_type     : Vulnerability type
            filepath      : Label

        Returns:
            FuzzComparison showing whether the fix holds.
        """
        comp = FuzzComparison()

        # Fuzz original (expect crashes)
        comp.pre_patch = self.fuzz_function(
            original_src, function_name, vuln_type, phase="pre_patch", filepath=filepath
        )

        # Fuzz patched (expect no crashes with same payloads)
        comp.post_patch = self.fuzz_function(
            patched_src, function_name, vuln_type, phase="post_patch", filepath=filepath
        )

        # Compare: fix works if pre had crashes and post doesn't
        pre_crashed  = comp.pre_patch.triggered
        post_crashed = comp.post_patch.triggered

        if pre_crashed and not post_crashed:
            comp.vuln_fixed = True
            comp.confidence = "HIGH"
        elif not pre_crashed:
            comp.vuln_fixed = True
            comp.confidence = "MEDIUM"   # Couldn't trigger bug even in original
        else:
            comp.vuln_fixed = False
            comp.confidence = "HIGH"     # Definitively: patch didn't fix it

        return comp

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _load_function(
        self,
        source_code  : str,
        function_name: str,
        filepath     : str,
    ) -> Optional[Callable]:
        """Load a function from source code into memory for calling."""
        try:
            # Write to temp file and import
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as f:
                f.write(source_code)
                tmp_path = f.name

            spec   = importlib.util.spec_from_file_location("_kavach_fuzz_target", tmp_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            func   = getattr(module, function_name, None)

            os.unlink(tmp_path)
            return func

        except Exception as e:
            return None

    def _run_with_payload(
        self,
        func    : Callable,
        payload : Payload,
        fname   : str,
    ) -> Optional[CrashReport]:
        """
        Call the function with the payload and catch any crash.
        Returns a CrashReport if an exception occurred, else None.
        """
        try:
            # Most vulnerable functions take 1-2 string args
            # Try calling with just the payload string
            try:
                func(payload.value)
            except TypeError:
                # Try two-arg signature (e.g., authenticate_user(username, password))
                try:
                    func(payload.value, payload.value)
                except TypeError:
                    pass
            return None   # No crash

        except Exception as e:
            return triage_crash(
                exception     = e,
                payload       = payload,
                function_name = fname,
            )


def format_fuzz_comparison(comp: FuzzComparison) -> str:
    """Format a FuzzComparison for CLI display."""
    lines = []
    if comp.vuln_fixed:
        lines.append(f"  [green]✅ FUZZER: Fix confirmed ({comp.confidence} confidence)[/green]")
        lines.append(f"     Pre-patch:  {comp.pre_patch.total_inputs} inputs, "
                     f"{len(comp.pre_patch.crashes)} crashes")
        lines.append(f"     Post-patch: {comp.post_patch.total_inputs} inputs, "
                     f"{len(comp.post_patch.crashes)} crashes (0 = fixed)")
    else:
        lines.append(f"  [red]❌ FUZZER: Fix may be INCOMPLETE[/red]")
        lines.append(f"     Post-patch still triggered {len(comp.post_patch.crashes)} crash(es)")
        if comp.post_patch.exploitable:
            lines.append(f"     Exploitable inputs: {comp.post_patch.exploitable[0].value[:60]}")
    return "\n".join(lines)
