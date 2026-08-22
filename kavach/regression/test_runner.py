"""
test_runner.py — Run regression tests pre/post patch and compare.

Executes the generated pytest suites and returns structured results
for the KAVACH-AIDR audit trail and CLI display.
"""

import subprocess
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TestRunResult:
    """Result of running a pytest test suite."""
    phase        : str         # "pre_patch" | "post_patch"
    test_file    : str
    passed       : int
    failed       : int
    errors       : int
    total        : int
    duration_sec : float
    exit_code    : int
    output       : str         # Raw pytest output


@dataclass
class RegressionComparison:
    """Before/after test run comparison."""
    pre_patch    : Optional[TestRunResult] = None
    post_patch   : Optional[TestRunResult] = None
    regression_ok: bool  = False   # True = post passes what pre failed
    summary      : str   = ""


def run_tests(
    test_file   : str | Path,
    phase       : str = "post_patch",
    timeout_sec : int = 30,
) -> TestRunResult:
    """
    Run a pytest file and return structured results.

    Args:
        test_file   : Path to the pytest .py file
        phase       : "pre_patch" or "post_patch" label
        timeout_sec : Timeout for the test run

    Returns:
        TestRunResult with pass/fail counts.
    """
    start = time.time()
    path  = Path(test_file)

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(path), "-v", "--tb=short",
             "--no-header", "-q"],
            capture_output = True,
            text           = True,
            timeout        = timeout_sec,
        )
        output    = proc.stdout + proc.stderr
        exit_code = proc.returncode

        # Parse pytest output
        passed, failed, errors = _parse_pytest_output(output)

    except subprocess.TimeoutExpired:
        output    = "Test run timed out."
        exit_code = -1
        passed = failed = errors = 0

    except Exception as e:
        output    = str(e)
        exit_code = -1
        passed = failed = errors = 0

    total = passed + failed + errors

    return TestRunResult(
        phase        = phase,
        test_file    = str(path),
        passed       = passed,
        failed       = failed,
        errors       = errors,
        total        = total,
        duration_sec = round(time.time() - start, 2),
        exit_code    = exit_code,
        output       = output,
    )


def compare_runs(
    pre_result  : TestRunResult,
    post_result : TestRunResult,
) -> RegressionComparison:
    """
    Compare pre and post patch test results.

    Regression OK means: post_patch passes at least as many tests
    as were failing in pre_patch (i.e., the patch fixed the bugs
    without breaking anything else).
    """
    comp = RegressionComparison(
        pre_patch  = pre_result,
        post_patch = post_result,
    )

    pre_fail  = pre_result.failed + pre_result.errors
    post_fail = post_result.failed + post_result.errors
    post_pass = post_result.passed

    if post_fail == 0 and post_pass > 0:
        comp.regression_ok = True
        comp.summary = (
            f"✅ REGRESSION HARNESS PASSED — "
            f"{post_pass}/{post_result.total} tests pass after patching. "
            f"All exploit inputs neutralised, no functionality broken."
        )
    elif post_fail < pre_fail:
        comp.regression_ok = True
        comp.summary = (
            f"⚠ PARTIAL — {post_fail} test(s) still failing after patch "
            f"(down from {pre_fail}). Patch is an improvement."
        )
    else:
        comp.regression_ok = False
        comp.summary = (
            f"❌ REGRESSION FAILED — {post_fail} test(s) still failing. "
            f"Patch did not fix the issues detected by fuzzing."
        )

    return comp


def _parse_pytest_output(output: str) -> tuple[int, int, int]:
    """Parse pytest output for passed/failed/error counts."""
    passed = failed = errors = 0
    for line in output.splitlines():
        line = line.strip()
        # e.g. "5 passed, 2 failed, 1 error in 0.5s"
        if "passed" in line:
            for token in line.split(","):
                token = token.strip()
                if "passed" in token:
                    try: passed = int(token.split()[0])
                    except: pass
                elif "failed" in token:
                    try: failed = int(token.split()[0])
                    except: pass
                elif "error" in token:
                    try: errors = int(token.split()[0])
                    except: pass
    return passed, failed, errors
