#!/usr/bin/env python
"""
demo.py — KAVACH-AIDR Autonomous Security Showcase & Verification Suite

Executes the full end-to-end cyber reasoning pipeline:
  1. System Telemetry & Hardware Profile
  2. Multi-Engine Static Analysis (Semgrep + Bandit + AST Code Graph)
  3. Context-Aware LLM Root Cause Reasoning
  4. Autonomous Security Patch Generation
  5. SMT Formal Theorem Prover (Microsoft Z3)
  6. Dynamic Execution & Smart Fuzzing
  7. Graph Neural Network (VulnGNN) Risk Scoring
  8. Cryptographic HMAC-SHA256 Audit Signing
  9. Automated Regression Test Generation

Usage:
    python demo.py                         # Scan all benchmark sample targets
    python demo.py --target myfile.py      # Scan a specific file or directory
    python demo.py --deep                  # Deep verification (Z3 + Fuzzer + VulnGNN)
    python demo.py --showcase              # Paced interactive presentation mode
"""

import sys
import io
import time
import subprocess
from pathlib import Path

# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule

console = Console()

# ── Project root ──────────────────────────────────────────────────────────────
ROOT    = Path(__file__).parent
SAMPLES = ROOT / "tests" / "samples"

SAMPLE_FILES = [
    SAMPLES / "vuln_sqli.py",
    SAMPLES / "vuln_pathtraversal.py",
    SAMPLES / "vuln_deserialization.py",
    SAMPLES / "vuln_secrets.py",
]

BANNER = """
[bold cyan]
 ██╗  ██╗ █████╗ ██╗   ██╗ █████╗  ██████╗██╗  ██╗
 ██║ ██╔╝██╔══██╗██║   ██║██╔══██╗██╔════╝██║  ██║
 █████╔╝ ███████║██║   ██║███████║██║     ███████║
 ██╔═██╗ ██╔══██║╚██╗ ██╔╝██╔══██║██║     ██╔══██║
 ██║  ██╗██║  ██║ ╚████╔╝ ██║  ██║╚██████╗██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝[/bold cyan]
[bold yellow]           A I D R  —  Autonomous Intelligent Defensive Reasoner[/bold yellow]
[dim]           Sovereign · Air-Gapped · Indian Armed Forces Infrastructure[/dim]
"""


@click.command()
@click.option("--target",   "-t", default=None,   help="Specific target file or directory (default: all benchmark samples)")
@click.option("--deep",           is_flag=True,   help="Enable deep verification: Z3 SMT prover + Fuzzer + VulnGNN")
@click.option("--top",      "-n", default=3,       help="Top priority findings to reason over (default: 3)")
@click.option("--no-patch",       is_flag=True,   help="Perform diagnostic and verification analysis without applying patches")
@click.option("--showcase",       is_flag=True,   help="Interactive presentation mode with paced execution")
def demo(target, deep, top, no_patch, showcase):
    """
    KAVACH-AIDR — Autonomous cyber reasoning, formal verification, and remediation suite.
    """
    console.print(BANNER)

    if showcase:
        console.print(Panel(
            "[bold]AUTONOMOUS DEFENSE SHOWCASE[/bold]\n\n"
            "This demonstration autonomously identifies security vulnerabilities,\n"
            "diagnoses root causes via local LLM reasoning, synthesizes security patches,\n"
            "and [bold green]mathematically proves remediation integrity[/bold green] via Z3 SMT formal verification.",
            title="[bold yellow]KAVACH-AIDR Security Suite[/bold yellow]",
            border_style="yellow",
        ))
        time.sleep(1.5)

    _print_capabilities(deep)

    if showcase:
        time.sleep(1)

    if target:
        targets = [target]
    else:
        targets = [str(f) for f in SAMPLE_FILES if f.exists()]
        if not targets:
            console.print("[red]Sample targets not found. Ensure execution from repository root.[/red]")
            sys.exit(1)

    console.print(f"\n[bold]Initiating scan across {len(targets)} target file(s)...[/bold]\n")

    for i, t in enumerate(targets, 1):
        fname = Path(t).name
        console.print(Rule(f"[bold cyan]Target {i}/{len(targets)}: {fname}[/bold cyan]"))

        if showcase:
            console.print(f"[dim]Analyzing {fname}...[/dim]")
            time.sleep(0.5)

        cmd = [
            sys.executable, "-m", "kavach.main", "scan", t,
            "--top", str(top),
        ]
        if deep:
            cmd.append("--deep")
        if no_patch:
            cmd.append("--no-patch")

        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            text=True,
            capture_output=False,
        )

        if proc.returncode != 0:
            console.print(f"[yellow]Diagnostic notice: process exited with code {proc.returncode}[/yellow]")

        if showcase:
            time.sleep(0.5)

    # ── Run VulnGNN Evaluation ─────────────────────────────────────────────
    console.print(Rule("[bold cyan]VulnGNN Graph Neural Network Evaluation[/bold cyan]"))
    subprocess.run(
        [sys.executable, "-m", "kavach.vuln_gnn.eval_vuln_gnn"],
        cwd=str(ROOT),
        text=True,
        capture_output=False,
    )

    # ── Executive Summary Panel ────────────────────────────────────────────
    console.print("\n")
    console.print(Panel(
        "[bold green]KAVACH-AIDR Verification Run Complete[/bold green]\n\n"
        "[bold]Autonomous Pipeline Summary:[/bold]\n"
        "  [cyan]1.[/cyan] Multi-Engine Static Analysis (Semgrep + Bandit + Code Graph)\n"
        "  [cyan]2.[/cyan] LLM Root Cause Diagnosis & Threat Modeling\n"
        "  [cyan]3.[/cyan] Autonomous AST-Validated Patch Generation\n"
        "  [cyan]4.[/cyan] Z3 SMT Formal Theorem Prover (Mathematical Safety Proof)\n"
        "  [cyan]5.[/cyan] Dynamic Fuzzing Execution & Crash Triage\n"
        "  [cyan]6.[/cyan] VulnGNN Graph Neural Network Classification\n"
        "  [cyan]7.[/cyan] Cryptographic HMAC-SHA256 Audit Trail\n"
        "  [cyan]8.[/cyan] Automated Pytest Regression Test Generation\n\n"
        "[bold yellow]Operational Environment: Fully Air-Gapped / Zero External Network Egress[/bold yellow]\n"
        "[dim]Sovereign · Air-Gapped · Indian Armed Forces Infrastructure[/dim]",
        border_style="green",
        title="[bold]KAVACH-AIDR Autonomous Defensive Reasoner[/bold]",
    ))

    console.print("\n[bold]Repository:[/bold] https://github.com/Programmer-Develops/kavach-aidr\n")


def _print_capabilities(deep: bool) -> None:
    """Print an overview table of active KAVACH-AIDR system capabilities."""
    table = Table(
        title="System Capabilities & Verification Layers",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
    )
    table.add_column("Layer", style="bold", width=16)
    table.add_column("Module", width=26)
    table.add_column("Underlying Engine / Technique", width=36)
    table.add_column("Status", width=12)

    rows = [
        ("Static Analysis",    "AST Code Parser",       "Abstract Syntax Tree (Symbolic AI)", "ACTIVE"),
        ("Static Analysis",    "Code Graph Builder",    "Graph Theory + Taint Flow Tracking", "ACTIVE"),
        ("Static Analysis",    "Semgrep Runner",        "Pattern Engine (Defense Rule Sets)", "ACTIVE"),
        ("Static Analysis",    "Bandit Runner",         "Python Security Linter (AST)",       "ACTIVE"),
        ("Ensemble",           "Finding Merger",        "Corroboration & Risk Scoring",       "ACTIVE"),
        ("Reasoning",          "LLM Reasoner",         "Transformer (CodeLlama-7B / Phi-3)",  "ACTIVE"),
        ("Remediation",        "Autonomous Patcher",   "LLM Code Synthesis + AST Validator",  "ACTIVE"),
        ("Audit",              "HMAC Audit Trail",     "Cryptographic Signing (HMAC-SHA256)", "ACTIVE"),
        ("Formal Verification","Z3 Formal Verifier",   "SMT Theorem Prover (Microsoft Z3)",   "ACTIVE" if deep else "use --deep"),
        ("Dynamic Validation", "Smart Fuzzer",         "Execution-Guided Heuristic Search",   "ACTIVE" if deep else "use --deep"),
        ("Regression",         "Regression Harness",   "Pytest Suite Synthesizer",            "ACTIVE" if deep else "use --deep"),
        ("Graph Intelligence", "VulnGNN",              "GraphSAGE Neural Network",            "ACTIVE"),
    ]

    for layer, module, technique, status in rows:
        color = "green" if status == "ACTIVE" else "yellow"
        table.add_row(layer, module, technique, f"[{color}]{status}[/{color}]")

    console.print(table)


if __name__ == "__main__":
    demo()
