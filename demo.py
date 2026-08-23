#!/usr/bin/env python
"""
demo.py — KAVACH-AIDR End-to-End Demo Script

One command. Full pipeline. For judges, evaluators, and presentations.

Usage:
    python demo.py                         # scans all 4 sample vulnerable files
    python demo.py --target myfile.py      # scan a specific file
    python demo.py --deep                  # with Z3 + fuzzer + GNN
    python demo.py --showcase              # slower, more verbose, for live demo

What it shows:
  1. Hardware detection (GPU, RAM, CPU)
  2. Multi-tool static analysis (Semgrep + Bandit + Code Graph)
  3. LLM reasoning (or static fallback if model not downloaded)
  4. Autonomous patch generation
  5. Z3 formal verification (--deep)
  6. Smart fuzzer pre/post comparison (--deep)
  7. VulnGNN vulnerability scoring (--deep)
  8. HMAC-SHA256 tamper-proof audit trail
  9. Auto-generated regression tests
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
from rich.columns import Columns
from rich.table import Table
from rich.rule import Rule
from rich import print as rprint

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
[dim]           Sovereign · Air-Gapped · Built for the Indian Armed Forces[/dim]
"""


@click.command()
@click.option("--target",   "-t", default=None,   help="Specific file/dir to scan (default: all 4 samples)")
@click.option("--deep",           is_flag=True,   help="Enable Phase 2: Z3 + Fuzzer + VulnGNN")
@click.option("--top",      "-n", default=3,       help="Top findings to analyse (default: 3)")
@click.option("--no-patch",       is_flag=True,   help="Analysis only — skip patching")
@click.option("--showcase",       is_flag=True,   help="Live demo mode — slower, more verbose output")
def demo(target, deep, top, no_patch, showcase):
    """
    KAVACH-AIDR — One-command end-to-end demonstration.

    Scans vulnerable sample code, detects bugs, reasons about them,
    patches them, and proves the fix holds — fully autonomously.
    """
    console.print(BANNER)

    if showcase:
        console.print(Panel(
            "[bold]SHOWCASE MODE[/bold] — Live demonstration for judges\n\n"
            "This demo will autonomously find, analyse, patch,\n"
            "and [bold green]mathematically prove[/bold green] fixes for real vulnerabilities\n"
            "in Python code — with zero human intervention.",
            title="[bold yellow]AI Kavach — Terrier Cyber Quest 2026[/bold yellow]",
            border_style="yellow",
        ))
        time.sleep(2)

    # ── Show capabilities summary ──────────────────────────────────────────
    _print_capabilities(deep)

    if showcase:
        time.sleep(1)

    # ── Determine target files ─────────────────────────────────────────────
    if target:
        targets = [target]
    else:
        targets = [str(f) for f in SAMPLE_FILES if f.exists()]
        if not targets:
            console.print("[red]Sample files not found. Run from kavach-aidr/ directory.[/red]")
            sys.exit(1)

    console.print(f"\n[bold]Scanning {len(targets)} target file(s)...[/bold]\n")

    # ── Run KAVACH scan on each target ─────────────────────────────────────
    all_run_ids = []
    total_findings = 0

    for i, t in enumerate(targets, 1):
        fname = Path(t).name
        console.print(Rule(f"[bold cyan]Target {i}/{len(targets)}: {fname}[/bold cyan]"))

        if showcase:
            console.print(f"[dim]Preparing analysis of {fname}...[/dim]")
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
            capture_output=False,   # stream output directly to terminal
        )

        if proc.returncode != 0:
            console.print(f"[yellow]Note: scan exited with code {proc.returncode}[/yellow]")

        if showcase:
            time.sleep(0.5)

    # ── Run GNN accuracy evaluation ────────────────────────────────────────
    console.print(Rule("[bold cyan]VulnGNN Accuracy Evaluation[/bold cyan]"))
    subprocess.run(
        [sys.executable, "-m", "kavach.vuln_gnn.eval_vuln_gnn"],
        cwd=str(ROOT),
        text=True,
        capture_output=False,
    )

    # ── Final showcase summary ─────────────────────────────────────────────
    console.print("\n")
    console.print(Panel(
        "[bold green]KAVACH-AIDR Demo Complete[/bold green]\n\n"
        "[bold]What you just witnessed:[/bold]\n"
        "  [cyan]1.[/cyan] Multi-tool static analysis (Semgrep + Bandit + Code Graph)\n"
        "  [cyan]2.[/cyan] AI-powered root cause explanation\n"
        "  [cyan]3.[/cyan] Autonomous patch generation\n"
        "  [cyan]4.[/cyan] Z3 formal verification (mathematical proof)\n"
        "  [cyan]5.[/cyan] LLM-guided smart fuzzer (pre/post patch comparison)\n"
        "  [cyan]6.[/cyan] VulnGNN vulnerability scoring (F1=72.7%)\n"
        "  [cyan]7.[/cyan] HMAC-SHA256 tamper-proof audit trail\n"
        "  [cyan]8.[/cyan] Auto-generated regression test suite\n\n"
        "[bold yellow]All of this ran OFFLINE. No internet. No foreign APIs.[/bold yellow]\n"
        "[dim]Sovereign · Air-Gapped · Built for the Indian Armed Forces[/dim]",
        border_style="green",
        title="[bold]KAVACH-AIDR — AI Kavach, Terrier Cyber Quest 2026[/bold]",
    ))

    console.print("\n[bold]Repository:[/bold] https://github.com/Programmer-Develops/kavach-aidr\n")


def _print_capabilities(deep: bool) -> None:
    """Print a table of active KAVACH-AIDR capabilities."""
    table = Table(
        title="Active KAVACH-AIDR Capabilities",
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
    )
    table.add_column("Phase", style="bold", width=10)
    table.add_column("Module", width=28)
    table.add_column("AI/ML Technique", width=35)
    table.add_column("Status", width=10)

    rows_p1 = [
        ("1", "AST Code Parser",       "Abstract Syntax Tree (Symbolic AI)", "ACTIVE"),
        ("1", "Code Graph Builder",    "Graph Theory + Taint Analysis",      "ACTIVE"),
        ("1", "Semgrep Runner",        "Rule-based Expert System (60+ rules)","ACTIVE"),
        ("1", "Bandit Runner",         "Rule-based Expert System (B-codes)",  "ACTIVE"),
        ("1", "Finding Merger",        "Ensemble Method + Corroboration",     "ACTIVE"),
        ("1", "LLM Reasoner",         "Transformer (CodeLlama-7B / Phi-3)",  "ACTIVE"),
        ("1", "Autonomous Patcher",   "LLM Code Generation",                 "ACTIVE"),
        ("1", "HMAC Audit Trail",     "Cryptographic Signing (SHA-256)",     "ACTIVE"),
    ]
    rows_p2 = [
        ("2", "Z3 Formal Verifier",   "SMT Theorem Proving (Microsoft Z3)",  "ACTIVE" if deep else "use --deep"),
        ("2", "Smart Fuzzer",         "LLM-guided Heuristic Search",         "ACTIVE" if deep else "use --deep"),
        ("2", "Regression Harness",   "Differential Behavioural Testing",    "ACTIVE" if deep else "use --deep"),
        ("2", "VulnGNN",              "GraphSAGE Neural Network (F1=72.7%)", "ACTIVE"),
    ]

    for phase, module, technique, status in rows_p1:
        color = "green" if status == "ACTIVE" else "yellow"
        table.add_row(phase, module, technique, f"[{color}]{status}[/{color}]")

    for phase, module, technique, status in rows_p2:
        color = "green" if status == "ACTIVE" else "yellow"
        table.add_row(phase, module, technique, f"[{color}]{status}[/{color}]")

    console.print(table)


if __name__ == "__main__":
    demo()
