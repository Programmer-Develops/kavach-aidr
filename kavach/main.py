"""
main.py -- KAVACH-AIDR CLI Orchestrator
"""

# Force UTF-8 output on Windows (fixes CP1252 UnicodeEncodeError with Rich)
import sys
import io
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


import uuid
import json
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich import print as rprint

# ── KAVACH imports ────────────────────────────────────────────────────────────
from kavach.config import build_config, detect_hardware, check_tools, MODELS
from kavach.ingestion.parser import parse_file, summarise as parse_summary
from kavach.ingestion.graph_builder import build_graph, graph_to_llm_context, get_vuln_nodes
from kavach.static.semgrep_runner import run_semgrep
from kavach.static.bandit_runner import run_bandit
from kavach.static.merger import (
    merge_findings, graph_to_findings, findings_summary, get_top_findings
)
from kavach.reasoner.llm_engine import get_engine
from kavach.reasoner.chain_of_thought import ChainOfThought
from kavach.reasoner.patch_generator import parse_patch
from kavach.patcher.patch_applicator import apply_patch
from kavach.patcher.syntax_validator import validate_patch
from kavach.audit.db import AuditDB
from kavach.audit.audit_logger import AuditLogger
from kavach.audit.siem_exporter import export_cef, export_json_findings

# ── Formal Verification, Fuzzing & GNN Imports ────────────────────────────────
from kavach.verifier.z3_verifier import Z3Verifier, format_result as format_z3, PROVED, COUNTEREX
from kavach.fuzzer.runner import KavachFuzzer, format_fuzz_comparison
from kavach.fuzzer.crash_triager import deduplicate_crashes
from kavach.regression.test_generator import generate_tests
from kavach.regression.test_runner import run_tests, compare_runs
from kavach.vuln_gnn.predict import predict_vulnerability

console = Console()

# ── KAVACH ASCII Banner ───────────────────────────────────────────────────────

BANNER = """
[bold blue]
 ##  ##   ##   ##  ##   ##   ###  ##  ##
 ## ##   ####  ## ##   ####  ##   ## ##
 ####   ##  ## ####   ##  ## ##   ####
 ## ##  ###### ## ##  ###### ##   ## ##
 ##  ## ##  ## ##  ## ##  ## ###  ##  ##
                                 A I D R[/bold blue]
[bold yellow] Autonomous Intelligent Defensive Reasoner[/bold yellow]
[dim] Sovereign | Air-gapped | Indian Armed Forces[/dim]
"""



# ── CLI Group ─────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """KAVACH-AIDR — Autonomous Cyber-Reasoning System for the Indian Armed Forces."""
    pass


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: scan
# ══════════════════════════════════════════════════════════════════════════════

@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--model",   "-m", default=None,  help="Force model: phi3-mini | codellama-7b | codellama-13b")
@click.option("--top",     "-n", default=5,      help="Number of top findings to reason over (default: 5)")
@click.option("--output",  "-o", default=None,   help="Output report directory (default: reports/)")
@click.option("--no-patch",      is_flag=True,   help="Skip patch application (analysis only)")
@click.option("--deep",          is_flag=True,   help="Enable multi-layer verification: Z3 formal proof + Fuzzer + VulnGNN")
@click.option("--verbose", "-v", is_flag=True,   help="Verbose LLM output")
@click.option("--export-cef",    is_flag=True,   help="Export CEF file for SIEM")
def scan(target, model, top, output, no_patch, deep, verbose, export_cef):
    """
    Run the full KAVACH-AIDR pipeline on a Python file or directory.

    TARGET: Path to a .py file or directory of .py files to analyse.

    Example:
        python -m kavach.main scan tests/samples/vuln_sqli.py
        python -m kavach.main scan ./my_army_software/ --top 10
    """
    console.print(BANNER)

    run_id     = str(uuid.uuid4())[:8].upper()
    start_time = time.time()
    target_path = Path(target)

    # ── Configuration ─────────────────────────────────────────────────────
    cfg     = build_config(model_override=model, verbose=verbose)
    tools   = check_tools()

    console.print(Panel(
        f"[bold]Run ID:[/bold] {run_id}\n"
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]CPU:[/bold] {cfg.hardware.cpu_cores} cores | "
        f"[bold]RAM:[/bold] {cfg.hardware.ram_gb:.1f} GB | "
        f"[bold]GPU:[/bold] {'✅ ' + cfg.hardware.gpu_name if cfg.hardware.has_gpu else '❌ None (CPU mode)'}\n"
        f"[bold]Model:[/bold] {MODELS[cfg.model_key]['name']} ({MODELS[cfg.model_key]['origin']})\n"
        f"[bold]Semgrep:[/bold] {'✅' if tools['semgrep'] else '❌ not installed'} | "
        f"[bold]Bandit:[/bold] {'✅' if tools['bandit'] else '❌ not installed'}",
        title="🛡️  KAVACH-AIDR — System Status",
        border_style="blue",
    ))

    # ── Audit setup ───────────────────────────────────────────────────────
    db     = AuditDB(cfg.audit_db_path)
    logger = AuditLogger(db, hmac_secret=cfg.hmac_secret, run_id=run_id)
    logger.log_scan_start(str(target_path), config_summary={
        "model"     : cfg.model_key,
        "hardware"  : {"cpu": cfg.hardware.cpu_cores, "ram_gb": cfg.hardware.ram_gb},
        "llm_loaded": cfg.model_path is not None,
    })

    # ── Step 1: Ingest & Parse ────────────────────────────────────────────
    with _step("Step 1/5", "Ingesting source code & building AST graph"):
        if target_path.is_file():
            py_files = [target_path]
        else:
            py_files = list(target_path.rglob("*.py"))

        if not py_files:
            console.print("[red]No Python files found in target.[/red]")
            sys.exit(1)

        all_parsed   = [parse_file(f) for f in py_files]
        all_graphs   = [build_graph(p) for p in all_parsed]
        graph_findings = []
        for g in all_graphs:
            graph_findings.extend(graph_to_findings(g))

    console.print(f"  [green]✓[/green] Parsed {len(py_files)} file(s), "
                  f"built {sum(g.summary['total_nodes'] for g in all_graphs)} graph nodes")

    # ── Step 2: Static Analysis ───────────────────────────────────────────
    semgrep_findings = []
    bandit_findings  = []

    with _step("Step 2/5", "Running static analysis (Semgrep + Bandit)"):
        if tools["semgrep"]:
            try:
                semgrep_findings = run_semgrep(target_path)
            except Exception as e:
                console.print(f"  [yellow]⚠ Semgrep error: {e}[/yellow]")

        if tools["bandit"]:
            try:
                bandit_findings = run_bandit(target_path)
            except Exception as e:
                console.print(f"  [yellow]⚠ Bandit error: {e}[/yellow]")

    console.print(f"  [green]✓[/green] Semgrep: {len(semgrep_findings)} | "
                  f"Bandit: {len(bandit_findings)} | "
                  f"Graph: {len(graph_findings)}")

    # ── Step 3: Merge & Rank ──────────────────────────────────────────────
    with _step("Step 3/5", "Merging & ranking findings"):
        merged = merge_findings(semgrep_findings, bandit_findings, graph_findings)
        summary = findings_summary(merged)

    logger.log_static_analysis_complete(
        len(semgrep_findings), len(bandit_findings), len(merged)
    )

    if not merged:
        console.print(Panel(
            "[bold green]✅ No vulnerabilities detected.[/bold green]\n"
            "The target code passed all KAVACH-AIDR security checks.",
            border_style="green",
        ))
        logger.log_scan_complete(0, status="COMPLETED_CLEAN")
        return

    # Display findings table
    _print_findings_table(merged)

    for f in merged:
        logger.log_finding(f)

    # ── Step 4: LLM Reasoning ────────────────────────────────────────────
    engine = get_engine(cfg)
    cot    = ChainOfThought(engine=engine)
    top_findings = get_top_findings(merged, n=top)

    if engine:
        console.print(f"\n[bold]Step 4/5:[/bold] LLM Reasoning "
                      f"[dim](model: {MODELS[cfg.model_key]['name']})[/dim]")
    else:
        console.print(f"\n[bold]Step 4/5:[/bold] LLM Reasoning "
                      f"[yellow](model not loaded — using static fallbacks)[/yellow]")
        if cfg.model_path is None:
            console.print(f"  [yellow]→ Download model: see models/DOWNLOAD.md[/yellow]")

    reasoning_results = []
    for i, finding in enumerate(top_findings, 1):
        # Load source for this file
        src_path = Path(finding.filepath)
        source_code = src_path.read_text(encoding="utf-8") if src_path.exists() else ""

        with console.status(
            f"  [{i}/{len(top_findings)}] Reasoning: "
            f"[bold]{finding.vuln_type}[/bold] @ line {finding.lineno} ...",
            spinner="dots",
        ):
            result = cot.reason(finding, source_code, finding.filepath)

        logger.log_llm_reasoning(result)
        reasoning_results.append(result)

        # Display reasoning output
        _print_reasoning(finding, result, i)

        # ── Step 5: Apply Patch ───────────────────────────────────────────
        patched_code = ""
        if not no_patch and result.patch_found and source_code:
            parsed_patch = parse_patch(result.patch_diff)
            patch_result = apply_patch(source_code, parsed_patch, finding.filepath)
            validation   = validate_patch(source_code, patch_result.patched_code) if patch_result.success else None
            patched_code = patch_result.patched_code if patch_result.success else ""

            logger.log_patch_result(finding.finding_id, patch_result)
            _print_patch_result(finding, patch_result, validation)

        # ── Multi-Layer Deep Verification (--deep flag) ──────────────────────
        if deep:
            _run_deep_verification(
                finding     = finding,
                source_code = source_code,
                patched_code= patched_code,
                engine      = engine,
                run_id      = run_id,
                out_dir_str = str(Path(output) if output else cfg.reports_dir / run_id),
            )

    # ── GNN scan of all graphs (deep mode) ────────────────────────────────
    if deep:
        console.print("\n[bold]VulnGNN Analysis:[/bold]")
        for graph, py_file in zip(all_graphs, py_files):
            gnn_pred = predict_vulnerability(graph)
            icon = "[red]VULN[/red]" if gnn_pred.is_vulnerable else "[green]SAFE[/green]"
            console.print(
                f"  {icon} {py_file.name}: "
                f"{gnn_pred.vulnerability_prob:.0%} vuln probability — "
                f"{gnn_pred.reasoning[:80]}..."
            )

    # ── Final Report ──────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    out_dir = Path(output) if output else cfg.reports_dir / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON report
    report_path = logger.export_json_report(run_id, out_dir / "kavach_report.json")

    # CEF export (if requested)
    if export_cef:
        cef_path = export_cef(merged, run_id, out_dir / "kavach_findings.cef")
        console.print(f"  [green]✓[/green] CEF export: {cef_path}")

    # JSON findings
    export_json_findings(merged, run_id, out_dir / "findings.json")

    logger.log_scan_complete(
        total_findings = len(merged),
        llm_model      = MODELS[cfg.model_key]["name"] if engine else None,
        llm_available  = engine is not None,
    )

    console.print(Panel(
        f"[bold green]🛡️  KAVACH-AIDR Scan Complete[/bold green]\n\n"
        f"[bold]Run ID:[/bold]           {run_id}\n"
        f"[bold]Total findings:[/bold]   {len(merged)}\n"
        f"  CRITICAL: {summary['severity'].get('CRITICAL',0)}  "
        f"HIGH: {summary['severity'].get('HIGH',0)}  "
        f"MEDIUM: {summary['severity'].get('MEDIUM',0)}  "
        f"LOW: {summary['severity'].get('LOW',0)}\n"
        f"[bold]Corroborated:[/bold]     {summary['corroborated']} (found by 2+ tools)\n"
        f"[bold]LLM analysed:[/bold]     {len(reasoning_results)}/{len(top_findings)} findings\n"
        f"[bold]Time elapsed:[/bold]     {elapsed:.1f}s\n"
        f"[bold]Report:[/bold]           {report_path}\n"
        f"[bold]Audit DB:[/bold]         {cfg.audit_db_path}\n\n"
        f"[dim]All events signed with HMAC-SHA256. "
        f"Run 'python -m kavach.main verify-audit {run_id}' to verify integrity.[/dim]",
        title="📊 Scan Summary",
        border_style="green",
    ))


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: verify-audit
# ══════════════════════════════════════════════════════════════════════════════

@cli.command("verify-audit")
@click.argument("run_id")
def verify_audit(run_id):
    """Verify tamper-proof integrity of all audit events for a scan run."""
    cfg    = build_config()
    db     = AuditDB(cfg.audit_db_path)
    logger = AuditLogger(db, hmac_secret=cfg.hmac_secret)

    all_valid, valid, total = logger.verify_all_events(run_id)

    if all_valid:
        console.print(Panel(
            f"[bold green]✅ INTEGRITY VERIFIED[/bold green]\n"
            f"All {total} audit events for run [bold]{run_id}[/bold] "
            f"have valid HMAC-SHA256 signatures.\n"
            f"No tampering detected.",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]❌ INTEGRITY VIOLATION[/bold red]\n"
            f"Only {valid}/{total} events passed signature verification.\n"
            f"⚠ Audit log may have been tampered with!",
            border_style="red",
        ))
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# COMMAND: info
# ══════════════════════════════════════════════════════════════════════════════

@cli.command()
def info():
    """Display system information and tool status."""
    console.print(BANNER)
    hw    = detect_hardware()
    tools = check_tools()

    hw_table = Table(title="Hardware Profile", border_style="blue")
    hw_table.add_column("Property", style="cyan")
    hw_table.add_column("Value",    style="white")
    hw_table.add_row("CPU Cores", str(hw.cpu_cores))
    hw_table.add_row("RAM",       f"{hw.ram_gb:.1f} GB")
    hw_table.add_row("GPU",       hw.gpu_name if hw.has_gpu else "None (CPU mode)")
    hw_table.add_row("VRAM",      f"{hw.vram_gb:.1f} GB" if hw.has_gpu else "N/A")
    hw_table.add_row("Platform",  hw.platform)
    console.print(hw_table)

    # Recommended model
    from kavach.config import select_model
    rec_model = select_model(hw)
    console.print(f"\n[bold]Recommended model:[/bold] "
                  f"[green]{MODELS[rec_model]['name']}[/green] "
                  f"({MODELS[rec_model]['description']})")

    tool_table = Table(title="Tool Status", border_style="blue")
    tool_table.add_column("Tool",    style="cyan")
    tool_table.add_column("Status",  style="white")
    for tool, available in tools.items():
        tool_table.add_row(tool, "[green]✅ Installed[/green]" if available else "[red]❌ Not found[/red]")
    console.print(tool_table)

    # Check for model files
    from kavach.config import MODELS_DIR
    console.print("\n[bold]Model files:[/bold]")
    for key, spec in MODELS.items():
        path   = MODELS_DIR / spec["filename"]
        exists = path.exists()
        size   = f"{path.stat().st_size / 1e9:.1f} GB" if exists else "not downloaded"
        console.print(
            f"  {'[green]✅[/green]' if exists else '[red]❌[/red]'} "
            f"{spec['name']} — {size}"
        )
    if not any((MODELS_DIR / s["filename"]).exists() for s in MODELS.values()):
        console.print("\n  [yellow]→ No models downloaded. See models/DOWNLOAD.md[/yellow]")



# ── Deep Verification Orchestrator ───────────────────────────────────────────

def _run_deep_verification(
    finding      : object,
    source_code  : str,
    patched_code : str,
    engine       : object,
    run_id       : str,
    out_dir_str  : str,
) -> None:
    """
    Run multi-layer verification on a single finding:
      1. Z3 SMT formal verification (pre/post patch)
      2. Dynamic execution & smart fuzzing (LLM-guided payloads)
      3. Automated regression test generation
    """
    import ast as _ast
    out_dir = Path(out_dir_str)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n  [bold cyan]--- Multi-Layer Verification: SMT Proof & Dynamic Fuzzing ---[/bold cyan]")

    # ── Z3 Formal Verification ─────────────────────────────────────────────
    with console.status("  [Z3] Running formal verification ...", spinner="dots"):
        verifier = Z3Verifier(timeout_ms=5000)
        z3_result = verifier.verify(
            finding_id   = finding.finding_id,
            vuln_type    = finding.vuln_type,
            filepath     = finding.filepath,
            lineno       = finding.lineno,
            original_src = source_code,
            patched_src  = patched_code or source_code,
        )

    console.print(f"  {format_z3(z3_result)}")

    # ── Smart Fuzzer ───────────────────────────────────────────────────────
    # Extract function name from finding context
    func_name = _infer_function_name(source_code, finding.lineno)
    if func_name and source_code:
        with console.status(
            f"  [Fuzzer] Running on '{func_name}' ({finding.vuln_type}) ...",
            spinner="dots",
        ):
            fuzzer = KavachFuzzer(llm_engine=engine, max_inputs=50, verbose=False)

            if patched_code:
                fuzz_comp = fuzzer.compare(
                    original_src  = source_code,
                    patched_src   = patched_code,
                    function_name = func_name,
                    vuln_type     = finding.vuln_type,
                    filepath      = finding.filepath,
                )
                console.print(format_fuzz_comparison(fuzz_comp))

                # ── Regression Test Generation ─────────────────────────────
                if fuzz_comp.pre_patch and fuzz_comp.pre_patch.exploitable:
                    with console.status("  [Regression] Generating test suite ...", spinner="dots"):
                        test_suite = generate_tests(
                            function_name      = func_name,
                            vuln_type          = finding.vuln_type,
                            source_filepath    = patched_code and finding.filepath or finding.filepath,
                            exploitable_inputs = fuzz_comp.pre_patch.exploitable,
                            safe_inputs        = [],
                            crashes            = deduplicate_crashes(fuzz_comp.pre_patch.crashes),
                            output_dir         = str(out_dir / "regression_tests"),
                        )
                    console.print(
                        f"  [green]✓[/green] Generated {test_suite.test_count} regression tests: "
                        f"{test_suite.filepath}"
                    )

                    # Run the tests on patched code
                    if patched_code and test_suite.filepath.exists():
                        with console.status("  [Regression] Running tests ...", spinner="dots"):
                            post_run = run_tests(test_suite.filepath, phase="post_patch")
                        passed_pct = (post_run.passed / max(post_run.total, 1)) * 100
                        color = "green" if post_run.failed == 0 else "yellow"
                        console.print(
                            f"  [{color}]Regression: {post_run.passed}/{post_run.total} passed "
                            f"({passed_pct:.0f}%)[/{color}]"
                        )
            else:
                # No patch — just fuzz pre-patch to confirm exploit
                pre_result = fuzzer.fuzz_function(
                    source_code   = source_code,
                    function_name = func_name,
                    vuln_type     = finding.vuln_type,
                    phase         = "pre_patch",
                    filepath      = finding.filepath,
                )
                if pre_result.triggered:
                    console.print(
                        f"  [red]Fuzzer confirmed exploit: "
                        f"{len(pre_result.crashes)} crash(es) with "
                        f"{pre_result.total_inputs} inputs[/red]"
                    )
                else:
                    console.print(
                        f"  [yellow]Fuzzer: {pre_result.total_inputs} inputs tested, "
                        f"no crashes (may need model for better seeds)[/yellow]"
                    )
    else:
        console.print("  [dim]Fuzzer: could not determine function name — skipped[/dim]")


def _infer_function_name(source_code: str, lineno: int) -> str:
    """Find the function that contains the given line number."""
    import ast as _ast
    try:
        tree = _ast.parse(source_code)
        for node in _ast.walk(tree):
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", node.lineno + 20)
                if node.lineno <= lineno <= end:
                    return node.name
    except Exception:
        pass
    return ""


# ── Display helpers ───────────────────────────────────────────────────────────

def _print_findings_table(merged) -> None:
    """Print a rich table of all merged findings."""
    sev_colors = {
        "CRITICAL": "bold red",
        "HIGH"    : "red",
        "MEDIUM"  : "yellow",
        "LOW"     : "green",
        "INFO"    : "dim",
    }

    table = Table(
        title=f"🔍 Findings ({len(merged)} total)",
        border_style="red" if any(f.severity == "CRITICAL" for f in merged) else "yellow",
        show_lines=True,
    )
    table.add_column("Sev",        style="bold",  width=9)
    table.add_column("Type",       style="cyan",  width=22)
    table.add_column("File",       style="white", width=25)
    table.add_column("Line",       style="white", width=5)
    table.add_column("Tools",      style="dim",   width=18)
    table.add_column("Score",      style="white", width=6)
    table.add_column("Confirmed?", style="white", width=10)

    for f in merged:
        color = sev_colors.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity}[/{color}]",
            f.vuln_type,
            Path(f.filepath).name,
            str(f.lineno),
            "+".join(f.sources),
            f"{f.score:.1f}",
            "[bold green]YES[/bold green]" if f.corroborated else "[dim]No[/dim]",
        )
    console.print(table)


def _print_reasoning(finding, result, idx: int) -> None:
    """Print LLM reasoning output for a single finding."""
    llm_tag = f"[dim](LLM: {result.model_name})[/dim]" if result.llm_available else "[yellow](static fallback)[/yellow]"

    console.print(Panel(
        f"[bold red]{finding.severity}[/bold red] | "
        f"[cyan]{finding.vuln_type}[/cyan] | "
        f"Line {finding.lineno} | {llm_tag}\n\n"
        f"[bold]🔍 Root Cause:[/bold]\n{result.root_cause or '(not available)'}\n\n"
        f"[bold]⚔ Exploit Scenario:[/bold]\n{result.exploit_scenario or '(not available)'}\n\n"
        f"[bold]🔧 Patch Found:[/bold] "
        f"{'[green]YES[/green]' if result.patch_found else '[red]NO[/red]'}",
        title=f"Finding [{idx}] — {Path(finding.filepath).name}",
        border_style="red" if finding.severity == "CRITICAL" else "yellow",
    ))

    if result.patch_found:
        console.print(Syntax(result.patch_diff, "diff", theme="monokai", line_numbers=False))


def _print_patch_result(finding, patch_result, validation) -> None:
    """Print the outcome of patch application."""
    if patch_result.success and validation and validation.passed:
        console.print(
            f"  [bold green]✅ PATCH APPLIED[/bold green] — "
            f"Strategy: {patch_result.strategy_used} | "
            f"{patch_result.diff_summary} | "
            f"Syntax: valid"
        )
    elif patch_result.success:
        console.print(
            f"  [yellow]⚠ PATCH APPLIED WITH WARNINGS[/yellow] — "
            f"{validation.summary if validation else 'no validation'}"
        )
        for w in (validation.warnings if validation else []):
            console.print(f"    [yellow]→ {w}[/yellow]")
    else:
        console.print(
            f"  [red]❌ PATCH FAILED[/red] — "
            f"{'; '.join(patch_result.syntax_errors) or 'no applicable strategy found'}"
        )


from contextlib import contextmanager

@contextmanager
def _step(label: str, description: str):
    """Simple context manager for displaying step progress."""
    with console.status(f"[bold]{label}:[/bold] {description} ...", spinner="dots"):
        yield


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
