"""
dashboard.py — KAVACH-AIDR Streamlit Web Dashboard

Interactive UI for browsing scan results, findings, audit trails,
and VulnGNN predictions.

Run:
    streamlit run kavach/ui/dashboard.py

Requires:
    pip install streamlit plotly pandas
"""

import sys
import io
import json
import sqlite3
import subprocess
from pathlib import Path
from datetime import datetime

# Force UTF-8 on Windows (guarded — Streamlit replaces sys.stdout)
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "buffer"):
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "buffer"):
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Project root ───────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent.parent  # kavach-aidr/
sys.path.insert(0, str(ROOT))

try:
    import streamlit as st
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd
    STREAMLIT_OK = True
except ImportError:
    STREAMLIT_OK = False

from kavach.config import build_config, detect_hardware, MODELS
from kavach.ingestion.parser import parse_file
from kavach.ingestion.graph_builder import build_graph
from kavach.vuln_gnn.predict import predict_vulnerability


# ══════════════════════════════════════════════════════════════════════════════
# Page config
# ══════════════════════════════════════════════════════════════════════════════

def setup_page():
    st.set_page_config(
        page_title    = "KAVACH-AIDR",
        page_icon     = "🛡️",
        layout        = "wide",
        initial_sidebar_state="expanded",
    )
    # Custom CSS for military theme
    st.markdown("""
    <style>
    .main { background-color: #0a0e1a; color: #e0e8ff; }
    .stApp { background: linear-gradient(135deg, #0a0e1a 0%, #0d1b2a 100%); }
    .metric-card {
        background: #1a2744;
        border: 1px solid #2a4080;
        border-radius: 8px;
        padding: 16px;
        margin: 8px 0;
    }
    .severity-CRITICAL { color: #ff2244; font-weight: bold; }
    .severity-HIGH     { color: #ff6622; font-weight: bold; }
    .severity-MEDIUM   { color: #ffaa00; }
    .severity-LOW      { color: #44cc88; }
    </style>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# Sidebar
# ══════════════════════════════════════════════════════════════════════════════

def render_sidebar():
    with st.sidebar:
        st.image("https://img.shields.io/badge/KAVACH-AIDR-0066cc?style=for-the-badge", use_container_width=True)
        st.markdown("### 🛡️ KAVACH-AIDR")
        st.caption("Autonomous Intelligent Defensive Reasoner\nSovereign · Air-Gapped · Indian Armed Forces")
        st.divider()

        # Hardware info
        hw = detect_hardware()
        st.markdown("**System Status**")
        cols = st.columns(2)
        cols[0].metric("CPU Cores", hw.cpu_cores)
        cols[1].metric("RAM (GB)", f"{hw.ram_gb:.1f}")
        if hw.gpu_name:
            st.success(f"GPU: {hw.gpu_name}")
        else:
            st.warning("No GPU detected")

        st.divider()
        page = st.radio(
            "Navigate",
            ["🏠 Overview", "🔍 Run Scan", "📊 Findings", "🧠 VulnGNN", "📋 Audit Trail", "ℹ️ About"],
            label_visibility="collapsed",
        )
        return page


# ══════════════════════════════════════════════════════════════════════════════
# Pages
# ══════════════════════════════════════════════════════════════════════════════

def page_overview():
    st.title("🛡️ KAVACH-AIDR Dashboard")
    st.caption("Autonomous Intelligent Defensive Reasoner — Indian Armed Forces Cyber Security")
    st.divider()

    # Stats from audit DB
    db_path = ROOT / "audit" / "kavach_audit.db"
    stats   = _load_db_stats(db_path)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Scans",        stats.get("total_runs", 0))
    col2.metric("Vulnerabilities Found", stats.get("total_findings", 0))
    col3.metric("Patches Generated",  stats.get("patches", 0))
    col4.metric("Audit Events",       stats.get("audit_events", 0))

    st.divider()

    # Architecture diagram
    st.subheader("Pipeline Architecture")
    st.markdown("""
    ```
    Input Code
        │
        ├──► AST Parser ──► Code Graph ──► Risk Score
        │
        ├──► Semgrep (60+ rules) ──┐
        ├──► Bandit (B-codes)    ──┼──► Merger ──► Ranked Findings
        └──► Code Graph          ──┘          │
                                              ▼
                                    LLM Reasoner (CodeLlama-7B)
                                       │         │
                                  Root Cause   Patch Generation
                                              │
                                       Syntax Validator
                                              │
                               ┌─────────────┼─────────────┐
                               ▼             ▼             ▼
                          Z3 Formal     Smart Fuzzer    VulnGNN
                          Verifier      (LLM seeds)     (GraphSAGE)
                               │             │
                          PROVED/           FIX CONFIRMED
                          COUNTEREX
                               │
                          HMAC-SHA256 Audit Trail
    ```
    """)

    # Recent scans table
    st.subheader("Recent Scans")
    runs = _load_recent_runs(db_path)
    if runs:
        st.dataframe(
            pd.DataFrame(runs),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No scans yet. Go to 'Run Scan' to start.")


def page_run_scan():
    st.title("🔍 Run New Scan")
    st.caption("Scan Python code for vulnerabilities autonomously")

    col1, col2 = st.columns([3, 1])
    with col1:
        sample_files = list((ROOT / "tests" / "samples").glob("*.py"))
        sample_names = ["-- select --"] + [f.name for f in sample_files]
        selected     = st.selectbox("Choose a sample file to scan:", sample_names)
        custom_path  = st.text_input("Or enter a custom file path:")

    with col2:
        top_n    = st.number_input("Top findings", min_value=1, max_value=20, value=3)
        deep     = st.checkbox("Deep scan (--deep)", help="Z3 + Fuzzer + GNN")
        no_patch = st.checkbox("No patch (analysis only)")

    target = None
    if custom_path:
        target = custom_path
    elif selected != "-- select --":
        target = str(ROOT / "tests" / "samples" / selected)

    if st.button("🚀 Launch Scan", type="primary", disabled=not target):
        cmd = [sys.executable, "-m", "kavach.main", "scan", target, "--top", str(top_n)]
        if deep:     cmd.append("--deep")
        if no_patch: cmd.append("--no-patch")

        with st.spinner(f"Scanning {Path(target).name} ..."):
            st.markdown("**Scan Output:**")
            output_box = st.empty()
            proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=120)
            output_box.code(proc.stdout + proc.stderr, language="text")

        if proc.returncode == 0:
            st.success("Scan complete! Check the Findings tab.")
        else:
            st.warning(f"Scan finished with warnings (exit {proc.returncode})")


def page_findings():
    st.title("📊 Vulnerability Findings")
    db_path = ROOT / "audit" / "kavach_audit.db"

    findings = _load_all_findings(db_path)
    if not findings:
        st.info("No findings yet. Run a scan first.")
        return

    df = pd.DataFrame(findings)

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total",    len(df))
    col2.metric("Critical", int((df["severity"] == "CRITICAL").sum()))
    col3.metric("High",     int((df["severity"] == "HIGH").sum()))
    col4.metric("Medium",   int((df["severity"] == "MEDIUM").sum()))

    # Severity chart
    sev_counts = df["severity"].value_counts()
    fig = px.pie(
        values=sev_counts.values,
        names=sev_counts.index,
        color=sev_counts.index,
        color_discrete_map={
            "CRITICAL": "#ff2244",
            "HIGH"    : "#ff6622",
            "MEDIUM"  : "#ffaa00",
            "LOW"     : "#44cc88",
        },
        title="Findings by Severity",
    )
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig, use_container_width=True)

    # Vuln type breakdown
    if "vuln_type" in df.columns:
        st.subheader("Vulnerability Types")
        type_counts = df["vuln_type"].value_counts()
        fig2 = px.bar(
            x=type_counts.index,
            y=type_counts.values,
            color=type_counts.values,
            color_continuous_scale="reds",
            title="Findings by Vulnerability Type",
            labels={"x": "Vuln Type", "y": "Count"},
        )
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig2, use_container_width=True)

    # Findings table
    st.subheader("All Findings")
    st.dataframe(df, use_container_width=True, hide_index=True)


def page_vuln_gnn():
    st.title("🧠 VulnGNN — Graph Neural Network")
    st.caption("GraphSAGE architecture — vulnerability probability scoring on code graphs")

    st.markdown("""
    **How VulnGNN works:**
    1. Parses Python code into an AST-based Code Graph (nodes = functions/calls/imports)
    2. Extracts 16-dimensional feature vector per node
    3. Aggregates node scores using 80th percentile weighting
    4. Outputs a vulnerability probability from 0% to 100%

    **Current accuracy (10-sample evaluation):**
    - Accuracy: 70% | Precision: 57.1% | **Recall: 100%** | F1: 72.7%
    """)

    # Live prediction
    st.subheader("Live Prediction")
    sample_files = list((ROOT / "tests" / "samples").glob("*.py"))
    all_files    = sample_files
    selected_file = st.selectbox(
        "Choose a file to analyse with VulnGNN:",
        ["-- select --"] + [f.name for f in all_files]
    )

    if selected_file != "-- select --":
        fpath = ROOT / "tests" / "samples" / selected_file
        if fpath.exists():
            with st.spinner("Running VulnGNN..."):
                parsed = parse_file(fpath)
                graph  = build_graph(parsed)
                pred   = predict_vulnerability(graph)

            col1, col2, col3 = st.columns(3)
            col1.metric("Vulnerability Probability", f"{pred.vulnerability_prob:.0%}")
            col2.metric("Verdict",     "VULNERABLE" if pred.is_vulnerable else "SAFE")
            col3.metric("Confidence",  pred.confidence)

            # Gauge chart
            fig = go.Figure(go.Indicator(
                mode  = "gauge+number",
                value = pred.vulnerability_prob * 100,
                title = {"text": "Vulnerability Score (%)"},
                gauge = {
                    "axis"      : {"range": [0, 100]},
                    "bar"       : {"color": "#ff4444" if pred.is_vulnerable else "#44cc88"},
                    "steps"     : [
                        {"range": [0, 30],   "color": "#1a2744"},
                        {"range": [30, 60],  "color": "#2a3060"},
                        {"range": [60, 100], "color": "#3a1020"},
                    ],
                    "threshold" : {"line": {"color": "red", "width": 4}, "value": 30},
                },
                number = {"suffix": "%"},
            ))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", height=300)
            st.plotly_chart(fig, use_container_width=True)

            st.info(pred.reasoning)

            if pred.top_risky_nodes:
                st.subheader("Highest-Risk Code Nodes")
                for node in pred.top_risky_nodes:
                    st.code(f"⚠  {node}", language="python")


def page_audit():
    st.title("📋 Audit Trail")
    st.caption("HMAC-SHA256 signed, tamper-evident audit log")

    db_path = ROOT / "audit" / "kavach_audit.db"
    if not db_path.exists():
        st.info("No audit database found. Run a scan first.")
        return

    events = _load_audit_events(db_path)
    if not events:
        st.info("No audit events yet.")
        return

    df = pd.DataFrame(events)
    st.metric("Total Audit Events", len(df))

    # Verify integrity button
    if st.button("🔐 Verify All Signatures"):
        # Get distinct run IDs and verify each
        run_ids = df["run_id"].unique() if "run_id" in df.columns else []
        all_ok  = True
        for run_id in run_ids:
            result = subprocess.run(
                [sys.executable, "-m", "kavach.main", "verify-audit", run_id],
                cwd=str(ROOT), capture_output=True, text=True
            )
            if result.returncode != 0:
                st.error(f"Run {run_id}: INTEGRITY VIOLATION")
                all_ok = False
            else:
                st.success(f"Run {run_id}: All signatures valid")
        if all_ok and run_ids:
            st.success("All audit events verified. No tampering detected.")

    st.subheader("Event Log")
    st.dataframe(df, use_container_width=True, hide_index=True)


def page_about():
    st.title("ℹ️ About KAVACH-AIDR")
    st.markdown("""
    ## KAVACH-AIDR
    ### Autonomous Intelligent Defensive Reasoner

    **Developed for:** AI Kavach — Indian Army Terrier Cyber Quest 2026

    ---

    ### What KAVACH means
    *Kavach (कवच) = Shield* — Defensive by design.

    ### What AIDR means
    **A**utonomous **I**ntelligent **D**efensive **R**easoner

    ---

    ### Mission
    Build a sovereign, air-gapped cyber-reasoning system for the Indian Armed
    Forces that can autonomously:
    1. **Find** vulnerabilities in military software
    2. **Understand** the root cause using AI
    3. **Patch** them autonomously
    4. **Prove** the fix holds mathematically

    ### AI/ML Techniques Used
    | Technique | Module |
    |---|---|
    | Abstract Syntax Tree (Symbolic AI) | ingestion/parser.py |
    | Graph Theory + Taint Analysis | ingestion/graph_builder.py |
    | Rule-based Expert System | static/ (Semgrep + Bandit) |
    | Ensemble Method | static/merger.py |
    | LLM Transformer (CodeLlama-7B) | reasoner/llm_engine.py |
    | Model Quantization (Q4_K_M) | reasoner/llm_engine.py |
    | Chain-of-Thought Reasoning | reasoner/chain_of_thought.py |
    | SMT Theorem Proving (Z3) | verifier/z3_verifier.py |
    | LLM-guided Fuzzing | fuzzer/ |
    | GraphSAGE Neural Network | vuln_gnn/model.py |
    | HMAC-SHA256 Cryptographic Signing | audit/audit_logger.py |

    ### GitHub
    https://github.com/Programmer-Develops/kavach-aidr

    ### Sovereignty Pledge
    - Zero foreign APIs
    - All models: Microsoft (USA) or Meta (USA)
    - Runs fully offline — air-gapped
    - No Chinese LLMs (DeepSeek, Qwen, etc.)
    """)


# ══════════════════════════════════════════════════════════════════════════════
# DB helpers
# ══════════════════════════════════════════════════════════════════════════════

def _load_db_stats(db_path: Path) -> dict:
    if not db_path.exists():
        return {}
    try:
        conn = sqlite3.connect(db_path)
        cur  = conn.cursor()
        stats = {}
        try:
            cur.execute("SELECT COUNT(*) FROM scan_runs")
            stats["total_runs"] = cur.fetchone()[0]
        except: pass
        try:
            cur.execute("SELECT COUNT(*) FROM findings")
            stats["total_findings"] = cur.fetchone()[0]
        except: pass
        try:
            cur.execute("SELECT COUNT(*) FROM patch_results WHERE success=1")
            stats["patches"] = cur.fetchone()[0]
        except: pass
        try:
            cur.execute("SELECT COUNT(*) FROM audit_events")
            stats["audit_events"] = cur.fetchone()[0]
        except: pass
        conn.close()
        return stats
    except Exception:
        return {}


def _load_recent_runs(db_path: Path) -> list:
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(db_path)
        cur  = conn.cursor()
        cur.execute(
            "SELECT run_id, target_path, started_at, status "
            "FROM scan_runs ORDER BY started_at DESC LIMIT 10"
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {"Run ID": r[0], "Target": Path(r[1]).name,
             "Started": r[2][:19] if r[2] else "", "Status": r[3]}
            for r in rows
        ]
    except Exception:
        return []


def _load_all_findings(db_path: Path) -> list:
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(db_path)
        cur  = conn.cursor()
        cur.execute(
            "SELECT run_id, finding_id, vuln_type, severity, filepath, lineno, score "
            "FROM findings ORDER BY score DESC LIMIT 200"
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "Run ID"  : r[0],
                "Finding" : r[1],
                "vuln_type": r[2],
                "severity": r[3],
                "File"    : Path(r[4]).name if r[4] else "",
                "Line"    : r[5],
                "Score"   : round(float(r[6]), 3) if r[6] else 0,
            }
            for r in rows
        ]
    except Exception:
        return []


def _load_audit_events(db_path: Path) -> list:
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(db_path)
        cur  = conn.cursor()
        cur.execute(
            "SELECT run_id, event_type, timestamp, seq_num "
            "FROM audit_events ORDER BY timestamp DESC LIMIT 500"
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {"run_id": r[0], "event_type": r[1],
             "timestamp": r[2][:19] if r[2] else "", "seq": r[3]}
            for r in rows
        ]
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not STREAMLIT_OK:
        print("Streamlit not installed. Run: pip install streamlit plotly pandas")
        sys.exit(1)

    setup_page()
    page = render_sidebar()

    if page == "🏠 Overview":
        page_overview()
    elif page == "🔍 Run Scan":
        page_run_scan()
    elif page == "📊 Findings":
        page_findings()
    elif page == "🧠 VulnGNN":
        page_vuln_gnn()
    elif page == "📋 Audit Trail":
        page_audit()
    elif page == "ℹ️ About":
        page_about()


if __name__ == "__main__":
    main()
