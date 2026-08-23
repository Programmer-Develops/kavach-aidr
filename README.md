# 🛡️ KAVACH-AIDR

### Autonomous Intelligent Defensive Reasoner
**Defensive by Design · Sovereign Cyber Reasoning · Indian Armed Forces**

> *Kavach (कवच) = Shield — A fully autonomous cyber-reasoning engine combining static/dynamic program analysis, Graph Neural Networks, Large Language Models, SMT formal verification, and regression test generation.*

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Formal Verification](https://img.shields.io/badge/Formal%20Verification-Z3%20SMT-purple?style=for-the-badge)]()
[![Sovereignty](https://img.shields.io/badge/Sovereign-Air--Gapped-orange?style=for-the-badge)]()

---

## Overview

**KAVACH-AIDR** is an autonomous, air-gapped cyber-reasoning system engineered for critical national security and defense infrastructure. It operates end-to-end without requiring external network connectivity or cloud APIs:

1. **Vulnerability Discovery**: Multi-engine static analysis (Semgrep with defense rule sets, AST-based control-flow graphs, Bandit) combined with Graph Neural Networks (VulnGNN).
2. **Root Cause Analysis**: Local Chain-of-Thought (CoT) LLM reasoning (quantized CodeLlama-7B / Phi-3-mini running via `llama.cpp`) to diagnose exploit paths in mission-critical software.
3. **Autonomous Patch Generation**: Context-aware remediation synthesizing minimal, non-breaking security patches with strict syntax and AST safety validation.
4. **SMT Formal Verification**: Mathematical proof of safety using Microsoft Z3 theorem prover (`UNSAT` post-patch verification).
5. **Dynamic Fuzzing Validation**: Execution-guided smart fuzzer with payload mutation and crash triage to verify exploit neutralization at runtime.
6. **Regression Test Harness**: Automated generation of Pytest test suites locking in verified remediations and ensuring functional integrity.
7. **Tamper-Evident Auditability**: Cryptographic HMAC-SHA256 logging with SIEM (CEF/JSON) export for defense forensic compliance.

---

## System Architecture

```
                                  Source Code File / Project
                                              │
                     ┌────────────────────────┼────────────────────────┐
                     ▼                        ▼                        ▼
             AST Code Graph           Semgrep Engine            Bandit Analyzer
          (Control/Data Flow)      (Custom Defense Rules)     (Python Security Linter)
                     │                        │                        │
                     └────────────────────────┼────────────────────────┘
                                              ▼
                                   Ensemble Findings Merger
                                (Corroboration & Risk Scoring)
                                              │
                                              ▼
                                    VulnGNN Analyzer
                                (GraphSAGE Architecture)
                                              │
                                              ▼
                                Local LLM Cyber Reasoner
                            (Offline CodeLlama-7B / Phi-3)
                                              │
                                 ┌────────────┴────────────┐
                                 ▼                         ▼
                         Root Cause Diagnosis       Patch Generator
                                                           │
                                                           ▼
                                                    Syntax Validator
                                                           │
                                ┌──────────────────────────┼──────────────────────────┐
                                ▼                          ▼                          ▼
                       Z3 SMT Verifier               Smart Fuzzer             Regression Harness
                     (Mathematical Proof)         (Dynamic Execution)        (Auto-generated Tests)
                                │                          │                          │
                         [PROVED / UNSAT]           [FIX CONFIRMED]            [SUITE PASS]
                                └──────────────────────────┼──────────────────────────┘
                                                           ▼
                                               HMAC-SHA256 Audit Trail
                                              (Tamper-Evident Forensics)
```

---

## Core Engineering Modules

| Component | Technology | Description |
|---|---|---|
| **AST Ingestion & Graph Builder** | Python `ast`, Graph Theory | Builds control-flow and data-dependency graphs with automated risk propagation. |
| **Static Analysis Ensemble** | Semgrep, Bandit, AST Rules | Multi-tool aggregation with set-similarity deduplication and confidence scoring. |
| **Deep Graph Reasoner (VulnGNN)** | GraphSAGE GNN | Node-level feature extraction (16 dimensions) assessing vulnerability risk on code graphs. |
| **Local LLM Reasoner** | GGUF Q4_K_M (Meta / Microsoft) | Offline Chain-of-Thought engine generating structured root-cause analyses and patches. |
| **Autonomous Patcher** | AST Validator, Unified Diff | Multi-strategy patch applicator with automated syntax validation and regression guardrails. |
| **Formal Verification Engine** | Microsoft Z3 SMT Solver | Translates vulnerabilities into logical constraints and proves safety mathematically (`UNSAT`). |
| **Dynamic Execution Fuzzer** | Payload Mutation, Importlib | Runtime fuzzing with 50+ curated payloads, dynamic execution, and crash triage. |
| **Regression Harness** | Pytest, Test Generator | Generates 4-tier functional, edge-case, boundary, and exploit-resistance tests. |
| **Cryptographic Audit** | HMAC-SHA256, SQLite, CEF | Cryptographically signs every decision, finding, and patch for forensic non-repudiation. |

---

## Formal Verification & Mathematical Proof

KAVACH-AIDR integrates the **Microsoft Z3 SMT Solver** to provide formal proofs that generated patches fully neutralize vulnerability conditions rather than merely suppressing surface symptoms:

$$\text{Pre-Patch State:} \quad \text{Constraint}(V) \land \text{Source}(\text{Orig}) \implies \mathbf{SAT} \quad (\text{Vulnerability Confirmed})$$

$$\text{Post-Patch State:} \quad \text{Constraint}(V) \land \text{Source}(\text{Patched}) \implies \mathbf{UNSAT} \quad (\text{Vulnerability Formally Proved Impossible})$$

Supported SMT formal constraint encodings:
- **SQL Injection**: Formal proof that untrusted input variables cannot alter the abstract syntax tree of SQL queries.
- **Command Injection**: Formal proof of argument isolation preventing subshell spawning and pipe chaining.
- **Path Traversal**: Canonical path confinement proofs bounding file operations to designated directory subtrees.
- **Hardcoded Secrets & Weak Crypto**: Symbolic entropy and cipher-suite constraint validation.

---

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Programmer-Develops/kavach-aidr.git
cd kavach-aidr

# Install dependencies and package
pip install -r requirements.txt
pip install -e .
```

### 2. Run Comprehensive Verification Suite

```bash
python demo.py
```

### 3. Scan a Target File or Directory

```bash
# Standard autonomous scan and patch
python -m kavach.main scan path/to/source.py

# Deep scan with Z3 formal verification, dynamic fuzzing, and VulnGNN
python -m kavach.main scan path/to/source.py --deep --top 5

# Directory-level recursive scan
python -m kavach.main scan path/to/project_dir/ --deep
```

### 4. Verify Cryptographic Audit Trail

```bash
python -m kavach.main verify-audit <RUN_ID>
```

### 5. Launch Interactive Web Dashboard

```bash
streamlit run kavach/ui/dashboard.py
```

### 6. Run Automated Test Suite

```bash
python -m pytest tests/ -v
```

---

## CLI Reference

```
Usage: python -m kavach.main [COMMAND] [OPTIONS]

Commands:
  scan          Run autonomous vulnerability discovery, reasoning, and patching
  verify-audit  Cryptographically verify the HMAC-SHA256 signature chain of a scan run
  info          Display local hardware profile, available models, and static tool status

Scan Options:
  TARGET              File or directory path to scan
  -m, --model         Force LLM model (phi3-mini | codellama-7b | codellama-13b)
  -n, --top INTEGER   Number of top-priority findings to reason over [default: 5]
  -o, --output PATH   Directory for exported JSON and CEF reports [default: reports/]
  --deep              Enable multi-layer verification (Z3 SMT proof + Smart Fuzzer + VulnGNN)
  --no-patch          Perform analysis and formal verification only without applying code patches
  -v, --verbose       Enable detailed diagnostic and reasoning output
  --export-cef        Export Common Event Format (CEF) logs for SIEM ingestion
```

---

## Repository Structure

```
kavach-aidr/
├── demo.py                         # Automated end-to-end verification showcase
├── kavach/
│   ├── main.py                     # CLI entry point and orchestration engine
│   ├── config.py                   # Hardware detection and air-gapped configuration
│   ├── ingestion/
│   │   ├── parser.py               # AST source code parser and call extractor
│   │   └── graph_builder.py        # Code graph construction and taint analysis
│   ├── static/
│   │   ├── semgrep_runner.py       # Custom defense-rules static analysis runner
│   │   ├── bandit_runner.py        # AST security linter integration
│   │   └── merger.py               # Ensemble findings merger and deduplicator
│   ├── reasoner/
│   │   ├── llm_engine.py           # Offline llama.cpp inference engine
│   │   ├── chain_of_thought.py     # Multi-step Chain-of-Thought reasoning
│   │   ├── prompt_builder.py       # Defense-domain security prompt synthesis
│   │   └── patch_generator.py      # Unified diff parsing and patch extraction
│   ├── patcher/
│   │   ├── patch_applicator.py     # Multi-strategy atomic patch applicator
│   │   └── syntax_validator.py     # AST validation and regression prevention
│   ├── verifier/
│   │   ├── constraint_builder.py   # SMT constraint mapper for vulnerability classes
│   │   └── z3_verifier.py          # Microsoft Z3 formal theorem prover
│   ├── fuzzer/
│   │   ├── mutation_engine.py      # Curated payloads and mutation operators
│   │   ├── seed_generator.py       # Semantic seed generator
│   │   ├── runner.py               # Dynamic runtime execution and comparison
│   │   └── crash_triager.py        # Exception classification and deduplication
│   ├── regression/
│   │   ├── test_generator.py       # Automated Pytest regression suite synthesizer
│   │   └── test_runner.py          # Pre/post test execution and differential analysis
│   ├── vuln_gnn/
│   │   ├── model.py                # GraphSAGE Graph Neural Network architecture
│   │   ├── features.py             # 16-dimensional node feature extraction
│   │   ├── predict.py              # High-level graph inference interface
│   │   └── eval_vuln_gnn.py        # Empirical evaluation and metric calculator
│   ├── audit/
│   │   ├── db.py                   # SQLite forensic audit storage schema
│   │   ├── audit_logger.py         # HMAC-SHA256 event signing and validation
│   │   └── siem_exporter.py        # CEF, JSON, and Syslog format exporters
│   └── ui/
│       └── dashboard.py            # Streamlit operations dashboard
├── data/semgrep_rules/             # Custom vulnerability pattern definitions
│   ├── injection.yml
│   ├── secrets.yml
│   ├── crypto_weak.yml
│   └── memory_safety.yml
├── tests/
│   ├── test_pipeline.py            # Automated unit test suite (33 tests)
│   └── samples/                    # Curated benchmark test cases
├── models/
│   └── DOWNLOAD.md                 # Offline model acquisition and setup guide
├── requirements.txt
└── setup.py
```

---

## Sovereignty & Operational Security Specification

KAVACH-AIDR is designed strictly adhering to defense-grade data isolation protocols:

- **100% Air-Gapped Operation**: Zero outbound network requests at runtime. All analysis, reasoning, patching, and verification execute locally on the host machine.
- **Sovereign Model Heritage**: Compatible with open-weights models from established, non-adversarial research sources (Meta CodeLlama, Microsoft Phi-3). No unvetted third-party cloud API dependencies.
- **Cryptographic Audit Integrity**: All telemetry, detected findings, LLM reasoning traces, and patch actions are signed with HMAC-SHA256 into a tamper-evident audit ledger.
- **Hardware Agnostic**: Automatically scales from resource-constrained field laptops (CPU-only with 4-bit quantization) to dedicated GPU workstations (CUDA-accelerated layer offloading).

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
