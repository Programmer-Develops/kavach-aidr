# 🛡️ KAVACH-AIDR

### Autonomous Intelligent Defensive Reasoner
**Built for AI Kavach — Indian Army Terrier Cyber Quest 2026**

> *Kavach (कवच) = Shield — Defensive by design.*

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Phase%202%20Complete-brightgreen?style=for-the-badge)]()
[![Sovereignty](https://img.shields.io/badge/Sovereign-Air--Gapped-orange?style=for-the-badge)]()

---

## What is KAVACH-AIDR?

KAVACH-AIDR is a **cyber-reasoning system** that autonomously:

1. **Finds** vulnerabilities in Python code
2. **Understands** the root cause using an LLM
3. **Patches** the code autonomously
4. **Proves** the fix holds — mathematically, using Z3 formal verification
5. **Confirms** the fix with a smart fuzzer
6. **Locks** it in with auto-generated regression tests
7. **Scores** the codebase with a Graph Neural Network

Everything runs **offline**. No internet. No foreign cloud APIs. Sovereign.

---

## Architecture

```
Input Code (.py)
       │
       ├──► AST Parser ──► Code Graph ──► Risk Score
       │
       ├──► Semgrep (60+ rules) ──┐
       ├──► Bandit (B-codes)    ──┼──► Ensemble Merger ──► Ranked Findings
       └──► Code Graph Analyser ──┘                │
                                                   ▼
                                        LLM Reasoner (CodeLlama-7B)
                                          │              │
                                     Root Cause    Patch Generation
                                                        │
                                              Syntax Validator
                                                        │
                              ┌─────────────────────────┼─────────────────────┐
                              ▼                         ▼                     ▼
                        Z3 Formal Verifier        Smart Fuzzer           VulnGNN
                        (SMT Theorem Proof)       (LLM-guided)        (GraphSAGE)
                              │                         │
                         PROVED ✅               FIX CONFIRMED ✅
                                                        │
                                          HMAC-SHA256 Audit Trail
```

---

## AI/ML Techniques

| # | Technique | Module | What it does |
|---|---|---|---|
| 1 | **Abstract Syntax Tree** | `ingestion/parser.py` | Parse code into logical structure |
| 2 | **Graph Theory + Taint Analysis** | `ingestion/graph_builder.py` | Track dangerous data flows |
| 3 | **Rule-based Expert System** | `static/` | 60+ security pattern rules |
| 4 | **Ensemble Method** | `static/merger.py` | Combine 3 tools, boost corroborated findings |
| 5 | **LLM Transformer (CodeLlama-7B)** | `reasoner/llm_engine.py` | Reason about bugs, generate patches |
| 6 | **Model Quantization (Q4_K_M)** | `config.py` | Run 7B model on 4GB VRAM, offline |
| 7 | **Chain-of-Thought Reasoning** | `reasoner/chain_of_thought.py` | Multi-step LLM analysis |
| 8 | **Prompt Engineering** | `reasoner/prompt_builder.py` | Military-context threat analysis |
| 9 | **SMT Theorem Proving (Z3)** | `verifier/z3_verifier.py` | Mathematical proof patch works |
| 10 | **LLM-guided Fuzzing** | `fuzzer/` | Smart attack payload generation |
| 11 | **GraphSAGE Neural Network** | `vuln_gnn/model.py` | Vulnerability probability scoring |
| 12 | **HMAC-SHA256 Signing** | `audit/audit_logger.py` | Tamper-proof audit trail |

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

### 2. One-command demo (for judges)
```bash
python demo.py
```

### 3. Phase 1 scan — basic pipeline
```bash
python -m kavach.main scan tests/samples/vuln_sqli.py
```

### 4. Phase 2 deep scan — Z3 + Fuzzer + GNN
```bash
python -m kavach.main scan tests/samples/vuln_sqli.py --deep --top 3
```

### 5. Scan a directory
```bash
python -m kavach.main scan my_army_software/ --top 10 --deep
```

### 6. Verify audit integrity
```bash
python -m kavach.main verify-audit <RUN_ID>
```

### 7. System info
```bash
python -m kavach.main info
```

### 8. Web Dashboard (Streamlit)
```bash
pip install streamlit plotly pandas
streamlit run kavach/ui/dashboard.py
```

### 9. Check VulnGNN accuracy
```bash
python -m kavach.vuln_gnn.eval_vuln_gnn
```

---

## CLI Commands

```
python -m kavach.main scan TARGET [OPTIONS]

  TARGET          Path to .py file or directory

  -m, --model     Force model: phi3-mini | codellama-7b | codellama-13b
  -n, --top       Top findings to reason over (default: 5)
  -o, --output    Report output directory
  --no-patch      Analysis only — skip patching
  --deep          Phase 2: Z3 formal verification + fuzzer + VulnGNN
  -v, --verbose   Verbose LLM output
  --export-cef    Export CEF file for SIEM integration
```

---

## Phase 1 — Core Pipeline ✅

**Status:** Complete. Live-tested. 25-second runtime.

- Multi-tool static analysis (Semgrep + Bandit + Code Graph)
- LLM-powered root cause explanation
- Autonomous patch generation
- Syntax validation + no-new-vulns check
- HMAC-SHA256 signed tamper-proof audit trail
- SIEM export (CEF format)
- SQLite audit database (5 tables)

**Live test result:**
- Target: `tests/samples/vuln_sqli.py`
- 7 findings (HIGH: 4, MEDIUM: 3)
- 15 HMAC-signed audit events — all verified
- Runtime: 24.9s | Exit code: 0

---

## Phase 2 — Intelligence Layer ✅

**Status:** Complete. All modules running.

### Z3 Formal Verifier (`kavach/verifier/`)
Uses Microsoft's Z3 SMT solver to **mathematically prove** that a patch
eliminates a vulnerability. Not heuristic — mathematical certainty.

```
Pre-patch:  Z3 finds SAT      → BUG EXISTS (confirmed)
Post-patch: Z3 finds UNSAT    → BUG IMPOSSIBLE (proved)
Verdict: PROVED ✅
```

Supports: SQL_INJECTION, COMMAND_INJECTION, PATH_TRAVERSAL,
HARDCODED_SECRET, CODE_INJECTION

### Smart Fuzzer (`kavach/fuzzer/`)
LLM-guided fuzzing with 50+ curated military attack payloads:
- SQL injection patterns (`' OR '1'='1`, `'; DROP TABLE--`)
- Command injection (`; ls -la`, `| cat /etc/passwd`)
- Path traversal (`../../../etc/passwd`, `..%2f..%2f`)
- Pre/post patch comparison — confirms fix works behaviourally

### VulnGNN (`kavach/vuln_gnn/`)
GraphSAGE architecture Graph Neural Network that scores vulnerability
probability from 0–100% by analysing the code's call graph.

**Evaluation on 10 samples:**
```
Accuracy:  70%    Precision: 57.1%
Recall:   100%    F1 Score:  72.7%  →  Grade: GOOD
```
100% Recall = caught every single real vulnerability.

### Regression Harness (`kavach/regression/`)
Auto-generates pytest test suites from fuzzer crash inputs.
Tests prove the fix holds and no functionality was broken.

---

## Model Selection

| Model | VRAM | Speed | Recommended for |
|---|---|---|---|
| `phi3-mini` (Microsoft) | CPU-safe | Fast | Air-gapped systems with no GPU |
| `codellama-7b` (Meta) | 4 GB | Medium | RTX 3050/3060 — **default** |
| `codellama-13b` (Meta) | 8 GB | Slower | RTX 3080+ |

**Sovereignty note:** Only US models used. No Chinese LLMs (no DeepSeek, no Qwen).

Download models: see [`models/DOWNLOAD.md`](models/DOWNLOAD.md)

---

## Project Structure

```
kavach-aidr/
├── demo.py                         ← One-command demo for judges
├── kavach/
│   ├── main.py                     ← CLI orchestrator (scan/verify-audit/info)
│   ├── config.py                   ← Hardware detection, model selection
│   ├── ingestion/
│   │   ├── parser.py               ← AST code parser
│   │   └── graph_builder.py        ← Code graph + taint analysis
│   ├── static/
│   │   ├── semgrep_runner.py       ← Semgrep integration
│   │   ├── bandit_runner.py        ← Bandit integration
│   │   └── merger.py               ← Ensemble merger + corroboration
│   ├── reasoner/
│   │   ├── llm_engine.py           ← CodeLlama/Phi-3 inference
│   │   ├── chain_of_thought.py     ← Multi-step reasoning
│   │   ├── prompt_builder.py       ← Military-context prompts
│   │   └── patch_generator.py      ← Patch extraction from LLM output
│   ├── patcher/
│   │   ├── patch_applicator.py     ← 3-strategy patch application
│   │   └── syntax_validator.py     ← Validate patch syntax + safety
│   ├── verifier/                   ← [Phase 2]
│   │   ├── constraint_builder.py   ← Vuln pattern → SMT constraints
│   │   └── z3_verifier.py          ← Z3 theorem prover
│   ├── fuzzer/                     ← [Phase 2]
│   │   ├── mutation_engine.py      ← 50+ attack payloads
│   │   ├── seed_generator.py       ← LLM-guided seed generation
│   │   ├── runner.py               ← Pre/post patch comparison
│   │   └── crash_triager.py        ← Crash classification + dedup
│   ├── regression/                 ← [Phase 2]
│   │   ├── test_generator.py       ← Auto-generate pytest tests
│   │   └── test_runner.py          ← Run + compare test suites
│   ├── vuln_gnn/                   ← [Phase 2]
│   │   ├── model.py                ← GraphSAGE GNN
│   │   ├── features.py             ← Code graph → feature vectors
│   │   ├── predict.py              ← Inference entry point
│   │   └── eval_vuln_gnn.py        ← Accuracy evaluation
│   ├── audit/
│   │   ├── db.py                   ← SQLite schema (5 tables)
│   │   ├── audit_logger.py         ← HMAC-SHA256 event signing
│   │   └── siem_exporter.py        ← CEF/JSON/Syslog export
│   └── ui/                         ← [Phase 3]
│       └── dashboard.py            ← Streamlit web dashboard
├── data/semgrep_rules/             ← Custom security rules
│   ├── injection.yml
│   ├── secrets.yml
│   ├── crypto_weak.yml
│   └── memory_safety.yml
├── tests/samples/                  ← Vulnerable code for testing
│   ├── vuln_sqli.py
│   ├── vuln_pathtraversal.py
│   ├── vuln_deserialization.py
│   └── vuln_secrets.py
├── models/DOWNLOAD.md              ← How to download LLM models
├── requirements.txt
└── setup.py
```

---

## Sovereignty Statement

KAVACH-AIDR is designed to operate in **fully air-gapped** environments:
- ✅ No internet dependency at runtime
- ✅ All LLMs: US-origin only (Meta, Microsoft)
- ✅ No Chinese models (DeepSeek ❌, Qwen ❌, Baichuan ❌)
- ✅ All dependencies: open-source, auditable
- ✅ Cryptographic audit trail — tamper-evident
- ✅ Can run on a laptop with no external network

---

## Team

Built for **AI Kavach — Indian Army Terrier Cyber Quest 2026**

Registration: https://www.cyberchallenge.in/registration/ai-kavach

---

*KAVACH — because the best defence is a shield that thinks.*
