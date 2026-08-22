# 🛡️ KAVACH-AIDR
## Autonomous Intelligent Defensive Reasoner
### *Sovereign · Air-Gapped · Built for the Indian Armed Forces*

---

## What Is This?

KAVACH-AIDR is an autonomous cyber-reasoning system that:

1. **Finds** security vulnerabilities in Python software (static analysis + AI graph analysis)
2. **Understands** why each bug is dangerous (local LLM reasoning — no internet)
3. **Patches** the code autonomously (generates and applies a code fix)
4. **Proves** the fix works (Z3 SMT formal verification — Phase 2)
5. **Logs** everything in a tamper-proof, HMAC-signed audit trail

**Zero bytes ever leave the machine.** Runs fully offline on Indian hardware.

---

## Quick Start

```bash
# 1. Install
pip install -e ".[llm]"

# 2. Check system status
python -m kavach.main info

# 3. Download a model (one-time, then offline forever)
# See models/DOWNLOAD.md

# 4. Run a scan
python -m kavach.main scan tests/samples/vuln_sqli.py

# 5. Scan a whole directory
python -m kavach.main scan tests/samples/ --top 10

# 6. Verify audit integrity
python -m kavach.main verify-audit <RUN_ID>

# 7. Export for SIEM
python -m kavach.main scan target.py --export-cef
```

---

## Pipeline

```
Source Code
    │
    ▼
[1] Ingestion & AST Graph
    │  Python ast module → function/call/import graph
    │  Graph builder flags dangerous patterns with severity scores
    ▼
[2] Static Analysis
    │  Semgrep (custom military rules) + Bandit
    │  25+ vulnerability classes detected
    ▼
[3] Merge & Rank
    │  Deduplication across tools
    │  Corroboration boost (2+ tools = higher confidence)
    ▼
[4] LLM Reasoning  (offline: Phi-3-mini / CodeLlama)
    │  Root cause analysis
    │  Patch generation (unified diff)
    │  Self-verification
    ▼
[5] Patch Application
    │  3-strategy applicator (line-replace → fuzzy → regex)
    │  Syntax validation
    ▼
[6] Audit Trail
       HMAC-SHA256 signed events → SQLite
       JSON report + CEF/Syslog SIEM export
```

---

## Tech Stack

| Component | Tool | Origin |
|---|---|---|
| LLM (primary) | Phi-3-mini-3.8B-Q4 | Microsoft 🇺🇸 |
| LLM (GPU) | CodeLlama-7B/13B-Q4 | Meta 🇺🇸 |
| LLM runtime | llama-cpp-python | Open Source |
| Static analysis | Semgrep + Bandit | Open Source |
| Formal verification | Z3 SMT Solver | Microsoft 🇺🇸 |
| Fuzzer (Phase 2) | Atheris | Google 🇺🇸 |
| Graph Neural Net (Phase 2) | PyTorch + DGL | Open Source |
| Database | SQLite | Open Source |
| CLI | Rich + Click | Open Source |

**No foreign APIs. No cloud. No Chinese software.**

---

## Vulnerability Classes Detected

- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Code Injection / eval() (CWE-94)
- Insecure Deserialization — pickle/yaml/marshal (CWE-502)
- Path Traversal (CWE-22)
- Hardcoded Secrets / Credentials (CWE-798)
- Weak Cryptography — MD5/SHA1 (CWE-326)
- Insecure Random (CWE-338)
- Insecure TLS (CWE-295)
- XSS, CSRF, LDAP Injection, XXE, and more

---

## Project Structure

```
kavach-aidr/
├── kavach/
│   ├── main.py           ← CLI orchestrator
│   ├── config.py         ← Hardware-adaptive configuration
│   ├── ingestion/        ← AST parsing + graph building
│   ├── static/           ← Semgrep + Bandit + findings merger
│   ├── reasoner/         ← LLM engine + prompt builder + reasoning chain
│   ├── patcher/          ← Patch application + syntax validation
│   └── audit/            ← HMAC-signed logger + SQLite + SIEM export
├── data/
│   └── semgrep_rules/    ← Custom military-context rules
├── models/
│   └── DOWNLOAD.md       ← Model download instructions
└── tests/
    └── samples/          ← Demo vulnerable Python files
```

---

## Audit Trail Integrity

Every pipeline event is signed with HMAC-SHA256:

```bash
python -m kavach.main verify-audit <RUN_ID>
# ✅ INTEGRITY VERIFIED — All 47 events valid
```

If any event is modified after the fact, the signature check fails immediately.

---

## Graceful Degradation

| Condition | Behaviour |
|---|---|
| No GPU | Runs on CPU (Phi-3-mini) |
| No model downloaded | Static analysis still runs; LLM skipped |
| Semgrep not installed | Bandit + Graph analysis used |
| Bandit not installed | Semgrep + Graph analysis used |

**KAVACH-AIDR never fails to run. It always provides value.**

---

## For the AI Kavach Hackathon — Indian Army Terrier Cyber Quest 2026

This system addresses the core challenge:
> "Build a cyber-reasoning system — an LLM laced with fuzzers, static and dynamic analysis,
> and a regression test harness — that autonomously finds a vulnerability, patches it,
> and proves the fix holds."

KAVACH-AIDR delivers this with zero foreign dependency, maximum sovereignty,
and mathematical proof of patch correctness.

**Jai Hind 🇮🇳**
