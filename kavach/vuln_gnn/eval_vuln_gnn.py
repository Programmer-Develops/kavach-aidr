"""
eval_vuln_gnn.py — Evaluate VulnGNN accuracy on a labeled dataset.

Labels:
  1 = Vulnerable   (should predict is_vulnerable=True,  prob > 0.3)
  0 = Safe/Clean   (should predict is_vulnerable=False, prob < 0.3)

We use:
  POSITIVE (vulnerable=1): our 4 sample files
  NEGATIVE (safe=0):       small inline clean Python snippets

Metrics computed:
  Accuracy, Precision, Recall, F1, Confusion Matrix, per-file scores
"""

import sys, io, os
# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from pathlib import Path
from kavach.ingestion.parser import parse_source
from kavach.ingestion.graph_builder import build_graph
from kavach.vuln_gnn.predict import predict_vulnerability

# ── Labeled dataset ────────────────────────────────────────────────────────────

# POSITIVE: Known vulnerable files (label = 1)
# Resolve from project root (kavach-aidr/) regardless of where script is run from
_HERE = Path(__file__).resolve()
# Walk up until we find tests/samples
for _parent in [_HERE.parent, _HERE.parent.parent, _HERE.parent.parent.parent]:
    _candidate = _parent / "tests" / "samples"
    if _candidate.exists():
        BASE = _candidate
        break
else:
    BASE = Path("tests/samples")  # fallback: run from project root

VULNERABLE_FILES = [
    (BASE / "vuln_sqli.py",          "SQL Injection"),
    (BASE / "vuln_pathtraversal.py", "Path Traversal + CMDi"),
    (BASE / "vuln_deserialization.py","Insecure Deserialization"),
    (BASE / "vuln_secrets.py",       "Hardcoded Secrets + Weak Crypto"),
]

# NEGATIVE: Clean Python snippets (label = 0)
SAFE_SNIPPETS = [
    ("safe_db_query", """
import sqlite3

def get_user(username: str) -> dict:
    \"\"\"Safe parameterised DB query.\"\"\"
    conn = sqlite3.connect("army.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return {"user": row}

def authenticate(username: str, password_hash: str) -> bool:
    \"\"\"Authenticate with hashed password.\"\"\"
    conn = sqlite3.connect("army.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM users WHERE username = ? AND password_hash = ?",
        (username, password_hash)
    )
    return cursor.fetchone() is not None
"""),

    ("safe_file_access", """
import os
from pathlib import Path

BASE_DIR = Path("/var/army_data/reports").resolve()

def read_report(filename: str) -> str:
    \"\"\"Safe file access — path validated against base directory.\"\"\"
    safe_path = (BASE_DIR / filename).resolve()
    if not str(safe_path).startswith(str(BASE_DIR)):
        raise ValueError("Path traversal attempt detected")
    if not safe_path.exists():
        raise FileNotFoundError(f"Report not found: filename")
    return safe_path.read_text(encoding="utf-8")

def list_reports() -> list:
    \"\"\"List only files within base directory.\"\"\"
    return [f.name for f in BASE_DIR.iterdir() if f.is_file()]
"""),

    ("safe_subprocess", """
import subprocess
import shlex

ALLOWED_COMMANDS = {"ping", "traceroute", "nslookup"}

def run_network_tool(tool: str, target: str) -> str:
    \"\"\"Safely run only whitelisted network tools.\"\"\"
    if tool not in ALLOWED_COMMANDS:
        raise ValueError(f"Tool not allowed: {tool}")
    # shlex.quote prevents shell injection
    safe_target = shlex.quote(target)
    result = subprocess.run(
        [tool, safe_target],
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )
    return result.stdout
"""),

    ("safe_crypto", """
import hashlib
import secrets
import os

def hash_password(password: str) -> str:
    \"\"\"Secure password hashing with SHA-256 + salt.\"\"\"
    salt = secrets.token_hex(32)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password: str, stored: str) -> bool:
    \"\"\"Verify password against stored hash.\"\"\"
    salt, hashed = stored.split(":", 1)
    return hashlib.sha256((salt + password).encode()).hexdigest() == hashed

def generate_token(length: int = 32) -> str:
    \"\"\"Cryptographically secure token.\"\"\"
    return secrets.token_urlsafe(length)

# Load secrets from environment — never hardcoded
API_KEY   = os.environ.get("API_KEY", "")
DB_PASS   = os.environ.get("DB_PASSWORD", "")
"""),

    ("safe_serialization", """
import json
import ast

def load_config(data: str) -> dict:
    \"\"\"Safe JSON deserialization.\"\"\"
    return json.loads(data)

def parse_expression(expr: str):
    \"\"\"Safe literal evaluation — no code execution.\"\"\"
    return ast.literal_eval(expr)

def process_request(payload: bytes) -> dict:
    \"\"\"Always decode as JSON, never pickle.\"\"\"
    return json.loads(payload.decode("utf-8"))
"""),

    ("safe_input_validation", """
import re
from typing import Optional

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,32}$')
EMAIL_RE    = re.compile(r'^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$')

def validate_username(username: str) -> Optional[str]:
    \"\"\"Strictly validate username — only alphanumeric + underscore.\"\"\"
    if not USERNAME_RE.match(username):
        return None
    return username

def validate_email(email: str) -> Optional[str]:
    \"\"\"Validate email format.\"\"\"
    if not EMAIL_RE.match(email):
        return None
    return email.lower()

def sanitise_filename(name: str) -> str:
    \"\"\"Remove all dangerous characters from filename.\"\"\"
    return re.sub(r'[^a-zA-Z0-9_\\-\\.]', '', name)[:64]
"""),
]

# ── Evaluation ─────────────────────────────────────────────────────────────────

def run_evaluation():
    results = []

    print("=" * 70)
    print("  KAVACH-AIDR — VulnGNN Accuracy Evaluation")
    print("=" * 70)

    # ── Positive (vulnerable) files ────────────────────────────────────────
    print("\n[POSITIVE — should predict VULNERABLE]\n")
    for filepath, description in VULNERABLE_FILES:
        try:
            source = filepath.read_text(encoding="utf-8")
            parsed = parse_source(source, str(filepath))
            graph  = build_graph(parsed)
            pred   = predict_vulnerability(graph)

            # Use 0.3 threshold (rule-based scorer max ~0.5 on small files)
            is_vuln = pred.vulnerability_prob > 0.3
            correct = is_vuln   # True = correct for positives
            results.append({
                "name"       : filepath.name,
                "label"      : 1,
                "predicted"  : 1 if is_vuln else 0,
                "prob"       : pred.vulnerability_prob,
                "confidence" : pred.confidence,
                "correct"    : correct,
                "type"       : description,
            })

            status = "[CORRECT]" if correct else "[MISSED ]"
            print(f"  {status}  {filepath.name}")
            print(f"           Prob: {pred.vulnerability_prob:.1%}  |  "
                  f"Confidence: {pred.confidence}  |  {description}")
            print(f"           {pred.reasoning[:80]}...")
            print()

        except Exception as e:
            print(f"  [ERROR]  {filepath.name}: {e}")

    # ── Negative (safe) snippets ───────────────────────────────────────────
    print("\n[NEGATIVE — should predict SAFE]\n")
    for name, source in SAFE_SNIPPETS:
        try:
            parsed = parse_source(source, name + ".py")
            graph  = build_graph(parsed)
            pred   = predict_vulnerability(graph)

            is_vuln = pred.vulnerability_prob > 0.3
            correct = not is_vuln   # False positive = incorrect for negatives
            results.append({
                "name"       : name + ".py",
                "label"      : 0,
                "predicted"  : 1 if is_vuln else 0,
                "prob"       : pred.vulnerability_prob,
                "confidence" : pred.confidence,
                "correct"    : correct,
                "type"       : "Safe code",
            })

            status = "[CORRECT      ]" if correct else "[FALSE POSITIVE]"
            print(f"  {status}  {name}.py")
            print(f"           Prob: {pred.vulnerability_prob:.1%}  |  Confidence: {pred.confidence}")
            print()

        except Exception as e:
            print(f"  [ERROR]  {name}: {e}")

    # ── Compute metrics ────────────────────────────────────────────────────
    print("=" * 70)
    print("  METRICS")
    print("=" * 70)

    total = len(results)
    if total == 0:
        print("No results.")
        return

    correct_count = sum(1 for r in results if r["correct"])
    accuracy      = correct_count / total

    # Confusion matrix
    tp = sum(1 for r in results if r["label"]==1 and r["predicted"]==1)
    tn = sum(1 for r in results if r["label"]==0 and r["predicted"]==0)
    fp = sum(1 for r in results if r["label"]==0 and r["predicted"]==1)
    fn = sum(1 for r in results if r["label"]==1 and r["predicted"]==0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    print(f"\n  Dataset:   {total} samples "
          f"({sum(1 for r in results if r['label']==1)} vulnerable, "
          f"{sum(1 for r in results if r['label']==0)} safe)\n")

    print(f"  Accuracy : {accuracy:.1%}  ({correct_count}/{total} correct)")
    print(f"  Precision: {precision:.1%}  (of predicted VULN, how many are truly VULN?)")
    print(f"  Recall   : {recall:.1%}  (of actual VULN, how many did we catch?)")
    print(f"  F1 Score : {f1:.1%}  (harmonic mean of precision + recall)")

    print(f"\n  Confusion Matrix:")
    print(f"                  Predicted VULN  Predicted SAFE")
    print(f"  Actual VULN   :      {tp:3d} (TP)       {fn:3d} (FN)")
    print(f"  Actual SAFE   :      {fp:3d} (FP)       {tn:3d} (TN)")

    print(f"\n  Missed vulnerabilities (FN): {fn}")
    for r in results:
        if r["label"] == 1 and r["predicted"] == 0:
            print(f"    - {r['name']}  (prob={r['prob']:.1%})")

    print(f"\n  False positives (FP): {fp}")
    for r in results:
        if r["label"] == 0 and r["predicted"] == 1:
            print(f"    - {r['name']}  (prob={r['prob']:.1%})")

    print("\n" + "=" * 70)
    grade = (
        "EXCELLENT" if f1 >= 0.85 else
        "GOOD"      if f1 >= 0.70 else
        "FAIR"      if f1 >= 0.50 else
        "POOR — needs improvement"
    )
    print(f"  Overall Grade: {grade} (F1={f1:.1%})")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    run_evaluation()
