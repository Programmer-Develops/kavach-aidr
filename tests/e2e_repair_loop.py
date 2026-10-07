"""
End-to-end check of the Stage 2 -> Stage 3 feedback loop
(patch -> Z3 -> Pass/Fail -> counterexample re-prompt) on a real sample file.

No GGUF model is needed: a scripted engine plays the role of the LLM so the
loop logic, the Z3 verdicts and the audit logging are exercised for real.

Run:  python tests/e2e_repair_loop.py
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from kavach.main import _patch_and_verify, MAX_REPAIR_ATTEMPTS          # noqa: E402
from kavach.reasoner.chain_of_thought import ChainOfThought, ReasoningResult  # noqa: E402
from kavach.reasoner.llm_engine import LLMResponse                       # noqa: E402
from kavach.static.merger import MergedFinding                           # noqa: E402
from kavach.audit.db import AuditDB                                      # noqa: E402
from kavach.audit.audit_logger import AuditLogger                        # noqa: E402

SAMPLE = ROOT / "tests" / "samples" / "vuln_sqli.py"
SRC    = SAMPLE.read_text(encoding="utf-8", errors="replace")
LINES  = SRC.splitlines()

q_idx = next(i for i, l in enumerate(LINES) if l.strip().startswith("query = ") and "username" in l)
e_idx = next(i for i in range(q_idx, len(LINES)) if "cursor.execute(query)" in LINES[i])
Q_LINE, E_LINE = LINES[q_idx], LINES[e_idx]


def diff(new_lines: list[str]) -> str:
    """Unified diff replacing the query + execute lines."""
    out = ["--- a/vuln_sqli.py", "+++ b/vuln_sqli.py", f"@@ -{q_idx+1},{e_idx-q_idx+1} +{q_idx+1},{len(new_lines)} @@"]
    out += ["-" + l for l in LINES[q_idx:e_idx + 1]]
    out += ["+" + l for l in new_lines]
    return "\n".join(out)


BAD_FSTRING = diff([
    '    cursor.execute(f"SELECT * FROM users WHERE username=\'{username}\' AND password=\'{password}\'")',
])
GOOD_PARAM = diff([
    '    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))',
])


class ScriptedEngine:
    """Stand-in for the local LLM: returns queued patches, records prompts."""
    def __init__(self, patches):
        self.patches, self.prompts = list(patches), []
    def is_loaded(self):
        return True
    def generate(self, prompt, system_prompt=""):
        self.prompts.append(prompt)
        p = self.patches.pop(0) if self.patches else BAD_FSTRING
        text = f"### STEP 3 - PATCH\nPATCH_START\n{p}\nPATCH_END\n### STEP 4 - VERIFICATION\nok"
        return LLMResponse(text=text, tokens_used=10, model_name="scripted", finish_reason="stop")


def run(first_patch, later_patches):
    engine  = ScriptedEngine(later_patches)
    cot     = ChainOfThought(engine=engine)
    finding = MergedFinding(
        finding_id="SQL_INJECTION:t:%d" % (e_idx + 1), vuln_type="SQL_INJECTION", severity="HIGH",
        message="sql", filepath=str(SAMPLE), lineno=e_idx + 1, end_lineno=e_idx + 1,
        code_snippet=E_LINE, fix_hint="", cwe=["CWE-89"], sources=["semgrep"], rule_ids=[],
    )
    result = ReasoningResult(finding=finding, root_cause="", exploit_scenario="",
                             patch_diff=first_patch, verification="", patch_found=True)
    tmp    = tempfile.mkdtemp()
    db     = AuditDB(Path(tmp) / "a.db")
    logger = AuditLogger(db, hmac_secret="test-secret", run_id="E2E")
    logger.log_scan_start(str(SAMPLE))
    patched, z3r = _patch_and_verify(finding, result, SRC, cot, logger)
    events = [e for e in db.get_audit_events("E2E") if e["event_type"] == "Z3_VERIFICATION"]
    ok, valid, total = logger.verify_all_events("E2E")
    return patched, z3r, engine, events, (ok, valid, total)


print("\n=== A: bad patch first, LLM repairs after Z3 counterexample ===")
patched, z3r, eng, ev, integ = run(BAD_FSTRING, [GOOD_PARAM])
assert z3r.verdict == "PROVED", z3r.verdict
assert len(ev) == 2 and len(eng.prompts) == 1
assert "attacker_input" in eng.prompts[0], "counterexample must reach the LLM prompt"
assert "?" in patched and "{username}" not in patched
assert integ[0], integ
print(">> A OK: FAIL -> counterexample re-prompt -> PASS (2 audited attempts, HMAC valid)")

print("\n=== B: LLM never fixes it -> rejected after max attempts ===")
patched, z3r, eng, ev, integ = run(BAD_FSTRING, [BAD_FSTRING, BAD_FSTRING])
assert patched == "" and z3r.verdict == "COUNTEREXAMPLE"
assert len(ev) == MAX_REPAIR_ATTEMPTS and len(eng.prompts) == MAX_REPAIR_ATTEMPTS - 1
assert integ[0]
print(">> B OK: patch rejected, original code untouched, %d attempts audited" % len(ev))

print("\n=== C: correct patch first time -> no re-prompt ===")
patched, z3r, eng, ev, integ = run(GOOD_PARAM, [])
assert z3r.verdict == "PROVED" and len(ev) == 1 and not eng.prompts
print(">> C OK: PASS on first attempt")

print("\nALL END-TO-END CHECKS PASSED")
