"""
Tests for the program-aware Z3 verifier.

Every case supplies (original, patched) source. A correct patch must yield
PROVED; an incomplete or missing patch must yield COUNTEREXAMPLE with a
concrete exploit input. These tests are the ground truth that the SMT verdict
actually depends on the patch contents.
"""

import pytest

from kavach.verifier.z3_verifier import Z3Verifier, PROVED, COUNTEREX, INCONCLUSIVE

V = Z3Verifier(timeout_ms=5000)

# ---------------------------------------------------------------- SQL injection
SQLI_ORIG = '''
def get_user(cur, name):
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    cur.execute(q)
'''
SQLI_FIXED_PARAM = '''
def get_user(cur, name):
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
'''
SQLI_FIXED_VAR = '''
def get_user(cur, name):
    q = "SELECT * FROM users WHERE name = ?"
    cur.execute(q, (name,))
'''
SQLI_BAD_FSTRING = '''
def get_user(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
'''
SQLI_BAD_FORMAT = '''
def get_user(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))
'''
SQLI_BAD_PERCENT = '''
def get_user(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
'''

# ------------------------------------------------------------ Command injection
CMD_ORIG = '''
import os
def ping(host):
    os.system("ping -c 1 " + host)
'''
CMD_FIXED_ARGV = '''
import subprocess
def ping(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
'''
CMD_FIXED_QUOTE = '''
import os, shlex
def ping(host):
    os.system("ping -c 1 " + shlex.quote(host))
'''
CMD_BAD_SHELL = '''
import subprocess
def ping(host):
    subprocess.run("ping -c 1 " + host, shell=True)
'''
CMD_BAD_STILL = CMD_ORIG

# ---------------------------------------------------------------- Path traversal
PATH_ORIG = '''
def read_doc(name):
    with open("/var/data/" + name) as f:
        return f.read()
'''
PATH_FIXED_BASENAME = '''
import os
def read_doc(name):
    with open("/var/data/" + os.path.basename(name)) as f:
        return f.read()
'''
PATH_FIXED_REALPATH = '''
import os
BASE = "/var/data"
def read_doc(name):
    p = os.path.realpath(os.path.join(BASE, name))
    if not p.startswith(BASE):
        raise ValueError("bad path")
    with open(p) as f:
        return f.read()
'''
PATH_BAD_STRIP = '''
def read_doc(name):
    with open("/var/data/" + name.strip()) as f:
        return f.read()
'''

# ------------------------------------------------------------- Code injection
CODE_ORIG = '''
def calc(expr):
    return eval(expr)
'''
CODE_FIXED = '''
import ast
def calc(expr):
    return ast.literal_eval(expr)
'''
CODE_BAD = '''
def calc(expr):
    return eval("1+" + expr)
'''

# ------------------------------------------------------------- Hardcoded secret
SECRET_ORIG = '''
def connect(db):
    password = "Sup3rS3cretPw!"
    return db.login("admin", password)
'''
SECRET_FIXED = '''
import os
def connect(db):
    password = os.environ["DB_PASSWORD"]
    return db.login("admin", password)
'''
SECRET_BAD = '''
def connect(db):
    password = "An0therHardcoded!"
    return db.login("admin", password)
'''


def _run(vt, orig, patched, line=3):
    return V.verify("t", vt, "t.py", line, orig, patched)


@pytest.mark.parametrize("vt,orig,patched", [
    ("SQL_INJECTION",     SQLI_ORIG, SQLI_FIXED_PARAM),
    ("SQL_INJECTION",     SQLI_ORIG, SQLI_FIXED_VAR),
    ("COMMAND_INJECTION", CMD_ORIG,  CMD_FIXED_ARGV),
    ("COMMAND_INJECTION", CMD_ORIG,  CMD_FIXED_QUOTE),
    ("PATH_TRAVERSAL",    PATH_ORIG, PATH_FIXED_BASENAME),
    ("PATH_TRAVERSAL",    PATH_ORIG, PATH_FIXED_REALPATH),
    ("CODE_INJECTION",    CODE_ORIG, CODE_FIXED),
    ("HARDCODED_SECRET",  SECRET_ORIG, SECRET_FIXED),
])
def test_correct_patch_is_proved(vt, orig, patched):
    r = _run(vt, orig, patched)
    assert r.pre_patch_step.result == "SAT", "original must be confirmed exploitable"
    assert r.post_patch_step.result == "UNSAT"
    assert r.verdict == PROVED


@pytest.mark.parametrize("vt,orig,patched", [
    ("SQL_INJECTION",     SQLI_ORIG, SQLI_ORIG),            # no fix at all
    ("SQL_INJECTION",     SQLI_ORIG, SQLI_BAD_FSTRING),
    ("SQL_INJECTION",     SQLI_ORIG, SQLI_BAD_FORMAT),
    ("SQL_INJECTION",     SQLI_ORIG, SQLI_BAD_PERCENT),
    ("COMMAND_INJECTION", CMD_ORIG,  CMD_BAD_STILL),
    ("COMMAND_INJECTION", CMD_ORIG,  CMD_BAD_SHELL),
    ("PATH_TRAVERSAL",    PATH_ORIG, PATH_ORIG),
    ("PATH_TRAVERSAL",    PATH_ORIG, PATH_BAD_STRIP),
    ("CODE_INJECTION",    CODE_ORIG, CODE_ORIG),
    ("CODE_INJECTION",    CODE_ORIG, CODE_BAD),
    ("HARDCODED_SECRET",  SECRET_ORIG, SECRET_ORIG),
    ("HARDCODED_SECRET",  SECRET_ORIG, SECRET_BAD),
])
def test_incomplete_or_missing_patch_gets_counterexample(vt, orig, patched):
    r = _run(vt, orig, patched)
    assert r.post_patch_step.result == "SAT"
    assert r.verdict == COUNTEREX


def test_counterexample_contains_concrete_input():
    r = _run("SQL_INJECTION", SQLI_ORIG, SQLI_BAD_FSTRING)
    assert "attacker_input" in r.post_patch_step.model_values


def test_already_safe_original_is_inconclusive_not_proved():
    """If the 'vulnerable' original is already safe the finding is a false
    positive: the verifier must not claim a proof for it."""
    r = _run("SQL_INJECTION", SQLI_FIXED_PARAM, SQLI_FIXED_PARAM, line=3)
    assert r.verdict == INCONCLUSIVE


def test_unencodable_class_is_inconclusive():
    r = _run("WEAK_CRYPTO", "import hashlib\nhashlib.md5(b'x')\n", "import hashlib\nhashlib.sha256(b'x')\n", line=2)
    assert r.verdict == INCONCLUSIVE


def test_unparseable_patch_is_inconclusive():
    r = _run("SQL_INJECTION", SQLI_ORIG, "def get_user(cur, name:\n    pass")
    assert r.verdict == INCONCLUSIVE
