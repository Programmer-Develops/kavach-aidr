"""
program_model.py - Program-aware SMT encoding for KAVACH-AIDR (Layer 3).

The abstract encodings in constraint_builder.py describe a vulnerability class
but never look at the patched program, so their verdict cannot depend on the
patch. This module closes that gap. For a given program version P it

  1. locates the security-sensitive sinks (SQL execute, shell, open, eval ...),
  2. classifies the string reaching each sink from the AST as either
        STATIC   - structure fixed at compile time (constant, parameterised
                   query, argv-list call without a shell, recognised sanitiser)
        DYNAMIC  - attacker-influenced data is spliced into the string
                   (concatenation, f-string, % / .format, unresolved variable)
  3. emits one Z3 formula   phi_vuln(x, P)   over a symbolic attacker input x:

        phi_vuln(x, P) = OR_i [ M(x)  AND  Contains(Q_i, x) ]

     M(x) : x contains an injection metacharacter for the vulnerability class
     Q_i  : the string reaching sink i.
            DYNAMIC -> Q_i is a free symbolic string   (x can reach it)
            STATIC  -> Q_i is the constant template    (x cannot reach it)

     phi_vuln is SAT  when some sink is attacker-influenced (exploit exists);
     phi_vuln is UNSAT when every sink is static            (exploit impossible
     within this model).

The model is a sound-by-construction *abstraction*, not a full program
semantics: unresolved or unrecognised data flow is always treated as DYNAMIC
(conservative), so an UNSAT verdict is never produced by missing information.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Optional

try:
    from z3 import (
        String, StringVal, Contains, Length, Or, And, Not, BoolVal, IntVal,
    )
    Z3_AVAILABLE = True
except ImportError:  # pragma: no cover
    Z3_AVAILABLE = False


# Placeholder spliced into a template where a sanitised / parameter value goes.
# Contains no metacharacter of any vulnerability class below.
_PLACEHOLDER = "{USER}"

# Metacharacter sets M(x). Strict (no bare keywords such as OR/AND, which occur
# in every legitimate SQL template and would produce spurious counterexamples).
_METACHARS = {
    "SQL_INJECTION":     ["'", '"', "--", ";", "/*", "*/"],
    "COMMAND_INJECTION": [";", "&&", "||", "|", "`", "$(", "&", ">", "<"],
    "PATH_TRAVERSAL":    ["../", "..\\"],
    "CODE_INJECTION":    ["import", "__", "os.", "sys.", "open(", "exec("],
}

_SQL_SINKS = {"execute", "executemany", "executescript", "raw", "mogrify"}
_SUBPROCESS = {"call", "run", "Popen", "check_output", "check_call"}
_CODE_SINKS = {"eval", "exec"}

_SECRET_NAMES = [
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "auth_token", "access_token", "private_key", "passphrase",
]
_PLACEHOLDER_SECRETS = ["", "your_password", "changeme", "example", "placeholder", "xxxx"]

# Vulnerability classes for which the model is defined.
SUPPORTED = set(_METACHARS) | {"HARDCODED_SECRET"}

# For these classes, removing the dangerous sink altogether is a valid fix
# (e.g. eval() -> ast.literal_eval()).  For the others a missing sink means
# "cannot tell where the data went", which is reported as inconclusive.
_REMOVAL_IS_FIX = {"CODE_INJECTION", "HARDCODED_SECRET"}


@dataclass
class ProgramFormula:
    """SMT formula for one program version, plus how it was derived."""
    formula       : object                 # z3 BoolRef (None if not built)
    sinks_found   : int  = 0
    dynamic_sinks : int  = 0
    static_sinks  : int  = 0
    ok            : bool = True            # False -> model could not be built
    note          : str  = ""
    sink_report   : list = field(default_factory=list)   # [(lineno, kind, text)]


# ── Scope helpers ────────────────────────────────────────────────────────────

def enclosing_function(source: str, lineno: int) -> str:
    """Name of the innermost function containing `lineno` ('' = module level)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    best, best_span = "", None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if node.lineno <= lineno <= end:
                span = end - node.lineno
                if best_span is None or span < best_span:
                    best, best_span = node.name, span
    return best


def _scope_node(tree: ast.AST, func_name: str) -> ast.AST:
    if func_name:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
                return node
    return tree


def _dotted(node: ast.AST) -> str:
    """'os.path.join' for an Attribute chain, 'open' for a Name, else ''."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


# ── String-flow classification ───────────────────────────────────────────────

def _is_sanitiser(call: ast.Call, vuln_type: str) -> bool:
    name = _dotted(call.func)
    if vuln_type == "COMMAND_INJECTION":
        return name in {"shlex.quote", "quote", "pipes.quote"}
    if vuln_type == "PATH_TRAVERSAL":
        return name in {"os.path.basename", "basename", "secure_filename",
                        "werkzeug.utils.secure_filename"}
    return False


def _last_assignment(scope: ast.AST, name: str, before_line: int) -> Optional[ast.AST]:
    """Value of the last `name = <expr>` strictly before `before_line`.
    Returns an ast.AugAssign marker if the name is mutated with +=."""
    best_line, best = -1, None
    for node in ast.walk(scope):
        ln = getattr(node, "lineno", None)
        if ln is None or ln > before_line:
            continue
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name and ln >= best_line:
                    best_line, best = ln, node.value
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name and ln >= best_line:
                best_line, best = ln, node          # AugAssign -> dynamic
    return best


def _classify(expr: ast.AST, scope: ast.AST, line: int, vuln_type: str,
              depth: int = 0) -> tuple[str, str]:
    """Return ('static', template) or ('dynamic', '')."""
    if depth > 6:
        return "dynamic", ""

    if isinstance(expr, ast.Constant):
        return ("static", expr.value) if isinstance(expr.value, str) else ("static", "")

    if isinstance(expr, ast.JoinedStr):
        out = []
        for part in expr.values:
            if isinstance(part, ast.Constant):
                out.append(str(part.value))
            elif isinstance(part, ast.FormattedValue):
                v = part.value
                if isinstance(v, ast.Call) and _is_sanitiser(v, vuln_type):
                    out.append(_PLACEHOLDER)
                else:
                    kind, txt = _classify(v, scope, line, vuln_type, depth + 1)
                    if kind == "dynamic":
                        return "dynamic", ""
                    out.append(txt)
        return "static", "".join(out)

    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        lk, lt = _classify(expr.left, scope, line, vuln_type, depth + 1)
        if isinstance(expr.right, ast.Tuple):
            rights = [_classify(e, scope, line, vuln_type, depth + 1) for e in expr.right.elts]
        else:
            rights = [_classify(expr.right, scope, line, vuln_type, depth + 1)]
        if lk == "dynamic" or any(k == "dynamic" for k, _ in rights):
            return "dynamic", ""
        return "static", lt + "".join(t for _, t in rights)

    if isinstance(expr, ast.Call):
        if _is_sanitiser(expr, vuln_type):
            return "static", _PLACEHOLDER
        if _dotted(expr.func) in {"os.path.join", "join"} and vuln_type == "PATH_TRAVERSAL":
            parts = [_classify(a, scope, line, vuln_type, depth + 1) for a in expr.args]
            if any(k == "dynamic" for k, _ in parts):
                return "dynamic", ""
            return "static", "/".join(t for _, t in parts)
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            lk, lt = _classify(expr.func.value, scope, line, vuln_type, depth + 1)
            args = [_classify(a, scope, line, vuln_type, depth + 1) for a in expr.args]
            args += [_classify(k.value, scope, line, vuln_type, depth + 1) for k in expr.keywords]
            if lk == "dynamic" or any(k == "dynamic" for k, _ in args):
                return "dynamic", ""
            return "static", lt
        return "dynamic", ""

    if isinstance(expr, (ast.List, ast.Tuple)):
        parts = [_classify(e, scope, line, vuln_type, depth + 1) for e in expr.elts]
        # Elements of an argv list never pass through a shell parser:
        # dynamic *elements* are placeholders, structure stays fixed.
        return "static", " ".join(t if k == "static" else _PLACEHOLDER for k, t in parts)

    if isinstance(expr, ast.Name):
        val = _last_assignment(scope, expr.id, line)
        if val is None or isinstance(val, ast.AugAssign):
            return "dynamic", ""            # parameter / global / mutated
        return _classify(val, scope, getattr(val, "lineno", line), vuln_type, depth + 1)

    return "dynamic", ""


def _path_is_guarded(scope: ast.AST) -> bool:
    """realpath/abspath/resolve followed by a prefix / containment check."""
    src_names = set()
    for n in ast.walk(scope):
        if isinstance(n, ast.Call):
            src_names.add(_dotted(n.func).split(".")[-1])
        if isinstance(n, ast.Attribute):
            src_names.add(n.attr)
    resolves = bool(src_names & {"realpath", "abspath", "resolve"})
    checks   = bool(src_names & {"startswith", "commonpath", "commonprefix", "is_relative_to"})
    return resolves and checks


# ── Sink discovery ───────────────────────────────────────────────────────────

def _sink_arg(call: ast.Call, vuln_type: str) -> Optional[ast.AST]:
    """Return the argument expression that reaches a sink, or None if `call`
    is not a sink for this vulnerability class. A (None-like) marker string
    'ARGV' is returned for shell-less subprocess calls."""
    name = _dotted(call.func)
    last = name.split(".")[-1] if name else ""
    if not call.args:
        return None

    if vuln_type == "SQL_INJECTION":
        if isinstance(call.func, ast.Attribute) and call.func.attr in _SQL_SINKS:
            return call.args[0]

    elif vuln_type == "COMMAND_INJECTION":
        if name in {"os.system", "os.popen", "popen"}:
            return call.args[0]
        if name.startswith("subprocess.") and last in _SUBPROCESS:
            shell_true = any(
                k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                for k in call.keywords
            )
            if shell_true:
                return call.args[0]
            return ast.Constant(value="ARGV")        # no shell -> no metachar parsing

    elif vuln_type == "PATH_TRAVERSAL":
        if name == "open":
            return call.args[0]

    elif vuln_type == "CODE_INJECTION":
        if name in _CODE_SINKS:
            return call.args[0]

    return None


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "<expr>"


def build_program_formula(vuln_type: str, source: str, func_name: str = "") -> ProgramFormula:
    """Build phi_vuln(x, P) for program source `source`, restricted to the
    function `func_name` (module scope when empty or not found)."""
    if not Z3_AVAILABLE:
        return ProgramFormula(None, ok=False, note="z3-solver not installed")
    if vuln_type not in SUPPORTED:
        return ProgramFormula(None, ok=False, note=f"{vuln_type} has no program-aware SMT model")

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return ProgramFormula(None, ok=False, note=f"patched source does not parse: {e.msg}")

    scope = _scope_node(tree, func_name)

    if vuln_type == "HARDCODED_SECRET":
        return _secret_formula(scope)

    guarded = vuln_type == "PATH_TRAVERSAL" and _path_is_guarded(scope)
    metas   = _METACHARS[vuln_type]
    x       = String("attacker_input")
    m_of_x  = Or(*[Contains(x, StringVal(m)) for m in metas])

    clauses, report = [], []
    dyn = sta = 0
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        arg = _sink_arg(node, vuln_type)
        if arg is None:
            continue
        if isinstance(arg, ast.Constant) and arg.value == "ARGV":
            kind, tmpl = "static", "argv-list invocation (no shell)"
        else:
            kind, tmpl = _classify(arg, scope, node.lineno, vuln_type)
            if kind == "dynamic" and guarded:
                kind, tmpl = "static", "path resolved and containment-checked"

        idx = len(report)
        if kind == "dynamic":
            dyn += 1
            q = String(f"sink_{idx}_string")
            clauses.append(And(m_of_x, Contains(q, x)))
        else:
            sta += 1
            clauses.append(And(m_of_x, Contains(StringVal(tmpl), x)))
        report.append((node.lineno, kind.upper(), tmpl if kind == "static" else _unparse(arg)))

    found = dyn + sta
    if found == 0:
        if vuln_type in _REMOVAL_IS_FIX:
            return ProgramFormula(BoolVal(False), 0, 0, 0, True,
                                  "no dangerous sink remains in the program", [])
        return ProgramFormula(None, 0, 0, 0, False,
                              "no sink located in this program version", [])

    return ProgramFormula(Or(*clauses), found, dyn, sta, True, "", report)


def _secret_formula(scope: ast.AST) -> ProgramFormula:
    """phi_vuln = OR over string literals bound to secret-named identifiers:
    len(s) > 6 AND s is not a known placeholder."""
    lits: list[tuple[int, str, str]] = []
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for t in node.targets:
                nm = t.id if isinstance(t, ast.Name) else getattr(t, "attr", "")
                if nm and any(p in nm.lower() for p in _SECRET_NAMES):
                    lits.append((node.lineno, nm, node.value.value))
        elif isinstance(node, ast.Call):
            for k in node.keywords:
                if k.arg and any(p in k.arg.lower() for p in _SECRET_NAMES) \
                        and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str):
                    lits.append((node.lineno, k.arg, k.value.value))

    if not lits:
        return ProgramFormula(BoolVal(False), 0, 0, 0, True,
                              "no credential literal remains in the program", [])

    clauses = []
    for _, _, s in lits:
        sv = StringVal(s)
        clauses.append(And(
            Length(sv) > IntVal(6),
            *[Not(Contains(sv, StringVal(p))) for p in _PLACEHOLDER_SECRETS if p],
        ))
    report = [(ln, "DYNAMIC", f"{nm} = <string literal>") for ln, nm, _ in lits]
    return ProgramFormula(Or(*clauses), len(lits), len(lits), 0, True, "", report)
