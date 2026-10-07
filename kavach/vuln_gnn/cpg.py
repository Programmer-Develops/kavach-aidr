"""
cpg.py — Code Property Graph (CPG) construction for VulnGNN.

Builds a unified graph for a single Python function from its AST:
    * AST edges  : parent -> child
    * CFG edges  : statement -> successor statement(s)
    * DFG edges  : definition -> use of the same variable, plus
                   value -> assignment target
and attaches a 16-dimensional feature vector to every node.

Feature layout (FEATURE_DIM = 16)
    0  call node
    1  assignment node
    2  string-building / arithmetic expression (BinOp, JoinedStr)
    3  control-flow statement (if / for / while / try / with)
    4  return / raise / assert
    5  variable reference (Name / Attribute / Subscript)
    6  string constant
    7  non-string constant
    8  operator class (0 = none, 0.5 = '+' or '%', 1 = other)
    9  call to a known dangerous sink
    10 call to a known sanitizer / validator
    11 taint source (function parameter or known input API)
    12 node is tainted (reached from a source through DFG/AST, not blocked
       by a sanitizer)
    13 sink call that receives a tainted argument
    14 normalised AST depth
    15 dynamic string construction (f-string, '%', '+', .format)

The builder never executes the code; it only parses it.
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass, field

FEATURE_DIM = 144
MAX_NODES = 600

SINK_NAMES = {
    "execute", "executemany", "executescript", "raw", "system", "popen",
    "call", "run", "check_output", "check_call", "Popen", "eval", "exec",
    "compile", "loads", "load", "unsafe_load", "open", "send_file",
    "send_from_directory", "render_template_string", "urlopen", "get",
    "post", "redirect", "extractall", "extract", "write", "unlink",
    "remove", "rmtree", "chmod", "makedirs", "mkdir", "fromstring",
    "parse", "md5", "sha1", "mark_safe", "format_html", "HttpResponse",
}
# Names that are only treated as sinks when they are attribute calls on
# these receivers, to avoid flagging every dict.get() as a sink.
RECEIVER_SENSITIVE = {"get", "post", "write", "remove", "parse", "load", "loads", "run", "call", "open"}
SENSITIVE_RECEIVERS = {
    "os", "subprocess", "pickle", "yaml", "marshal", "shelve", "requests",
    "urllib", "shutil", "tarfile", "zipfile", "etree", "ET", "hashlib",
    "cursor", "conn", "connection", "db", "session", "json5",
}

SANITIZER_NAMES = {
    "quote", "escape", "literal_eval", "realpath", "abspath", "basename",
    "secure_filename", "sanitize", "sanitise", "validate", "is_safe",
    "isinstance", "int", "float", "bool", "bleach", "clean", "safe_load",
    "normpath", "fullmatch", "match", "isalnum", "isdigit", "startswith",
    "escape_string", "html_escape", "urlparse", "is_relative_to",
    "check_password_hash", "compare_digest", "shlex_quote", "scrub",
}

SOURCE_NAMES = {
    "input", "raw_input", "getenv", "read", "recv", "recvfrom", "readline",
    "get_json", "getlist", "get_data",
}
SOURCE_ATTRS = {"args", "form", "json", "values", "cookies", "headers", "data",
                "GET", "POST", "COOKIES", "META", "files", "argv", "environ", "stdin"}


@dataclass
class CPG:
    x: list[list[float]] = field(default_factory=list)       # N x 16
    edges: list[tuple[int, int]] = field(default_factory=list)  # directed (src, dst)
    edge_kinds: list[str] = field(default_factory=list)       # "ast" | "cfg" | "dfg"
    n_sink: int = 0
    n_tainted_sink: int = 0


def _call_name(node: ast.Call) -> tuple[str, str]:
    """Return (attribute/function name, receiver root name)."""
    f = node.func
    if isinstance(f, ast.Name):
        return f.id, ""
    if isinstance(f, ast.Attribute):
        recv = f.value
        while isinstance(recv, ast.Attribute):
            recv = recv.value
        root = recv.id if isinstance(recv, ast.Name) else ""
        return f.attr, root
    return "", ""


def _is_sink(name: str, recv: str) -> bool:
    if name not in SINK_NAMES:
        return False
    if name in RECEIVER_SENSITIVE:
        return recv in SENSITIVE_RECEIVERS or recv == ""  and name in {"open"}
    return True


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        for side in (node.left, node.right):
            if isinstance(side, ast.Constant) and isinstance(side.value, str):
                return True
            if isinstance(side, ast.JoinedStr):
                return True
        return False
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format" and isinstance(node.func.value, ast.Constant):
        return True
    return False


def build_cpg(source: str) -> CPG | None:
    """Parse a single function (or any Python snippet) and build its CPG.

    Returns None if the code cannot be parsed or exceeds MAX_NODES.
    """
    try:
        tree = ast.parse(textwrap.dedent(source))
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None

    nodes: list[ast.AST] = []
    depth: list[int] = []
    idx: dict[int, int] = {}
    edges: list[tuple[int, int]] = []
    kinds: list[str] = []

    def add_edge(a: int, b: int, kind: str) -> None:
        if a != b:
            edges.append((a, b))
            kinds.append(kind)

    # ── 1. AST nodes and edges (skip context / operator singletons) ──────
    skip = (ast.Load, ast.Store, ast.Del, ast.operator, ast.boolop,
            ast.unaryop, ast.cmpop, ast.expr_context)
    stack = [(tree, -1, 0)]
    while stack:
        node, parent, d = stack.pop()
        if isinstance(node, skip):
            continue
        i = len(nodes)
        if i >= MAX_NODES:
            return None
        nodes.append(node)
        depth.append(d)
        idx[id(node)] = i
        if parent >= 0:
            add_edge(parent, i, "ast")
        children = list(ast.iter_child_nodes(node))
        for ch in reversed(children):
            stack.append((ch, i, d + 1))

    n = len(nodes)
    if n < 3:
        return None

    # ── 2. CFG edges between statements ──────────────────────────────────
    def cfg_block(stmts: list[ast.stmt], preds: list[int]) -> list[int]:
        for s in stmts:
            si = idx.get(id(s))
            if si is None:
                continue
            for p in preds:
                add_edge(p, si, "cfg")
            preds = [si]
            bodies = []
            for attr in ("body", "orelse", "finalbody"):
                b = getattr(s, attr, None)
                if isinstance(b, list) and b and isinstance(b[0], ast.stmt):
                    bodies.append(b)
            for h in getattr(s, "handlers", []) or []:
                if h.body:
                    bodies.append(h.body)
            if bodies and not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                outs = []
                for b in bodies:
                    outs.extend(cfg_block(b, [si]))
                preds = outs or [si]
                if isinstance(s, (ast.For, ast.While, ast.AsyncFor)):
                    for o in outs:
                        add_edge(o, si, "cfg")  # back edge
            elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                cfg_block(s.body, [si])
                preds = [si]
        return preds

    top = tree.body
    if len(top) == 1 and isinstance(top[0], (ast.FunctionDef, ast.AsyncFunctionDef)):
        fn = top[0]
        cfg_block(fn.body, [idx[id(fn)]])
    else:
        cfg_block(top, [])

    # ── 3. DFG edges (definition -> use, value -> target) ────────────────
    defs: dict[str, set[int]] = {}
    param_nodes: set[int] = set()

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            for a in list(args.args) + list(args.kwonlyargs) + list(args.posonlyargs):
                ai = idx.get(id(a))
                if ai is not None and a.arg not in ("self", "cls"):
                    defs[a.arg] = {ai}
                    param_nodes.add(ai)
            for a in (args.vararg, args.kwarg):
                if a is not None and idx.get(id(a)) is not None:
                    defs[a.arg] = {idx[id(a)]}
                    param_nodes.add(idx[id(a)])
            body = node.body if isinstance(node.body, list) else [node.body]
            for b in body:
                visit(b)
            return
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            value = getattr(node, "value", None)
            if value is not None:
                visit(value)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            vi = idx.get(id(value)) if value is not None else None
            for t in targets:
                for sub in ast.walk(t):
                    if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                        si = idx.get(id(sub))
                        if si is None:
                            continue
                        if vi is not None:
                            add_edge(vi, si, "dfg")
                        if isinstance(node, ast.AugAssign):
                            for d in defs.get(sub.id, ()):
                                add_edge(d, si, "dfg")
                        defs[sub.id] = {si}
                    elif isinstance(sub, ast.Name):
                        pass
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            visit(node.iter)
            ii = idx.get(id(node.iter))
            for sub in ast.walk(node.target):
                if isinstance(sub, ast.Name):
                    si = idx.get(id(sub))
                    if si is not None:
                        if ii is not None:
                            add_edge(ii, si, "dfg")
                        defs[sub.id] = {si}
            for b in node.body + node.orelse:
                visit(b)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            ni = idx.get(id(node))
            if ni is not None:
                for d in defs.get(node.id, ()):
                    add_edge(d, ni, "dfg")
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                visit(item.context_expr)
                if item.optional_vars is not None:
                    vi = idx.get(id(item.context_expr))
                    for sub in ast.walk(item.optional_vars):
                        if isinstance(sub, ast.Name):
                            si = idx.get(id(sub))
                            if si is not None:
                                if vi is not None:
                                    add_edge(vi, si, "dfg")
                                defs[sub.id] = {si}
            for b in node.body:
                visit(b)
            return
        for ch in ast.iter_child_nodes(node):
            visit(ch)

    visit(tree)

    # ── 4. Local features ────────────────────────────────────────────────
    x = [[0.0] * FEATURE_DIM for _ in range(n)]
    is_sink = [False] * n
    is_sanit = [False] * n
    is_source = [False] * n
    max_depth = max(depth) or 1

    for i, node in enumerate(nodes):
        f = x[i]
        
        # Token Hashing for 128 additional feature dimensions
        token = type(node).__name__
        if isinstance(node, ast.Name):
            token = node.id
        elif isinstance(node, ast.Attribute):
            token = node.attr
        elif isinstance(node, ast.Call):
            name, _ = _call_name(node)
            if name: token = name
        elif isinstance(node, ast.Constant):
            token = str(node.value)
        
        # Consistent string hash
        hash_val = sum(ord(c) * (31 ** idx) for idx, c in enumerate(token[:10]))
        hash_idx = 16 + (hash_val % 128)
        f[hash_idx] = 1.0

        if isinstance(node, ast.Call):
            f[0] = 1.0
            name, recv = _call_name(node)
            if _is_sink(name, recv):
                f[9] = 1.0
                is_sink[i] = True
            if name in SANITIZER_NAMES:
                f[10] = 1.0
                is_sanit[i] = True
            if name in SOURCE_NAMES:
                is_source[i] = True
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            f[1] = 1.0
        elif isinstance(node, (ast.BinOp, ast.JoinedStr)):
            f[2] = 1.0
            if isinstance(node, ast.BinOp):
                f[8] = 0.5 if isinstance(node.op, (ast.Add, ast.Mod)) else 1.0
        elif isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.With,
                               ast.AsyncFor, ast.AsyncWith, ast.IfExp)):
            f[3] = 1.0
        elif isinstance(node, (ast.Return, ast.Raise, ast.Assert)):
            f[4] = 1.0
        elif isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
            f[5] = 1.0
            if isinstance(node, ast.Attribute) and node.attr in SOURCE_ATTRS:
                is_source[i] = True
            if isinstance(node, ast.Name) and node.id in ("argv", "environ"):
                is_source[i] = True
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                f[6] = 1.0
            else:
                f[7] = 1.0
        if _is_dynamic_string(node):
            f[15] = 1.0
        f[14] = depth[i] / max_depth
        if i in param_nodes or is_source[i]:
            is_source[i] = True
        if is_source[i]:
            f[11] = 1.0

    # ── 5. Taint propagation (AST child->parent and DFG def->use) ────────
    fwd: list[list[int]] = [[] for _ in range(n)]
    for (a, b), k in zip(edges, kinds):
        if k == "dfg":
            fwd[a].append(b)
        elif k == "ast":
            fwd[b].append(a)           # child taints enclosing expression
    tainted = [False] * n
    work = [i for i in range(n) if is_source[i]]
    for i in work:
        tainted[i] = True
    while work:
        cur = work.pop()
        if is_sanit[cur]:
            continue                    # sanitizer blocks propagation
        for nxt in fwd[cur]:
            if not tainted[nxt] and not isinstance(nodes[nxt], (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
                tainted[nxt] = True
                work.append(nxt)
    n_sink = n_tsink = 0
    for i in range(n):
        if tainted[i] and not is_sanit[i]:
            x[i][12] = 1.0
        if is_sink[i]:
            n_sink += 1
            call = nodes[i]
            # Payload is the first positional argument (SQL text / command /
            # path / data); later positional args are bound parameters.
            first = list(call.args[:1])
            arg_nodes = [idx.get(id(a)) for a in first + [k.value for k in call.keywords
                                                           if k.arg in ("shell", "cmd", "command", "query", "sql", "path", "file", "url", "data", "args")]]
            if any(a is not None and tainted[a] and not is_sanit[a] for a in arg_nodes):
                x[i][13] = 1.0
                n_tsink += 1

    # Message passing is undirected: add reverse edges.
    all_edges = edges + [(b, a) for a, b in edges]
    return CPG(x=x, edges=all_edges, edge_kinds=kinds + kinds, n_sink=n_sink, n_tainted_sink=n_tsink)
