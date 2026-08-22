"""
parser.py — Python source code ingestion and AST analysis.

Uses Python's built-in `ast` module (zero extra dependencies) to:
  - Parse source code into an Abstract Syntax Tree
  - Extract structured metadata: functions, calls, imports, assignments
  - Identify code constructs relevant to vulnerability detection

This is the first stage of the KAVACH-AIDR pipeline.
"""

import ast
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class FunctionInfo:
    name       : str
    lineno     : int
    end_lineno : int
    args       : list[str]
    body_lines : list[str]   # raw source lines of the function body
    calls      : list[str]   # names of functions called inside


@dataclass
class ImportInfo:
    module  : str
    names   : list[str]
    lineno  : int
    is_from : bool           # True = "from X import Y"


@dataclass
class AssignInfo:
    target : str
    value  : str             # repr of the value node
    lineno : int


@dataclass
class ParsedCode:
    """Complete structured representation of a parsed Python file."""
    filepath    : Path
    source      : str
    lines       : list[str]
    functions   : list[FunctionInfo]  = field(default_factory=list)
    imports     : list[ImportInfo]    = field(default_factory=list)
    assignments : list[AssignInfo]    = field(default_factory=list)
    syntax_ok   : bool  = True
    parse_error : Optional[str] = None
    tree        : Optional[ast.AST] = None   # raw AST (for further analysis)


# ── Visitor ──────────────────────────────────────────────────────────────────

class CodeVisitor(ast.NodeVisitor):
    """
    AST visitor that extracts structured information from Python source code
    relevant to security analysis.
    """

    def __init__(self, source_lines: list[str]):
        self.source_lines  = source_lines
        self.functions     : list[FunctionInfo] = []
        self.imports       : list[ImportInfo]   = []
        self.assignments   : list[AssignInfo]   = []
        self._current_func : Optional[FunctionInfo] = None

    # ── Imports ──────────────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        self.imports.append(ImportInfo(
            module  = "",
            names   = [alias.name for alias in node.names],
            lineno  = node.lineno,
            is_from = False,
        ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.imports.append(ImportInfo(
            module  = node.module or "",
            names   = [alias.name for alias in node.names],
            lineno  = node.lineno,
            is_from = True,
        ))
        self.generic_visit(node)

    # ── Functions ─────────────────────────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._extract_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._extract_function(node)

    def _extract_function(self, node) -> None:
        args = [arg.arg for arg in node.args.args]
        end  = getattr(node, "end_lineno", node.lineno)

        # Extract body source lines (1-indexed → 0-indexed slice)
        body_lines = self.source_lines[node.lineno : end]

        # Collect all function calls inside this function
        call_visitor = CallCollector()
        call_visitor.visit(node)

        func_info = FunctionInfo(
            name       = node.name,
            lineno     = node.lineno,
            end_lineno = end,
            args       = args,
            body_lines = body_lines,
            calls      = call_visitor.calls,
        )
        self.functions.append(func_info)
        self.generic_visit(node)

    # ── Assignments ───────────────────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments.append(AssignInfo(
                    target = target.id,
                    value  = ast.unparse(node.value) if hasattr(ast, "unparse") else str(node.value),
                    lineno = node.lineno,
                ))
        self.generic_visit(node)


class CallCollector(ast.NodeVisitor):
    """Collect all function call names within a subtree."""

    def __init__(self):
        self.calls: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            self.calls.append(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            self.calls.append(f"{ast.unparse(node.func)}" if hasattr(ast, "unparse") else node.func.attr)
        self.generic_visit(node)


# ── Public API ───────────────────────────────────────────────────────────────

def parse_file(filepath: str | Path) -> ParsedCode:
    """
    Parse a Python source file and return structured metadata.

    Args:
        filepath: Path to the .py file to analyse.

    Returns:
        ParsedCode dataclass with all extracted information.
    """
    path = Path(filepath)
    source = path.read_text(encoding="utf-8", errors="replace")
    return parse_source(source, filepath=path)


def parse_source(source: str, filepath: Path = Path("<string>")) -> ParsedCode:
    """
    Parse Python source code from a string.

    Args:
        source  : Python source code as a string.
        filepath: Optional filepath label for error messages.

    Returns:
        ParsedCode dataclass.
    """
    result = ParsedCode(
        filepath = filepath,
        source   = source,
        lines    = source.splitlines(),
    )

    try:
        tree = ast.parse(source, filename=str(filepath))
        result.tree = tree

        visitor = CodeVisitor(source.splitlines())
        visitor.visit(tree)

        result.functions   = visitor.functions
        result.imports     = visitor.imports
        result.assignments = visitor.assignments
        result.syntax_ok   = True

    except SyntaxError as e:
        result.syntax_ok   = False
        result.parse_error = f"SyntaxError at line {e.lineno}: {e.msg}"

    return result


def get_code_snippet(parsed: ParsedCode, lineno: int, context: int = 3) -> str:
    """
    Extract a code snippet around a given line number.

    Args:
        parsed  : Parsed code object.
        lineno  : 1-indexed line number of interest.
        context : Number of lines before/after to include.

    Returns:
        Formatted code snippet with line numbers.
    """
    lines = parsed.lines
    start = max(0, lineno - 1 - context)
    end   = min(len(lines), lineno + context)

    snippet_lines = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == lineno else "   "
        snippet_lines.append(f"{marker} {i:4d} │ {line}")

    return "\n".join(snippet_lines)


def summarise(parsed: ParsedCode) -> dict:
    """Return a compact summary dict for logging/display."""
    return {
        "file"       : str(parsed.filepath),
        "syntax_ok"  : parsed.syntax_ok,
        "lines"      : len(parsed.lines),
        "functions"  : len(parsed.functions),
        "imports"    : len(parsed.imports),
        "assignments": len(parsed.assignments),
        "error"      : parsed.parse_error,
    }
