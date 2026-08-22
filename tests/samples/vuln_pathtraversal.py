"""
vuln_pathtraversal.py — Sample VULNERABLE code: Path Traversal + Command Injection

Vulnerability: User-controlled file paths are not validated → attacker can
read arbitrary files from the filesystem using '../../../etc/passwd' style paths.

Also contains a command injection via os.system with unsanitised input.
"""

import os
import subprocess


BASE_DIR = "/var/army_data/reports/"


def read_report(filename: str) -> str:
    """
    VULNERABLE: Read a report file by name.
    Path Traversal: attacker passes '../../../etc/passwd' to read system files.
    """
    # ❌ VULNERABLE: no path sanitisation → path traversal
    filepath = BASE_DIR + filename
    with open(filepath, "r") as f:
        return f.read()


def export_report(filename: str, output_format: str) -> None:
    """
    VULNERABLE: Export a report using a system command.
    Command Injection: attacker can inject shell commands via output_format.
    e.g., output_format = "pdf; rm -rf /; #"
    """
    # ❌ VULNERABLE: shell=True + unsanitised input → command injection
    command = f"convert_report {filename} --format {output_format}"
    os.system(command)


def run_diagnostic(host: str) -> str:
    """
    VULNERABLE: Run a network diagnostic on a host.
    Command Injection via subprocess with shell=True.
    """
    # ❌ VULNERABLE: shell=True with user-controlled input
    result = subprocess.run(
        f"ping -c 3 {host}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def get_file_info(filepath: str) -> dict:
    """
    VULNERABLE: Get file metadata using eval on user input.
    Code injection via eval().
    """
    # ❌ VULNERABLE: eval() on user input → arbitrary code execution
    file_attrs = eval(f"os.stat('{filepath}')")
    return {
        "size"  : file_attrs.st_size,
        "mode"  : file_attrs.st_mode,
    }
