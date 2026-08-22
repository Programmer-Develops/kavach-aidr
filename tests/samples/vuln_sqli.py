"""
vuln_sqli.py — Sample VULNERABLE code: SQL Injection

This file intentionally contains a SQL injection vulnerability.
Used to demonstrate KAVACH-AIDR's detection and patch capabilities.

Vulnerability: User input is directly concatenated into a SQL query
without parameterisation → attacker can bypass authentication or
exfiltrate the entire database.

Attack payload: ' OR '1'='1
"""

import sqlite3


def authenticate_user(username: str, password: str) -> bool:
    """
    VULNERABLE: Authenticate a user against the database.
    SQL Injection: attacker can log in as any user with username: ' OR '1'='1' --
    """
    conn = sqlite3.connect("army_personnel.db")
    cursor = conn.cursor()

    # ❌ VULNERABLE: direct string concatenation — SQL INJECTION
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result is not None


def get_user_record(user_id: str) -> dict:
    """
    VULNERABLE: Fetch a user record by ID.
    SQL Injection via format string.
    """
    conn = sqlite3.connect("army_personnel.db")
    cursor = conn.cursor()

    # ❌ VULNERABLE: format string SQL injection
    query = "SELECT * FROM personnel WHERE id = %s" % user_id
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    return row


def search_personnel(search_term: str) -> list:
    """
    VULNERABLE: Search for personnel by name.
    """
    conn = sqlite3.connect("army_personnel.db")
    cursor = conn.cursor()

    # ❌ VULNERABLE: f-string SQL injection
    query = f"SELECT * FROM personnel WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)

    results = cursor.fetchall()
    conn.close()
    return results


# ── Safe version (for comparison, NOT for the AI to analyse) ─────────────────

def authenticate_user_safe(username: str, password: str) -> bool:
    """SAFE version using parameterised queries."""
    conn = sqlite3.connect("army_personnel.db")
    cursor = conn.cursor()
    # ✅ SAFE: parameterised query
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()
    conn.close()
    return result is not None
