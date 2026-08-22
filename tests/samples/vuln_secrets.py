"""
vuln_secrets.py — Sample VULNERABLE code: Hardcoded Secrets + Weak Crypto

Vulnerabilities:
  1. Hardcoded credentials, API keys, and passwords in source code
  2. Use of broken cryptographic algorithms (MD5, SHA1)
  3. Weak random number generation for security-sensitive operations
  4. Insecure TLS configuration

In a military context: leaked credentials from source code
can give adversaries direct access to classified systems.
"""

import hashlib
import hmac
import random
import base64


# ❌ CRITICAL: Hardcoded credentials — visible to ANYONE with code access
DATABASE_PASSWORD = "ArmySecure@2024"
API_SECRET_KEY    = "sk-army-api-key-a1b2c3d4e5f6g7h8i9j0"
ADMIN_TOKEN       = "Bearer eyJhbGciOiJIUzI1NiJ9.admin.HARDCODED"
ENCRYPTION_KEY    = "supersecretkey123"
PRIVATE_KEY       = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."


def hash_password(password: str) -> str:
    """
    VULNERABLE: Hash a password using MD5.
    MD5 is cryptographically broken — rainbow tables exist for common passwords.
    Should use bcrypt, scrypt, or argon2 instead.
    """
    # ❌ VULNERABLE: MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def verify_integrity(data: bytes) -> str:
    """
    VULNERABLE: Compute a data integrity hash using SHA1.
    SHA1 is deprecated for security use (collision attacks demonstrated in 2017).
    """
    # ❌ VULNERABLE: SHA1 for integrity verification
    return hashlib.sha1(data).hexdigest()


def generate_session_token() -> str:
    """
    VULNERABLE: Generate a session token using Python's random module.
    random is NOT cryptographically secure — predictable from seed.
    Should use secrets.token_hex() instead.
    """
    # ❌ VULNERABLE: non-cryptographic random for security token
    token_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    return base64.b64encode(token_bytes).decode()


def connect_to_database():
    """
    VULNERABLE: Connect using hardcoded credentials.
    """
    import sqlite3
    # ❌ VULNERABLE: hardcoded password in code
    conn = sqlite3.connect(f"file:army_db?password=ArmySecure@2024")
    return conn


def encrypt_message(message: str) -> bytes:
    """
    VULNERABLE: Encrypt using a hardcoded key (ECB mode, weak key).
    """
    # ❌ VULNERABLE: hardcoded encryption key
    key = b"hardcodedkey1234"  # 16 bytes but completely predictable
    # In a real vuln this would use PyCrypto with ECB mode
    return message.encode()  # Placeholder — real vuln shown above
