"""
vuln_deserialization.py — Sample VULNERABLE code: Insecure Deserialization

Vulnerability: Untrusted data is deserialised using pickle — an attacker
who controls the serialised payload can execute arbitrary Python code
on the server upon deserialization.

Also demonstrates unsafe yaml.load() and marshal usage.
"""

import pickle
import yaml
import marshal
import base64


def load_user_session(session_data: bytes) -> dict:
    """
    VULNERABLE: Deserialise a user session from bytes.
    An attacker can craft a pickle payload that executes arbitrary code
    on the server when loaded.

    Example malicious payload:
        class Exploit(object):
            def __reduce__(self):
                return (os.system, ('cat /etc/passwd',))
    """
    # ❌ VULNERABLE: pickle.loads on untrusted data → Remote Code Execution
    session = pickle.loads(session_data)
    return session


def load_config(config_str: str) -> dict:
    """
    VULNERABLE: Load configuration from YAML string.
    yaml.load() without Loader allows arbitrary Python object construction.
    """
    # ❌ VULNERABLE: yaml.load without Loader=yaml.SafeLoader
    config = yaml.load(config_str)
    return config


def load_cached_model(encoded_data: str) -> object:
    """
    VULNERABLE: Load a cached model from base64-encoded data.
    Uses marshal which can also execute arbitrary bytecode.
    """
    raw = base64.b64decode(encoded_data)
    # ❌ VULNERABLE: marshal.loads on untrusted bytecode
    code_obj = marshal.loads(raw)
    model = eval(compile(code_obj, "<string>", "exec"))
    return model


def receive_and_process(raw_bytes: bytes) -> None:
    """
    VULNERABLE: Generic receiver that processes serialized data.
    Used in network communication — extremely dangerous in military context.
    """
    # ❌ VULNERABLE: no validation before deserialization
    data = pickle.loads(raw_bytes)
    process(data)


def process(data: dict) -> None:
    """Placeholder for processing logic."""
    print(f"Processing: {data}")
