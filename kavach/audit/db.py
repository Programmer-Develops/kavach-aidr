"""
db.py — SQLite database schema and operations for KAVACH-AIDR audit trail.

All events are stored in a local SQLite database — no network, no cloud.
The database records every pipeline action with enough detail to reconstruct
the full decision chain for military accountability requirements.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any, Optional


# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
-- One row per KAVACH-AIDR pipeline run
CREATE TABLE IF NOT EXISTS scan_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT    NOT NULL UNIQUE,   -- UUID for this run
    started_at    TEXT    NOT NULL,          -- ISO8601 UTC timestamp
    completed_at  TEXT,
    target_file   TEXT    NOT NULL,
    status        TEXT    NOT NULL,          -- RUNNING | COMPLETED | FAILED
    total_findings INTEGER DEFAULT 0,
    llm_model     TEXT,
    llm_available INTEGER DEFAULT 0,        -- 1 = LLM was used, 0 = static only
    metadata      TEXT                      -- JSON blob for extras
);

-- One row per vulnerability finding
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT    NOT NULL REFERENCES scan_runs(run_id),
    finding_id    TEXT    NOT NULL,          -- VULN_TYPE:file:line
    vuln_type     TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    message       TEXT,
    filepath      TEXT,
    lineno        INTEGER,
    sources       TEXT,                     -- JSON: ["semgrep","bandit"]
    corroborated  INTEGER DEFAULT 0,
    score         REAL,
    cwe           TEXT,                     -- JSON: ["CWE-89"]
    code_snippet  TEXT,
    created_at    TEXT    NOT NULL
);

-- One row per reasoning result (LLM analysis of a finding)
CREATE TABLE IF NOT EXISTS reasoning_results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT NOT NULL REFERENCES scan_runs(run_id),
    finding_id       TEXT NOT NULL,
    root_cause       TEXT,
    exploit_scenario TEXT,
    patch_diff       TEXT,
    patch_found      INTEGER DEFAULT 0,
    verification     TEXT,
    total_tokens     INTEGER,
    total_time_sec   REAL,
    model_name       TEXT,
    created_at       TEXT NOT NULL
);

-- One row per patch application attempt
CREATE TABLE IF NOT EXISTS patch_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         TEXT NOT NULL REFERENCES scan_runs(run_id),
    finding_id     TEXT NOT NULL,
    success        INTEGER DEFAULT 0,
    strategy_used  TEXT,
    changes_made   INTEGER,
    syntax_valid   INTEGER DEFAULT 0,
    syntax_errors  TEXT,                    -- JSON list
    diff_summary   TEXT,
    created_at     TEXT NOT NULL
);

-- Tamper-proof event log (every action is signed)
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,           -- SCAN_START | FINDING | PATCH | etc.
    event_data  TEXT    NOT NULL,           -- JSON payload
    hmac_sig    TEXT    NOT NULL,           -- HMAC-SHA256 signature
    timestamp   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_events_run   ON audit_events(run_id);
"""


# ── Database class ────────────────────────────────────────────────────────────

class AuditDB:
    """SQLite database wrapper for KAVACH-AIDR audit data."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Scan runs ─────────────────────────────────────────────────────────

    def create_run(self, run_id: str, target_file: str, metadata: dict = None) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO scan_runs (run_id, started_at, target_file, status, metadata)
                   VALUES (?, ?, ?, 'RUNNING', ?)""",
                (run_id, self._now(), target_file, json.dumps(metadata or {}))
            )

    def complete_run(
        self,
        run_id         : str,
        total_findings : int,
        llm_model      : Optional[str] = None,
        llm_available  : bool = False,
        status         : str = "COMPLETED",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE scan_runs
                   SET completed_at=?, status=?, total_findings=?, llm_model=?, llm_available=?
                   WHERE run_id=?""",
                (self._now(), status, total_findings,
                 llm_model, int(llm_available), run_id)
            )

    # ── Findings ──────────────────────────────────────────────────────────

    def insert_finding(self, run_id: str, finding: Any) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO findings
                   (run_id, finding_id, vuln_type, severity, message, filepath,
                    lineno, sources, corroborated, score, cwe, code_snippet, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    finding.finding_id,
                    finding.vuln_type,
                    finding.severity,
                    finding.message,
                    finding.filepath,
                    finding.lineno,
                    json.dumps(finding.sources),
                    int(finding.corroborated),
                    finding.score,
                    json.dumps(finding.cwe),
                    finding.code_snippet,
                    self._now(),
                )
            )

    # ── Reasoning results ─────────────────────────────────────────────────

    def insert_reasoning(self, run_id: str, result: Any) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO reasoning_results
                   (run_id, finding_id, root_cause, exploit_scenario, patch_diff,
                    patch_found, verification, total_tokens, total_time_sec,
                    model_name, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    result.finding.finding_id,
                    result.root_cause,
                    result.exploit_scenario,
                    result.patch_diff,
                    int(result.patch_found),
                    result.verification,
                    result.total_tokens,
                    result.total_time_sec,
                    result.model_name,
                    self._now(),
                )
            )

    # ── Patch results ─────────────────────────────────────────────────────

    def insert_patch_result(
        self,
        run_id     : str,
        finding_id : str,
        result     : Any,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO patch_results
                   (run_id, finding_id, success, strategy_used, changes_made,
                    syntax_valid, syntax_errors, diff_summary, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    finding_id,
                    int(result.success),
                    result.strategy_used,
                    result.changes_made,
                    int(result.syntax_valid),
                    json.dumps(result.syntax_errors),
                    result.diff_summary,
                    self._now(),
                )
            )

    # ── Audit events ──────────────────────────────────────────────────────

    def log_event(
        self,
        run_id     : str,
        event_type : str,
        event_data : dict,
        hmac_sig   : str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO audit_events
                   (run_id, event_type, event_data, hmac_sig, timestamp)
                   VALUES (?, ?, ?, ?, ?)""",
                (run_id, event_type, json.dumps(event_data), hmac_sig, self._now())
            )

    # ── Queries ───────────────────────────────────────────────────────────

    def get_run_summary(self, run_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scan_runs WHERE run_id=?", (run_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_findings_for_run(self, run_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE run_id=? ORDER BY score DESC",
                (run_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_audit_events(self, run_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events WHERE run_id=? ORDER BY id",
                (run_id,)
            ).fetchall()
            return [dict(r) for r in rows]
