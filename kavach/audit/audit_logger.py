"""
audit_logger.py — HMAC-SHA256 signed audit logger for KAVACH-AIDR.

Every action taken by the pipeline is logged as a tamper-proof event:
  - Signed with HMAC-SHA256 using a secret key
  - Stored in SQLite with full payload + signature
  - Can be exported as JSON or CEF/Syslog for SIEM integration

Tamper detection: if any event's data is modified after the fact,
its HMAC signature will not match — immediately detectable.
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from kavach.audit.db import AuditDB


class AuditLogger:
    """
    Military-grade, tamper-proof audit logger for KAVACH-AIDR.

    Usage:
        logger = AuditLogger(db, hmac_secret="your-secret-key", run_id="abc123")
        logger.log_scan_start("target.py")
        logger.log_finding(finding)
        logger.log_patch_applied(patch_result)
        logger.log_scan_complete(total_findings=5)
    """

    def __init__(
        self,
        db          : AuditDB,
        hmac_secret : str,
        run_id      : Optional[str] = None,
    ):
        self.db          = db
        self._secret     = hmac_secret.encode("utf-8")
        self.run_id      = run_id or str(uuid.uuid4())
        self._event_count = 0

    # ── High-level logging methods ────────────────────────────────────────

    def log_scan_start(self, target_file: str, config_summary: dict = None) -> None:
        """Log the start of a KAVACH-AIDR scan."""
        self.db.create_run(
            run_id      = self.run_id,
            target_file = target_file,
            metadata    = config_summary or {},
        )
        self._log("SCAN_START", {
            "target_file"    : target_file,
            "config_summary" : config_summary or {},
        })

    def log_static_analysis_complete(
        self,
        semgrep_count : int,
        bandit_count  : int,
        merged_count  : int,
    ) -> None:
        """Log completion of static analysis phase."""
        self._log("STATIC_ANALYSIS_COMPLETE", {
            "semgrep_findings" : semgrep_count,
            "bandit_findings"  : bandit_count,
            "merged_total"     : merged_count,
        })

    def log_finding(self, finding: Any) -> None:
        """Log a single merged vulnerability finding."""
        self.db.insert_finding(self.run_id, finding)
        self._log("VULNERABILITY_FOUND", {
            "finding_id"  : finding.finding_id,
            "vuln_type"   : finding.vuln_type,
            "severity"    : finding.severity,
            "filepath"    : finding.filepath,
            "lineno"      : finding.lineno,
            "corroborated": finding.corroborated,
            "sources"     : finding.sources,
            "score"       : finding.score,
        })

    def log_llm_reasoning(self, result: Any) -> None:
        """Log the LLM reasoning result for a finding."""
        self.db.insert_reasoning(self.run_id, result)
        self._log("LLM_REASONING_COMPLETE", {
            "finding_id"    : result.finding.finding_id,
            "patch_found"   : result.patch_found,
            "model_name"    : result.model_name,
            "tokens_used"   : result.total_tokens,
            "time_sec"      : result.total_time_sec,
            "llm_available" : result.llm_available,
        })

    def log_patch_result(self, finding_id: str, patch_result: Any) -> None:
        """Log the result of applying a patch."""
        self.db.insert_patch_result(self.run_id, finding_id, patch_result)
        self._log("PATCH_APPLIED", {
            "finding_id"   : finding_id,
            "success"      : patch_result.success,
            "strategy"     : patch_result.strategy_used,
            "changes_made" : patch_result.changes_made,
            "syntax_valid" : patch_result.syntax_valid,
            "diff_summary" : patch_result.diff_summary,
        })

    def log_scan_complete(
        self,
        total_findings : int,
        llm_model      : Optional[str] = None,
        llm_available  : bool = False,
        status         : str = "COMPLETED",
    ) -> None:
        """Log scan completion."""
        self.db.complete_run(
            run_id         = self.run_id,
            total_findings = total_findings,
            llm_model      = llm_model,
            llm_available  = llm_available,
            status         = status,
        )
        self._log("SCAN_COMPLETE", {
            "total_findings" : total_findings,
            "llm_model"      : llm_model,
            "llm_available"  : llm_available,
            "status"         : status,
        })

    def log_error(self, error_type: str, message: str, context: dict = None) -> None:
        """Log an error event."""
        self._log("ERROR", {
            "error_type" : error_type,
            "message"    : message,
            "context"    : context or {},
        })

    # ── HMAC signing ──────────────────────────────────────────────────────

    def _log(self, event_type: str, event_data: dict) -> None:
        """
        Create a tamper-proof log entry with HMAC-SHA256 signature.

        The HMAC is computed over: event_type + run_id + timestamp + event_data
        This means any post-hoc modification of ANY field will break the signature.
        """
        self._event_count += 1
        timestamp  = datetime.now(timezone.utc).isoformat()

        # Include event count in payload to prevent replay/reorder attacks
        payload = {
            "event_sequence" : self._event_count,
            "run_id"         : self.run_id,
            "event_type"     : event_type,
            "timestamp"      : timestamp,
            **event_data,
        }

        # Compute HMAC over canonical JSON (sorted keys for determinism)
        canonical  = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        signature  = hmac.new(self._secret, canonical, hashlib.sha256).hexdigest()

        self.db.log_event(
            run_id     = self.run_id,
            event_type = event_type,
            event_data = payload,
            hmac_sig   = signature,
        )

    def verify_event(self, event: dict) -> bool:
        """
        Verify that a stored audit event has not been tampered with.

        Args:
            event: Dict from db.get_audit_events() with 'event_data' and 'hmac_sig'

        Returns:
            True if signature matches (event is authentic).
        """
        stored_sig = event.get("hmac_sig", "")
        event_data = event.get("event_data", {})
        if isinstance(event_data, str):
            event_data = json.loads(event_data)

        canonical = json.dumps(event_data, sort_keys=True, default=str).encode("utf-8")
        expected  = hmac.new(self._secret, canonical, hashlib.sha256).hexdigest()

        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_sig, expected)

    def verify_all_events(self, run_id: str) -> tuple[bool, int, int]:
        """
        Verify all audit events for a run.

        Returns:
            (all_valid, valid_count, total_count)
        """
        events = self.db.get_audit_events(run_id)
        valid   = sum(1 for e in events if self.verify_event(e))
        return valid == len(events), valid, len(events)

    def export_json_report(self, run_id: str, output_path: str | Path) -> Path:
        """
        Export the full audit trail for a run as a signed JSON report.

        Args:
            run_id      : The run to export.
            output_path : Where to write the JSON file.

        Returns:
            Path to the written file.
        """
        report = {
            "kavach_report_version" : "1.0",
            "run_summary"           : self.db.get_run_summary(run_id),
            "findings"              : self.db.get_findings_for_run(run_id),
            "audit_events"          : self.db.get_audit_events(run_id),
            "integrity"             : {
                "hmac_algorithm" : "SHA-256",
                "verification"   : "Use verify_all_events() to check all signatures",
            },
        }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return path
