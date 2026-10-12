#!/usr/bin/env python3
"""
Forensic Pipeline Verification Test Suite
=========================================
Validates the end-to-end insider risk detection pipeline:
- Database schema initialization, WAL mode, and indices
- Fallback / EVTX ingestion and event normalization
- Stage 1-5 detection heuristics (off-hours collection, archiving, USB, cloud, log clearing)
- Risk scoring formula and threat categorization
- Evidentiary deliverable compilation and SHA-256 cryptographic verification
- Security controls (SQL injection prevention & directory traversal protection)

Can be executed with either `pytest` or Python standard library `unittest`.
"""

import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

# Ensure project root is available for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.timeline_generator import (
    init_timeline_db,
    insert_timeline_events,
    build_timeline,
    parse_fallback_telemetry,
)
from parser.exfil_analyzer import InsiderRiskEvaluator
from reporting.generate_case_brief import (
    validate_case_id,
    compute_file_sha256,
    generate_case_artifacts,
)


class TestForensicPipeline(unittest.TestCase):
    """Full forensic workflow test cases."""

    def setUp(self):
        """Creates a temporary isolated test environment for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)
        self.db_path = self.test_root / "test_timeline.db"

        # Copy sample dataset into temp directory
        self.sample_dir = PROJECT_ROOT / "datasets" / "sample_insider_evtx"

    def tearDown(self):
        """Cleans up temporary resources."""
        self.temp_dir.cleanup()

    def test_database_initialization_and_schema(self):
        """Verifies table structure, columns, and performance indices."""
        conn = init_timeline_db(self.db_path)
        cur = conn.cursor()

        # Check table existence
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='super_timeline';")
        self.assertIsNotNone(cur.fetchone(), "super_timeline table must exist")

        # Check indices
        cur.execute("SELECT name FROM sqlite_master WHERE type='index';")
        indices = [row[0] for row in cur.fetchall()]
        self.assertIn("idx_time_user", indices, "Composite index idx_time_user must be present")
        self.assertIn("idx_event_id", indices, "Index idx_event_id must be present")
        self.assertIn("idx_mitre", indices, "Index idx_mitre must be present")

        # Verify WAL mode
        cur.execute("PRAGMA journal_mode;")
        journal_mode = cur.fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal", "Database must use WAL mode")

        conn.close()

    def test_telemetry_ingestion(self):
        """Verifies ingestion of normalized event records into super_timeline."""
        conn = init_timeline_db(self.db_path)
        count = parse_fallback_telemetry(self.sample_dir, conn)
        conn.close()

        self.assertEqual(count, 7, f"Expected 7 ingested sample events, got {count}")

        # Check database records
        check_conn = sqlite3.connect(str(self.db_path))
        cur = check_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM super_timeline;")
        total_rows = cur.fetchone()[0]
        self.assertEqual(total_rows, 7)
        check_conn.close()

    def test_stage1_off_hours_share_enumeration(self):
        """Verifies Stage 1 detection: off-hours mass network share access (T1025)."""
        build_timeline(self.sample_dir, self.db_path, engine="builtin")

        with InsiderRiskEvaluator(str(self.db_path)) as evaluator:
            analysis = evaluator.analyze_user_session("alex.mercer")
            stage1_count = analysis["stage_breakdown"]["stage1_off_hours_share_enum"]
            self.assertGreaterEqual(stage1_count, 1, "Must detect off-hours share enumeration")
            self.assertIn("T1025", analysis["mitre_techniques"])

    def test_stage2_mass_archive_staging(self):
        """Verifies Stage 2 detection: 7-Zip password-protected archiving (T1560.001)."""
        build_timeline(self.sample_dir, self.db_path, engine="builtin")

        with InsiderRiskEvaluator(str(self.db_path)) as evaluator:
            analysis = evaluator.analyze_user_session("alex.mercer")
            stage2_count = analysis["stage_breakdown"]["stage2_mass_archive_staging"]
            self.assertGreaterEqual(stage2_count, 1, "Must detect mass archive creation")
            self.assertIn("T1560.001", analysis["mitre_techniques"])

    def test_stage3_removable_media(self):
        """Verifies Stage 3 detection: USB device insertion & volume write (T1052.001)."""
        build_timeline(self.sample_dir, self.db_path, engine="builtin")

        with InsiderRiskEvaluator(str(self.db_path)) as evaluator:
            analysis = evaluator.analyze_user_session("alex.mercer")
            stage3_count = analysis["stage_breakdown"]["stage3_removable_media"]
            self.assertGreaterEqual(stage3_count, 1, "Must detect USB removable media usage")
            self.assertTrue(
                "T1052.001" in analysis["mitre_techniques"] or "T1052" in analysis["mitre_techniques"]
            )

    def test_stage4_cloud_storage_upload(self):
        """Verifies Stage 4 detection: Cloud POST upload burst to Mega.nz (T1567.002)."""
        build_timeline(self.sample_dir, self.db_path, engine="builtin")

        with InsiderRiskEvaluator(str(self.db_path)) as evaluator:
            analysis = evaluator.analyze_user_session("alex.mercer")
            stage4_count = analysis["stage_breakdown"]["stage4_cloud_upload"]
            self.assertGreaterEqual(stage4_count, 1, "Must detect cloud upload spike")
            self.assertIn("T1567.002", analysis["mitre_techniques"])

    def test_stage5_log_evasion(self):
        """Verifies Stage 5 detection: wevtutil audit log clearing (T1070.001)."""
        build_timeline(self.sample_dir, self.db_path, engine="builtin")

        with InsiderRiskEvaluator(str(self.db_path)) as evaluator:
            analysis = evaluator.analyze_user_session("alex.mercer")
            stage5_count = analysis["stage_breakdown"]["stage5_log_evasion"]
            self.assertGreaterEqual(stage5_count, 1, "Must detect event log clearing evasion")
            self.assertIn("T1070.001", analysis["mitre_techniques"])

    def test_composite_risk_scoring(self):
        """Verifies overall risk score calculation and threat classification."""
        build_timeline(self.sample_dir, self.db_path, engine="builtin")

        with InsiderRiskEvaluator(str(self.db_path)) as evaluator:
            analysis = evaluator.analyze_user_session("alex.mercer")
            self.assertEqual(analysis["overall_risk_score"], 100)
            self.assertEqual(analysis["threat_classification"], "CRITICAL_INSIDER_EXFILTRATION")
            self.assertEqual(analysis["stages_triggered"], 5)
            self.assertEqual(len(analysis["indicators"]), 5)

    def test_case_brief_generation_and_cryptographic_verification(self):
        """Verifies case brief artifacts, SHA-256 generation, and tamper detection."""
        build_timeline(self.sample_dir, self.db_path, engine="builtin")

        case_id = "TEST-CASE-2026-UNIT"
        output_cases = self.test_root / "cases"

        results = generate_case_artifacts(
            case_id=case_id,
            db_path=str(self.db_path),
            user_name="alex.mercer",
            output_root=str(output_cases)
        )

        report_file = results["report_file"]
        csv_file = results["csv_file"]
        sha_file = results["sha_file"]

        self.assertTrue(report_file.is_file(), "Executive summary markdown must exist")
        self.assertTrue(csv_file.is_file(), "Evidence CSV must exist")
        self.assertTrue(sha_file.is_file(), "SHA-256 hash manifest must exist")

        # Verify cryptographic integrity
        actual_csv_sha = compute_file_sha256(csv_file)
        recorded_sha_content = sha_file.read_text(encoding="utf-8")
        self.assertIn(actual_csv_sha, recorded_sha_content, "Recorded SHA-256 must match file hash")

        # Verify report content
        report_text = report_file.read_text(encoding="utf-8")
        self.assertIn("Alex Mercer", report_text)
        self.assertIn("Confirmed Malicious Insider Exfiltration", report_text)
        self.assertIn("4C53000123081110", report_text)
        self.assertIn(actual_csv_sha, report_text)

    def test_security_controls_sql_injection_defense(self):
        """Ensures evaluator resists SQL injection payloads via parameterized queries."""
        build_timeline(self.sample_dir, self.db_path, engine="builtin")

        malicious_input = "alex.mercer' OR '1'='1"
        with InsiderRiskEvaluator(str(self.db_path)) as evaluator:
            analysis = evaluator.analyze_user_session(malicious_input)
            # Should safely return 0 events rather than dumping table or erroring
            self.assertEqual(analysis["evidence_count"], 0)
            self.assertEqual(analysis["overall_risk_score"], 0)

    def test_security_controls_path_traversal_defense(self):
        """Ensures case generator rejects directory traversal attempts."""
        with self.assertRaises(ValueError):
            validate_case_id("../../etc/passwd")

        with self.assertRaises(ValueError):
            validate_case_id("case;rm -rf /")

        with self.assertRaises(ValueError):
            validate_case_id("CASE/2026/EXFIL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
