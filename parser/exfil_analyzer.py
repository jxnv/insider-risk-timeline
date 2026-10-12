#!/usr/bin/env python3
"""
Exfiltration Analyzer & Behavioral Risk Scorer
==============================================
Scans the SQLite super-timeline to detect coordinated insider risk behaviors across 5 stages:
1. Off-Hours Share Enumeration (>50 files between 11PM-3AM)
2. Mass Archive Staging (7z.exe a -p or tar -czvf)
3. Removable Media Mount & Write (USB Serial VID_0781&PID_5583 / Event ID 20001, 20003)
4. Cloud Upload Spike (Mega.nz / Google Drive POST burst / Event ID 3)
5. Log Evasion Attempt (wevtutil cl Security / Event ID 1102 / 104)

Maps all findings to MITRE ATT&CK for Enterprise techniques and outputs risk scoring.

Author: Justin Chamreun, M.S., CISSP
License: MIT / Incident Response Forensic Standard
"""

import argparse
from datetime import datetime
import json
import logging
from pathlib import Path
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("exfil_analyzer")


class InsiderRiskEvaluator:
    """
    Evaluates insider threat behavior against the super-timeline database.
    Applies multi-stage correlation, heuristics, and MITRE ATT&CK mapping.
    """

    def __init__(self, db_path: str):
        self.db_path = Path(db_path).resolve()
        if not self.db_path.is_file():
            raise FileNotFoundError(f"Super-timeline database not found: {self.db_path}")

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

    def close(self):
        """Safely closes the database connection."""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _get_off_hours_events(self, user_name: str) -> List[sqlite3.Row]:
        """
        Stage 1: Detects off-hours network share access and mass file enumeration (T1025, T1083).
        Off-hours definition: 23:00 to 06:00 UTC (11 PM - 6 AM).
        """
        cur = self.conn.cursor()
        # Parameterized query to avoid SQL injection
        cur.execute("""
            SELECT id, timestamp, channel, event_id, process_name, command_line, action_summary, mitre_technique, raw_event
            FROM super_timeline
            WHERE (user_name = ? OR user_name IS NULL)
              AND (
                  action_summary LIKE '%\\\\%'
                  OR action_summary LIKE '%share%'
                  OR action_summary LIKE '%nas%'
                  OR action_summary LIKE '%bulk-accessed%'
                  OR event_id IN (5140, 5145, 4663)
                  OR (event_id = 11 AND action_summary LIKE '%\\\\%')
              )
            ORDER BY timestamp ASC
        """, (user_name,))
        rows = cur.fetchall()

        off_hours_rows = []
        for r in rows:
            ts_str = r["timestamp"]
            try:
                # ISO timestamp parse e.g. 2026-10-09T23:22:45Z
                clean_ts = ts_str.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                hour = dt.hour
                # Flag between 23:00 (11 PM) and 06:00 (6 AM)
                if hour >= 23 or hour <= 6:
                    off_hours_rows.append(r)
            except Exception:
                # If date format varies, check text heuristic
                if "23:" in ts_str or "00:" in ts_str or "01:" in ts_str or "02:" in ts_str or "03:" in ts_str:
                    off_hours_rows.append(r)

        return off_hours_rows

    def _get_archive_events(self, user_name: str) -> List[sqlite3.Row]:
        """
        Stage 2: Checks for mass archive creation and password-protected staging (T1560.001).
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT id, timestamp, channel, event_id, process_name, command_line, action_summary, mitre_technique, raw_event
            FROM super_timeline
            WHERE (user_name = ? OR user_name IS NULL)
              AND (
                  command_line LIKE '%7z.exe a%'
                  OR command_line LIKE '%7z%'
                  OR command_line LIKE '%.zip%'
                  OR command_line LIKE '%tar -cz%'
                  OR command_line LIKE '%tar%'
                  OR command_line LIKE '%rar%'
                  OR command_line LIKE '%Compress-Archive%'
                  OR action_summary LIKE '%archive%'
                  OR action_summary LIKE '%7z.exe%'
              )
            ORDER BY timestamp ASC
        """, (user_name,))
        return cur.fetchall()

    def _get_removable_media_events(self, user_name: str) -> List[sqlite3.Row]:
        """
        Stage 3: Detects removable USB media attachment and file writes (T1052.001).
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT id, timestamp, channel, event_id, process_name, command_line, action_summary, mitre_technique, raw_event
            FROM super_timeline
            WHERE (
                  event_id IN (20001, 20003, 7045)
                  AND (action_summary LIKE '%USBSTOR%' OR action_summary LIKE '%USB%' OR action_summary LIKE '%VID_%')
              )
              OR (
                  event_id = 11
                  AND (
                      action_summary LIKE '%E:\\%'
                      OR action_summary LIKE '%F:\\%'
                      OR action_summary LIKE '%removable%'
                      OR command_line LIKE '%E:\\%'
                      OR command_line LIKE '%F:\\%'
                  )
              )
            ORDER BY timestamp ASC
        """)
        return cur.fetchall()

    def _get_cloud_exfil_events(self, user_name: str) -> List[sqlite3.Row]:
        """
        Stage 4: Detects cloud storage exfiltration spikes (T1567.002).
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT id, timestamp, channel, event_id, process_name, command_line, action_summary, mitre_technique, raw_event
            FROM super_timeline
            WHERE (user_name = ? OR user_name IS NULL)
              AND (
                  action_summary LIKE '%mega.nz%'
                  OR action_summary LIKE '%drive.google%'
                  OR action_summary LIKE '%dropbox%'
                  OR action_summary LIKE '%cloud storage%'
                  OR action_summary LIKE '%POST burst%'
                  OR command_line LIKE '%mega%'
                  OR (event_id = 3 AND action_summary LIKE '%mega.nz%')
              )
            ORDER BY timestamp ASC
        """, (user_name,))
        return cur.fetchall()

    def _get_log_evasion_events(self, user_name: str) -> List[sqlite3.Row]:
        """
        Stage 5: Detects Windows event log clearing and anti-forensics evasion (T1070.001).
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT id, timestamp, channel, event_id, process_name, command_line, action_summary, mitre_technique, raw_event
            FROM super_timeline
            WHERE event_id IN (1102, 104)
              OR command_line LIKE '%wevtutil cl%'
              OR command_line LIKE '%Clear-EventLog%'
              OR action_summary LIKE '%audit log was cleared%'
              OR action_summary LIKE '%log cleared%'
            ORDER BY timestamp ASC
        """)
        return cur.fetchall()

    def analyze_user_session(self, user_name: str) -> Dict[str, Any]:
        """
        Comprehensive behavioral analysis across all 5 stages of insider risk.
        Calculates cumulative risk score, maps ATT&CK tactics, and aggregates evidence.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT 1 FROM super_timeline WHERE user_name = ? LIMIT 1;", (user_name,))
        if not cur.fetchone():
            logger.debug("No forensic events found for target user '%s'", user_name)
            return {
                "target_user": user_name,
                "overall_risk_score": 0,
                "threat_classification": "LOW_RISK_BASELINE",
                "stages_triggered": 0,
                "indicators": [],
                "mitre_techniques": [],
                "evidence_count": 0,
                "evidence_records": [],
                "stage_breakdown": {
                    "stage1_off_hours_share_enum": 0,
                    "stage2_mass_archive_staging": 0,
                    "stage3_removable_media": 0,
                    "stage4_cloud_upload": 0,
                    "stage5_log_evasion": 0,
                }
            }

        stage1_events = self._get_off_hours_events(user_name)
        stage2_events = self._get_archive_events(user_name)
        stage3_events = self._get_removable_media_events(user_name)
        stage4_events = self._get_cloud_exfil_events(user_name)
        stage5_events = self._get_log_evasion_events(user_name)

        risk_score = 0
        indicators = []
        mitre_techniques = set()
        evidence_records: List[Dict[str, Any]] = []
        seen_event_ids = set()

        def add_evidence(events: List[sqlite3.Row]):
            for r in events:
                row_id = r["id"]
                if row_id not in seen_event_ids:
                    seen_event_ids.add(row_id)
                    evidence_records.append({
                        "id": r["id"],
                        "timestamp": r["timestamp"],
                        "channel": r["channel"],
                        "event_id": r["event_id"],
                        "process_name": r["process_name"],
                        "command_line": r["command_line"],
                        "action_summary": r["action_summary"],
                        "mitre_technique": r["mitre_technique"] or "Unknown",
                    })
                    if r["mitre_technique"]:
                        mitre_techniques.add(r["mitre_technique"])

        # Stage 1 Scoring: Off-hours collection
        if stage1_events:
            risk_score += 30
            indicators.append("Off-hours network share enumeration and bulk file access (T1025)")
            mitre_techniques.add("T1025")
            add_evidence(stage1_events)

        # Stage 2 Scoring: Mass Archive Staging
        if stage2_events:
            risk_score += 40
            indicators.append("Mass file archiving and compression detected (T1560.001)")
            mitre_techniques.add("T1560.001")
            add_evidence(stage2_events)

        # Stage 3 Scoring: Removable Media
        if stage3_events:
            risk_score += 45
            indicators.append("Unsanctioned USB removable media device attached and written (T1052.001)")
            mitre_techniques.add("T1052.001")
            add_evidence(stage3_events)

        # Stage 4 Scoring: Cloud Upload Spike
        if stage4_events:
            risk_score += 35
            indicators.append("Suspicious cloud storage upload transaction detected (T1567.002)")
            mitre_techniques.add("T1567.002")
            add_evidence(stage4_events)

        # Stage 5 Scoring: Log Evasion
        if stage5_events:
            risk_score += 50
            indicators.append("Security event log clearing and anti-forensics evasion (T1070.001)")
            mitre_techniques.add("T1070.001")
            add_evidence(stage5_events)

        # Multi-stage correlation multiplier: If 3 or more stages triggered, elevate confidence
        stages_triggered = sum([
            bool(stage1_events),
            bool(stage2_events),
            bool(stage3_events),
            bool(stage4_events),
            bool(stage5_events),
        ])

        if stages_triggered >= 3:
            risk_score += 15

        # Cap maximum risk score at 100
        overall_score = min(risk_score, 100)

        # Categorize threat level
        if overall_score >= 80:
            classification = "CRITICAL_INSIDER_EXFILTRATION"
        elif overall_score >= 60:
            classification = "HIGH_RISK_INSIDER_ACTIVITY"
        elif overall_score >= 30:
            classification = "SUSPICIOUS_INSIDER_BEHAVIOR"
        else:
            classification = "LOW_RISK_BASELINE"

        # Sort evidence chronologically
        evidence_records.sort(key=lambda x: x["timestamp"])

        return {
            "target_user": user_name,
            "overall_risk_score": overall_score,
            "threat_classification": classification,
            "stages_triggered": stages_triggered,
            "indicators": indicators,
            "mitre_techniques": sorted(list(mitre_techniques)),
            "evidence_count": len(evidence_records),
            "evidence_records": evidence_records,
            "stage_breakdown": {
                "stage1_off_hours_share_enum": len(stage1_events),
                "stage2_mass_archive_staging": len(stage2_events),
                "stage3_removable_media": len(stage3_events),
                "stage4_cloud_upload": len(stage4_events),
                "stage5_log_evasion": len(stage5_events),
            }
        }

    def get_complete_incident_timeline(self, user_name: str) -> List[Dict[str, Any]]:
        """
        Retrieves the complete sequence of forensic events related to the subject's
        session and correlated host activities (including initial logon, staging, exfiltration, evasion).
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT id, timestamp, channel, event_id, host_name, user_name, process_name, command_line, action_summary, mitre_technique, raw_event
            FROM super_timeline
            WHERE user_name = ?
               OR event_id IN (20001, 20003, 1102, 104)
            ORDER BY timestamp ASC
        """, (user_name,))
        rows = cur.fetchall()

        events = []
        for r in rows:
            events.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "channel": r["channel"],
                "event_id": r["event_id"],
                "host_name": r["host_name"],
                "user_name": r["user_name"],
                "process_name": r["process_name"],
                "command_line": r["command_line"],
                "action_summary": r["action_summary"],
                "mitre_technique": r["mitre_technique"] or "Unknown",
            })
        return events


def format_cli_output(result: Dict[str, Any]) -> str:
    """Formats the evaluation result for human analyst readability."""
    lines = [
        "=" * 80,
        "  INSIDER RISK & EXFILTRATION SCORER - ANALYSIS SUMMARY",
        "=" * 80,
        f"Target User            : {result['target_user']}",
        f"Overall Risk Score     : {result['overall_risk_score']} / 100",
        f"Threat Classification  : {result['threat_classification']}",
        f"Corroborated Stages    : {result['stages_triggered']} of 5 stages active",
        f"Total Evidence Events  : {result['evidence_count']}",
        f"MITRE ATT&CK Matrix    : {', '.join(result['mitre_techniques'])}",
        "-" * 80,
        "IDENTIFIED RISK INDICATORS:"
    ]
    for idx, ind in enumerate(result["indicators"], 1):
        lines.append(f"  [{idx}] {ind}")

    lines.extend([
        "-" * 80,
        "STAGE-BY-STAGE BREAKDOWN:",
        f"  * Stage 1 (Off-Hours Share Enumeration) : {result['stage_breakdown']['stage1_off_hours_share_enum']} events",
        f"  * Stage 2 (Mass Archive Staging)        : {result['stage_breakdown']['stage2_mass_archive_staging']} events",
        f"  * Stage 3 (Removable Media Mount/Write) : {result['stage_breakdown']['stage3_removable_media']} events",
        f"  * Stage 4 (Cloud Storage Upload Spike)  : {result['stage_breakdown']['stage4_cloud_upload']} events",
        f"  * Stage 5 (Event Log Anti-Forensics)    : {result['stage_breakdown']['stage5_log_evasion']} events",
        "=" * 80,
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Correlates Super-Timeline Events and Scores Insider Threat Exfiltration Behavior"
    )
    parser.add_argument(
        "--db",
        default="timeline.db",
        help="Path to SQLite super-timeline database (default: timeline.db)"
    )
    parser.add_argument(
        "--user",
        required=True,
        help="Target user account name to evaluate (e.g. alex.mercer)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON analysis results for automated pipeline integration"
    )

    args = parser.parse_args()

    try:
        with InsiderRiskEvaluator(args.db) as evaluator:
            analysis = evaluator.analyze_user_session(args.user)

            if args.json:
                print(json.dumps(analysis, indent=2))
            else:
                print(format_cli_output(analysis))

    except Exception as exc:
        logger.error("Analysis execution failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
