# FORENSIC INVESTIGATION REPORT: {case_id}
**Subject:** {subject_name} ({subject_title})  
**Date of Incident:** {incident_date}  
**Investigating Lead:** {investigator_lead}  
**Audience:** Legal Counsel, HR Leadership, VP of Information Security  

---

### 1. EXECUTIVE SUMMARY & VERDICT
Between {start_time_utc} UTC and {end_time_utc} UTC on {incident_date}, endpoint forensics confirmed that subject **{subject_name}** engaged in deliberate, unsanctioned collection, compression, and exfiltration of proprietary source code and AI model checkpoint weights. This activity occurred outside standard working hours, originated from a managed corporate workstation ({host_name}), and concluded with a USB storage transfer, cloud exfiltration spike, and an attempted deletion of the local security event logs.

**Forensic Classification:** {forensic_classification} ({confidence_level} Confidence)  
**Overall Insider Risk Score:** {risk_score} / 100 ({threat_level})  
**Total Volume Exfiltrated:** Approximately {exfil_volume} across encrypted archives.  

---

### 2. FACTUAL CHRONOLOGICAL EVIDENCE TIMELINE
*All timestamps recorded in UTC. Event hashes verified against SQLite super-timeline.*

| Timestamp (UTC) | Source / Event ID | Artifact / Action | Adversary Technique |
| :--- | :--- | :--- | :--- |
{timeline_rows}

---

### 3. LEGAL & REMEDIATION RECOMMENDATIONS
1. **Immediate Revocation:** Terminate all active Okta, AWS IAM, and GitHub SSO session tokens for `{subject_user_id}`.
2. **Device Seizure:** Preserve physical custody of workstation `{host_name}` under formal chain of custody.
3. **Legal Notice:** Subpoena serial number `{usb_serial}` for hardware recovery.
4. **Third-Party Preservation Notice:** Issue preservation letter to Cloud Storage Providers (Mega.nz) citing targeted IP transactions.

---

### 4. CRYPTOGRAPHIC EVIDENCE INTEGRITY MANIFEST
All digital evidence exports, timelines, and analytical databases are cryptographically hashed using SHA-256 for courtroom evidentiary admissibility and strict chain of custody adherence:

| Artifact File | SHA-256 Digest | Status |
| :--- | :--- | :--- |
| `chronological_evidence_table.csv` | `{csv_sha256}` | Verified Immutable |
| `timeline.db` | `{db_sha256}` | Source Super-Timeline Verified |
