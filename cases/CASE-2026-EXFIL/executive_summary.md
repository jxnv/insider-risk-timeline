# FORENSIC INVESTIGATION REPORT: CASE-2026-EXFIL
**Subject:** Alex Mercer (Senior Staff AI Infrastructure Engineer)  
**Date of Incident:** October 9, 2026  
**Investigating Lead:** Justin Chamreun, M.S., CISSP (Senior Detection & Forensics Engineer)  
**Audience:** Legal Counsel, HR Leadership, VP of Information Security  

---

### 1. EXECUTIVE SUMMARY & VERDICT
Between 23:14:02 UTC and 00:41:05 UTC on October 9, 2026, endpoint forensics confirmed that subject **Alex Mercer** engaged in deliberate, unsanctioned collection, compression, and exfiltration of proprietary source code and AI model checkpoint weights. This activity occurred outside standard working hours, originated from a managed corporate workstation (WS-CORP-8104), and concluded with a USB storage transfer, cloud exfiltration spike, and an attempted deletion of the local security event logs.

**Forensic Classification:** Confirmed Malicious Insider Exfiltration (100% Confidence)  
**Overall Insider Risk Score:** 100 / 100 (CRITICAL_INSIDER_EXFILTRATION)  
**Total Volume Exfiltrated:** Approximately 14.8 GB across encrypted archives.  

---

### 2. FACTUAL CHRONOLOGICAL EVIDENCE TIMELINE
*All timestamps recorded in UTC. Event hashes verified against SQLite super-timeline.*

| Timestamp (UTC) | Source / Event ID | Artifact / Action | Adversary Technique |
| :--- | :--- | :--- | :--- |
| **23:14:02** | Security (4624) | Successful Interactive Logon (LogonType 2) via WS-CORP-8104 | Valid Accounts (T1078) |
| **23:22:45** | Sysmon (11) | Subject bulk-accessed and read 842 proprietary source files from network share \\nas-prod\research\weights\ | Data from Network Drive (T1025) |
| **23:48:10** | Sysmon (1) | Executed 7z.exe a -pSecretKey2026! C:\Temp\weights_backup.7z C:\Temp\Staging\* | Archive via Utility (T1560.001) |
| **00:15:33** | System (20001) | Plug-and-Play driver loaded for SanDisk Ultra USB Device (Serial: 4C53000123081110, HardwareID: USBSTOR\DiskSanDisk_Ultra___________1.00, VID_0781&PID_5583) | Removable Media (T1052.001) |
| **00:18:22** | Sysmon (11) | File weights_backup.7z written to mounted volume E:\ (Removable Storage) | Exfiltration to USB (T1052) |
| **00:32:14** | Sysmon (3) | Network POST burst to cloud storage destination https://mega.nz/api/v2/upload (DestinationIp: 31.216.145.8, DestinationPort: 443, Domain: mega.nz) | Exfiltration to Cloud Storage (T1567.002) |
| **00:41:05** | Security (1102) | The Windows Security audit log was cleared via wevtutil cl Security | Indicator Removal (T1070.001) |

---

### 3. LEGAL & REMEDIATION RECOMMENDATIONS
1. **Immediate Revocation:** Terminate all active Okta, AWS IAM, and GitHub SSO session tokens for `alex.mercer`.
2. **Device Seizure:** Preserve physical custody of workstation `WS-CORP-8104` under formal chain of custody.
3. **Legal Notice:** Subpoena serial number `4C53000123081110` for hardware recovery.
4. **Third-Party Preservation Notice:** Issue preservation letter to Cloud Storage Providers (Mega.nz) citing targeted IP transactions.

---

### 4. CRYPTOGRAPHIC EVIDENCE INTEGRITY MANIFEST
All digital evidence exports, timelines, and analytical databases are cryptographically hashed using SHA-256 for courtroom evidentiary admissibility and strict chain of custody adherence:

| Artifact File | SHA-256 Digest | Status |
| :--- | :--- | :--- |
| `chronological_evidence_table.csv` | `7a0424a8d0da36ed70ce582aef630a88b431108a3746225a4072fa43713bb690` | Verified Immutable |
| `timeline.db` | `1035412548bf44bdf6244bdb951d6463703796c41a10b613c639a37122881307` | Source Super-Timeline Verified |
