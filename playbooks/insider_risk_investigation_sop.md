# STANDARD OPERATING PROCEDURE (SOP): INSIDER RISK & DATA EXFILTRATION INVESTIGATION

**Document Control Identifier:** SOP-IR-2026-004  
**Classification:** TLP:AMBER+STRICT / Privileged & Confidential (Attorney-Client / Work-Product)  
**Effective Date:** October 2026  
**Governing Standards:** CERT Guide to Insider Threats (CMU/SEI), NIST SP 800-86, ISO/IEC 27037, Federal Rules of Evidence (FRE 901/902)  
**Target Roles:** Detection Engineers, Digital Forensics & Incident Response (DFIR) Analysts, General Counsel, HR People Partners  

---

## 1. PURPOSE & APPLICABILITY
This Standard Operating Procedure (SOP) establishes a repeatable, defensible, and legally admissible investigative workflow for detecting, triaging, analyzing, and documenting malicious insider threat behaviors, data theft, and intellectual property (IP) exfiltration.

It covers forensic artifact acquisition from corporate Windows endpoints, timeline normalization into high-speed relational database storage, algorithmic threat scoring, and packaging courtroom-ready deliverables.

---

## 2. LEGAL & PRIVACY GOVERNANCE
1. **Legal Hold Authorization:** No proactive endpoint interrogation or network monitoring targeted at an individual employee may begin without written concurrence from Legal Counsel (Employment / Litigation) and HR Leadership.
2. **Acceptable Use Policy (AUP) Basis:** All forensic analysis relies on corporate ownership of hardware, network telemetry, and explicit employee acknowledgment of monitoring consent.
3. **Chain of Custody (ISO/IEC 27037):** Every disk image, EVTX artifact, memory dump, or triage package must have its SHA-256 hash computed immediately upon acquisition and logged in the physical/digital Evidence Custody Form.

---

## 3. INVESTIGATION WORKFLOW OVERVIEW

```
  +-------------------------------------------------------------------------+
  | PHASE 1: TRIGGER & LEGAL HOLD CONCURRENCE                               |
  |  - DLP alert, resignation notice, anomalous access audit                |
  |  - Legal hold issued; silent Okta/IAM privilege freeze prepared         |
  +------------------------------------+------------------------------------+
                                       |
                                       v
  +-------------------------------------------------------------------------+
  | PHASE 2: FORENSIC TELEMETRY ACQUISITION (Live / Triage)                 |
  |  - Windows Event Logs: Security.evtx, Sysmon.evtx, System.evtx          |
  |  - Registry: SYSTEM, SOFTWARE, NTUSER.DAT (USBSTOR & Shellbags)         |
  |  - Browser Artifacts: Chrome/Edge SQLite History & Cache                |
  +------------------------------------+------------------------------------+
                                       |
                                       v
  +-------------------------------------------------------------------------+
  | PHASE 3: SUPER-TIMELINE NORMALIZATION (`timeline_generator.py`)          |
  |  - Parse via Hayabusa (Rust) / Chainsaw (Go/Rust) / Built-in fallback   |
  |  - Ingest into SQLite WAL super-timeline database (`timeline.db`)        |
  +------------------------------------+------------------------------------+
                                       |
                                       v
  +-------------------------------------------------------------------------+
  | PHASE 4: BEHAVIORAL EXFILTRATION SCORING (`exfil_analyzer.py`)          |
  |  - Stage 1: Off-Hours Share Enumeration (>50 files between 11PM-3AM)    |
  |  - Stage 2: Mass Archive Staging (7z.exe, tar, zip password staging)    |
  |  - Stage 3: Removable Media Mount (USB serial & drive write tracking)   |
  |  - Stage 4: Cloud Storage Exfiltration (POST bursts to Mega/Drive)       |
  |  - Stage 5: Anti-Forensics & Log Tampering (wevtutil cl Security)       |
  +------------------------------------+------------------------------------+
                                       |
                                       v
  +-------------------------------------------------------------------------+
  | PHASE 5: EXECUTIVE & COURTROOM PACKAGING (`generate_case_brief.py`)      |
  |  - Executive Summary (`cases/<CASE-ID>/executive_summary.md`)           |
  |  - Hashed Chronological Evidence Table (`chronological_evidence_table`) |
  |  - Containment, device seizure, account revocation & legal subpoenas    |
  +-------------------------------------------------------------------------+
```

---

## 4. DETAILED PROCEDURAL STEPS

### Step 4.1: Forensic Evidence Acquisition
Execute live endpoint triage or acquire forensic disk images via write-blocker:
- Target Paths:
  - `%SystemRoot%\System32\Winevt\Logs\Security.evtx`
  - `%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`
  - `%SystemRoot%\System32\Winevt\Logs\System.evtx`
  - `%SystemRoot%\System32\config\SYSTEM` (Registry USBSTOR entries)
  - `C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Default\History`

Store all acquired artifacts in an encrypted, read-only directory: `datasets/<CASE-NAME>/` and immediately record SHA-256 digests.

### Step 4.2: Super-Timeline Ingestion
Run the automated normalization pipeline:
```bash
python3 parser/timeline_generator.py \
  --evtx-dir datasets/sample_insider_evtx/ \
  --output-db timeline.db \
  --engine auto
```
- Validates binary magic signatures (`ElfFile\x00`).
- Normalizes event timestamps into ISO-8601 UTC.
- Builds b-tree indexed relational tables with WAL mode.

### Step 4.3: Multi-Stage Threat Evaluation
Execute behavioral scoring against the target user identity:
```bash
python3 parser/exfil_analyzer.py \
  --db timeline.db \
  --user "alex.mercer" \
  --json
```
- Heuristic Thresholds:
  - **Score >= 80:** `CRITICAL_INSIDER_EXFILTRATION` (Immediate containment triggered)
  - **Score 60 - 79:** `HIGH_RISK_INSIDER_ACTIVITY` (Escalate to Legal & HR)
  - **Score 30 - 59:** `SUSPICIOUS_INSIDER_BEHAVIOR` (Expanded monitoring window)

### Step 4.4: Deliverable Compilation & Cryptographic Verification
Generate the formal case packet:
```bash
python3 reporting/generate_case_brief.py \
  --case-id "CASE-2026-0811-EXFIL" \
  --db timeline.db \
  --user "alex.mercer" \
  --output-dir cases
```
Verify the generated checksums:
```bash
sha256sum -c cases/CASE-2026-0811-EXFIL/chronological_evidence_table.csv.sha256
```

---

## 5. INCIDENT CONTAINMENT & LEGAL REMEDIATION PROTOCOL

When risk score reaches `CRITICAL_INSIDER_EXFILTRATION`:
1. **Access Revocation:**
   - Terminate active SSO sessions (Okta, Entra ID, Ping).
   - Invalidate refresh tokens and OAuth grants.
   - Revoke AWS/GCP/Azure IAM credentials and SSH authorized keys.
2. **Workstation Seizure:**
   - Dispatch corporate security or local IT to retrieve workstation.
   - Do NOT reboot or power cycle if memory analysis is required; isolate network interface via managed switch/EDR containment.
3. **Subpoena & Preservation Notices:**
   - Legal Counsel issues dynamic preservation letters to third-party cloud destinations identified in Stage 4 (e.g. Mega.nz, Google Drive, Microsoft OneDrive).
   - Identify USB serial numbers from Stage 3 for physical retrieval demand letters.

---

## 6. MITRE ATT&CK INSIDER THREAT MATRIX REFERENCE

| Stage | MITRE Technique | Description | Log Telemetry |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1078 (Valid Accounts) | Legitimate employee credentials used off-hours | Security 4624 (LogonType 2 / 10) |
| **Collection** | T1025 (Data from Network Drive) | Mass file enumeration across file servers & shares | Sysmon 11, Security 5145, 4663 |
| **Staging** | T1560.001 (Archive via Utility) | Compression and encryption using 7-Zip, tar, or zip | Sysmon 1 (CommandLine `7z.exe a -p`) |
| **Exfiltration 1** | T1052.001 (Removable Media) | Transferring staged archives to USB thumb drive | System 20001 (PnP), Sysmon 11 (`E:\`) |
| **Exfiltration 2** | T1567.002 (Cloud Storage) | Web POST burst uploading archives to external cloud | Sysmon 3, Browser History / Proxy |
| **Defense Evasion**| T1070.001 (Clear Event Logs) | Wiping security event logs to erase forensic trace | Security 1102, Sysmon 1 (`wevtutil cl`) |

---

## 7. AUDIT LOG & CONTINUOUS IMPROVEMENT
Post-investigation, conduct a blameless post-mortem with Legal, Security, and Engineering leaders to evaluate data access governance (Least Privilege), network segmentation around model checkpoints, and DLP detection fidelity.
