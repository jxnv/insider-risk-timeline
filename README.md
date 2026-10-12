# Insider Risk Lens: Super-Timeline & Multi-Stage Exfiltration Analysis Engine

[![Forensic Pipeline](https://img.shields.io/badge/forensics-pipeline-blue.svg)](#)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-green.svg)](#)
[![Database](https://img.shields.io/badge/database-SQLite%20WAL-orange.svg)](#)
[![Standards](https://img.shields.io/badge/standards-CERT%20%7C%20NIST%20SP%20800--86%20%7C%20FRE%20902-purple.svg)](#)

An enterprise-grade digital forensics and behavioral detection pipeline engineered to reconstruct multi-source Windows endpoint telemetry into a unified SQLite super-timeline, algorithmically detect coordinated insider threat exfiltration behaviors across five chronological stages, and generate cryptographically verified (SHA-256), courtroom-ready evidentiary briefs for Legal Counsel and HR Leadership.

---

## 1. System Architecture & Timeline Reconstruction Flow

```
  +-----------------------------------------------------------------------------+
  | ARTIFACT ACQUISITION LAYER (`datasets/sample_insider_evtx/`)                |
  |                                                                             |
  |  Target Endpoint Forensic Telemetry:                                        |
  |   - Windows Security Log (Security.evtx): Logon Types, 4624, 4672, 4663, 1102|
  |   - Sysmon Log (Sysmon.evtx): Process Trees (ID 1), File Creations (ID 11)  |
  |   - System Log (System.evtx): Service installs (7045), USB Drivers (20001)  |
  |   - Registry & Shellbags: USBSTOR device serial numbers, mounted volumes    |
  |   - Browser History: Chrome/Edge web upload transactions & cloud destinations|
  +--------------------------------------+--------------------------------------+
                                         |
                                         | (Orchestrated by timeline_generator.py)
                                         v
  +-----------------------------------------------------------------------------+
  | HIGH-SPEED FORENSIC PARSING ENGINES (Rust & Go Open-Source Tools)           |
  |                                                                             |
  |  [Hayabusa (Rust EVTX Engine)]    [Chainsaw (Sigma-over-EVTX Engine)]       |
  |               |                                   |                         |
  |               +-----------------+-----------------+                         |
  |                                 |                                           |
  |                                 v (Normalized Chronological Output)         |
  |                [Built-in Pure-Python Fallback Engine]                       |
  +-----------------------------------------------------------------------------+
                                    |
                                    v
  +-----------------------------------------------------------------------------+
  | UNIFIED SUPER-TIMELINE DATABASE (SQLite Engine: `timeline.db`)              |
  |                                                                             |
  |  Schema: `super_timeline` (WAL Mode enabled)                                |
  |   - timestamp, user_sid, host, event_source, event_id, action, artifact_path|
  |                                      |                                      |
  |                                      v                                      |
  |  [BEHAVIORAL RISK & EXFILTRATION SCORER: `exfil_analyzer.py`]               |
  |   - Stage 1: Off-Hours Share Enumeration (>50 files between 11PM-3AM)       |
  |   - Stage 2: Mass Archive Staging (`7z.exe a -p` or `tar -czvf`)            |
  |   - Stage 3: Removable Media Mount (USB Serial: `VID_0781&PID_5583`)        |
  |   - Stage 4: Cloud Upload Spike (Mega.nz / Google Drive POST burst)         |
  |   - Stage 5: Log Evasion Attempt (`wevtutil cl Security`)                   |
  |                                      |                                      |
  |                                      v                                      |
  +-----------------------------------------------------------------------------+
                                         |
                                         v
  +-----------------------------------------------------------------------------+
  | EVIDENTIARY CASE OUTPUTS (HR, LEGAL & EXECUTIVE DELIVERABLES)               |
  |                                                                             |
  |  1. `cases/CASE-2026-0811-EXFIL/executive_summary.md`                       |
  |     - Non-technical factual narrative tailored for General Counsel & HR     |
  |  2. `cases/CASE-2026-0811-EXFIL/chronological_evidence_table.csv`           |
  |     - Cryptographically hashed (SHA-256) immutable event chronology         |
  |  3. `playbooks/insider_risk_investigation_sop.md`                           |
  |     - Standardized repeatable procedure mapping to CERT Insider Threat Spec |
  +-----------------------------------------------------------------------------+
```

---

## 2. Threat Model & Investigation Profile

- **Incident Reference:** `CASE-2026-0811-EXFIL` / `CASE-2026-EXFIL`
- **Subject:** Alex Mercer (Senior Staff AI Infrastructure Engineer)
- **Host Workstation:** `WS-CORP-8104` (Domain: `CORP.LOCAL`)
- **Subject SID:** `S-1-5-21-3829104829-1092837461-827364519-1004`
- **Exfiltrated Assets:** 14.8 GB of proprietary AI foundational model weights and training checkpoints
- **Incident Window:** October 9, 2026, 23:14:02 UTC to October 10, 2026, 01:42:18 UTC (Standard business hours: 09:00 - 18:00)

### Multi-Stage Attack Chain:
1. **Initial Access / Off-Hours Logon:** Subject logged into workstation at 23:14:02 UTC via interactive session (LogonType 2, Security ID 4624 / MITRE T1078).
2. **Stage 1 (Off-Hours Share Enumeration):** Accessed 842 proprietary model files from `\\nas-prod\research\weights\` (Sysmon ID 11 / MITRE T1025).
3. **Stage 2 (Mass Archive Staging):** Compressed files into password-protected archive using `7z.exe a -pSecretKey2026! C:\Temp\weights_backup.7z C:\Temp\Staging\*` (Sysmon ID 1 / MITRE T1560.001).
4. **Stage 3 (Removable Media Transfer):** Inserted SanDisk Ultra USB Device (Serial: `4C53000123081110`, HardwareID: `USB\VID_0781&PID_5583`) and copied `weights_backup.7z` to volume `E:\` (System ID 20001, Sysmon ID 11 / MITRE T1052.001).
5. **Stage 4 (Cloud Exfiltration):** Executed POST burst to `https://mega.nz/api/v2/upload` transferring 4.2 GB staged segment (Sysmon ID 3 / MITRE T1567.002).
6. **Stage 5 (Anti-Forensics & Log Tampering):** Executed `wevtutil cl Security` to delete security audit event logs (Security ID 1102 / MITRE T1070.001).

---

## 3. Repository Structure

```
insider-risk-lens/
├── README.md                   # Investigation methodology, architecture, and threat model
├── requirements.txt            # Python dependencies (pandas, pyyaml, pytest)
├── bin/                        # Local directory for forensic binaries (Hayabusa / Chainsaw)
├── datasets/
│   └── sample_insider_evtx/    # Windows EVTX artifact test fixtures
│       ├── Security.evtx       # Windows Security audit log (4624, 1102)
│       ├── Sysmon.evtx         # Microsoft Sysmon log (1, 3, 11)
│       ├── System.evtx         # Windows System log (20001 PnP USB driver)
│       ├── sample_events.json  # Normalized telemetry fixture for instant fallback ingestion
│       └── README.md           # Dataset documentation & MITRE mapping
├── parser/
│   ├── __init__.py
│   ├── timeline_generator.py   # Ingests EVTX into SQLite super_timeline table
│   └── exfil_analyzer.py       # Algorithmic risk scoring for multi-stage exfil
├── reporting/
│   ├── __init__.py
│   ├── generate_case_brief.py  # Compiles factual markdown briefs from database
│   └── templates/
│       └── executive_summary_template.md # Courtroom & Legal report template
├── cases/
│   ├── CASE-2026-EXFIL/        # Mock case outputs
│   └── CASE-2026-0811-EXFIL/   # Canonical investigation deliverables
│       ├── executive_summary.md# HR & Legal evidentiary brief
│       ├── chronological_evidence_table.csv      # Normalized evidence table
│       ├── chronological_evidence_table.csv.sha256# SHA-256 verification hash
│       └── timeline_dump.csv   # Verified evidence export
├── playbooks/
│   └── insider_risk_investigation_sop.md # CERT & NIST SP 800-86 investigation SOP
├── scripts/
│   └── bootstrap_tools.py      # Binary bootstrapping and offline readiness checker
└── tests/
    ├── __init__.py
    └── test_forensic_pipeline.py # Comprehensive test suite (11 test cases)
```

---

## 4. Step-by-Step Build & Execution Guide

### Step 1: Verify Environment & Tools
```bash
# Clone repository
git clone https://github.com/jxnv/insider-risk-lens.git
cd insider-risk-lens

# Verify environment readiness or bootstrap binaries:
python3 scripts/bootstrap_tools.py
```
*Note: The pipeline operates seamlessly in air-gapped or sandbox environments using its built-in Python forensic engine with zero mandatory external dependencies.*

### Step 2: Ingest EVTX Telemetry into SQLite Super-Timeline
```bash
python3 parser/timeline_generator.py \
  --evtx-dir datasets/sample_insider_evtx/ \
  --output-db timeline.db \
  --engine auto
```
- Ingests Windows Security, Sysmon, and System logs.
- Enables SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL`).
- Builds composite indices on `(timestamp, user_name)`, `event_id`, and `mitre_technique`.

### Step 3: Run the Automated Behavioral Risk Scorer
```bash
python3 parser/exfil_analyzer.py \
  --db timeline.db \
  --user "alex.mercer"
```
To obtain machine-readable JSON output for automated SIEM/SOAR pipelines:
```bash
python3 parser/exfil_analyzer.py --db timeline.db --user "alex.mercer" --json
```

### Step 4: Generate Courtroom-Ready Case Brief for HR & Legal
```bash
python3 reporting/generate_case_brief.py \
  --case-id CASE-2026-0811-EXFIL \
  --db timeline.db \
  --user "alex.mercer"
```
Deliverables produced in `cases/CASE-2026-0811-EXFIL/`:
- `executive_summary.md`: Non-technical factual narrative, chronological timeline table, and legal recommendations.
- `chronological_evidence_table.csv`: Normalized evidence export.
- `chronological_evidence_table.csv.sha256`: Cryptographic SHA-256 checksum for chain-of-custody verification.

### Step 5: Execute Automated Verification Test Suite
```bash
# Execute using unittest runner:
python3 -m unittest discover tests -v

# Or execute test script directly:
python3 tests/test_forensic_pipeline.py -v

# Or execute with pytest (if installed):
pytest tests/test_forensic_pipeline.py -v
```

---

## 5. Security & Forensic Best Practices

1. **SQL Injection Defense:** All database queries utilize strict parameterized SQL (`?` placeholders). User input and telemetry strings are never interpolated directly into SQL syntax.
2. **Directory Traversal Protection:** All case IDs and paths undergo regex filtering (`^[A-Za-z0-9_-]+$`) and path boundary verification (`Path.resolve().startswith()`), strictly preventing traversal exploits.
3. **Safe Subprocess Execution:** External forensic binaries (Hayabusa/Chainsaw) are invoked using explicit argument lists without `shell=True`.
4. **Cryptographic Integrity (FRE 902):** Cryptographic SHA-256 hashes are computed using memory-efficient streaming buffers for all evidence exports, databases, and artifacts to satisfy legal admissibility standards.
5. **Zero-Dependency Resilience:** Core analysis runs entirely on the standard Python library (`sqlite3`, `hashlib`, `json`, `csv`, `datetime`, `unittest`), guaranteeing immediate execution in restricted air-gapped forensic environments.
