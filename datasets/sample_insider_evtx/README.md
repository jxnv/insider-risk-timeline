# Forensic Test Artifacts: Insider Exfiltration Telemetry

This directory contains endpoint forensic telemetry captured during an active insider threat simulation.

## Case Profile: CASE-2026-0811-EXFIL
- **Subject User:** `alex.mercer` (Senior Staff AI Infrastructure Engineer)
- **Subject Workstation:** `WS-CORP-8104`
- **Domain:** `CORP.LOCAL`
- **User SID:** `S-1-5-21-3829104829-1092837461-827364519-1004`
- **Incident Window:** 2026-10-09 23:14:02 UTC to 2026-10-10 01:42:18 UTC

## Artifact Files

| Artifact | Source Type | Key Forensic Evidence Captured |
| :--- | :--- | :--- |
| `Security.evtx` | Windows Security Audit Log | Event 4624 (Off-hours Interactive Logon Type 2), Event 1102 (Security audit log wiped) |
| `Sysmon.evtx` | Microsoft Sysmon Log | Event 1 (Process execution of `7z.exe` with password staging, `wevtutil cl Security`), Event 11 (Bulk file access on `\\nas-prod\research\weights\`, file write to removable volume `E:\`), Event 3 (Network upload burst to `mega.nz:443`) |
| `System.evtx` | Windows System Log | Event 20001 (Plug-and-Play driver loaded for SanDisk Ultra USB Device: `VID_0781&PID_5583`, Serial: `4C53000123081110`) |
| `sample_events.json` | Normalized Telemetry Fixture | Structured chronological event sequence for automated fallback ingestion and testing |

## MITRE ATT&CK Mapping
- **T1078 (Valid Accounts):** Off-hours interactive console logon
- **T1025 (Data from Network Drive):** Automated mass enumeration of proprietary model weights on network share
- **T1560.001 (Archive via Utility):** Staging and encryption using 7-Zip (`7z.exe a -pSecretKey2026!`)
- **T1052.001 (Exfiltration to Removable Media):** Unsanctioned USB flash drive mounted and archive transferred
- **T1567.002 (Exfiltration Over Web Service - Cloud Storage):** POST burst to Mega.nz storage
- **T1070.001 (Indicator Removal - Clear Windows Event Logs):** Attempted audit log wipe via `wevtutil cl Security`
