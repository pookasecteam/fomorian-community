# T1036.003 - Masquerading: Rename System Utilities

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1036.003 |
| Tactic | Defense Evasion (TA0005) |
| Name | Masquerading: Rename System Utilities |
| Platforms | Windows, Linux, macOS |
| Data Sources | Process, File |

## Description

Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing.

## Attack Variations

### 001 - Renamed cmd.exe
cmd.exe copied and renamed to evade detection.
- **Detection:** Process name/path mismatch
- **Severity:** HIGH

### 002 - Renamed PowerShell
powershell.exe renamed to bypass controls.
- **Detection:** OriginalFileName mismatch
- **Severity:** HIGH

### 003 - Renamed certutil
certutil.exe renamed to evade LOLBin detection.
- **Detection:** Hash/OriginalFileName mismatch
- **Severity:** HIGH

## Detection Logic

- Compare OriginalFileName to actual process name
- Match process hash against known system utilities
- Detect system binaries running from user directories
- Alert on name/path anomalies

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-renamed-cmd.json | Renamed cmd.exe | HIGH - Should trigger |
| 002-renamed-powershell.json | Renamed PowerShell | HIGH - Should trigger |
