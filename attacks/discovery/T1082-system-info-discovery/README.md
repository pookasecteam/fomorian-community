# T1082 - System Information Discovery

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1082 |
| Tactic | Discovery (TA0007) |
| Name | System Information Discovery |
| Platforms | Windows, Linux, macOS |
| Data Sources | Process, Command |

## Description

An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.

## Attack Variations

### 001 - systeminfo Command
Basic systeminfo command execution.
- **Detection:** systeminfo.exe execution
- **Severity:** LOW

### 002 - WMI System Query
WMI queries for system information.
- **Detection:** wmic os get command
- **Severity:** LOW

### 003 - PowerShell System Enumeration
Get-ComputerInfo and related cmdlets.
- **Detection:** Get-ComputerInfo PowerShell
- **Severity:** LOW

## Detection Logic

- Monitor for systeminfo.exe execution
- Watch for WMI system queries
- Detect bulk system enumeration patterns
- Alert when combined with other discovery techniques

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-systeminfo-enum.json | systeminfo execution | LOW - Should trigger |
| 002-wmi-system-query.json | WMI system query | LOW - Should trigger |
