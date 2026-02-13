# T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1548.002 |
| Tactic | Privilege Escalation (TA0004), Defense Evasion (TA0005) |
| Name | Abuse Elevation Control Mechanism: Bypass User Account Control |
| Platforms | Windows |
| Data Sources | Process, Windows Registry, Command |

## Description

Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions.

## Common UAC Bypass Techniques

- **fodhelper.exe**: Registry-based bypass via ms-settings
- **eventvwr.exe**: Registry-based bypass via mscfile
- **computerdefaults.exe**: Registry-based bypass
- **sdclt.exe**: Registry-based bypass for backup settings

## Attack Variations

### 001 - fodhelper.exe UAC Bypass
Registry modification followed by fodhelper.exe execution.
- **Detection:** Registry key modification + fodhelper spawn
- **Severity:** HIGH

### 002 - eventvwr.exe UAC Bypass
eventvwr.exe registry hijack for UAC bypass.
- **Detection:** mscfile registry modification + eventvwr
- **Severity:** HIGH

### 003 - CMSTP UAC Bypass
CMSTP.exe INF file bypass.
- **Detection:** CMSTP with /au flag
- **Severity:** HIGH

## Detection Logic

- Monitor registry modifications to Shell\Open\command keys
- Watch for fodhelper.exe, eventvwr.exe spawning child processes
- Detect IntegrityLevel changes from Medium to High
- Alert on known UAC bypass patterns

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-fodhelper-bypass.json | fodhelper UAC bypass | HIGH - Should trigger |
| 002-eventvwr-bypass.json | eventvwr UAC bypass | HIGH - Should trigger |
