# T1047 - Windows Management Instrumentation (WMI)

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1047 |
| Tactic | Execution (TA0002) |
| Name | Windows Management Instrumentation |
| Platforms | Windows |
| Data Sources | Process, Command, Network Traffic |

## Description

Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is an administration feature that provides a uniform environment to access Windows system components. WMI can be used locally or remotely.

## Attack Variations

### 001 - WMI Process Creation
Local WMI process creation via wmic.exe.
- **Detection:** wmic.exe process create command
- **Severity:** HIGH

### 002 - Remote WMI Execution
WMI executing process on remote system.
- **Detection:** wmic.exe with /node: parameter
- **Severity:** CRITICAL

### 003 - WMI Event Subscription Persistence
WMI event subscription for persistence.
- **Detection:** WMI subscription events (Event IDs 19, 20, 21)
- **Severity:** CRITICAL

## Detection Logic

- Monitor wmic.exe command lines containing "process call create"
- Detect remote WMI (/node: parameter)
- Watch for WMI event subscription creation (Sysmon 19-21)
- Alert on wmiprvse.exe spawning suspicious processes

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-wmic-process-create.json | Local WMI exec | HIGH - Should trigger |
| 002-wmic-remote-exec.json | Remote WMI exec | CRITICAL - Should trigger |
| 003-wmi-subscription.json | WMI persistence | CRITICAL - Should trigger |
