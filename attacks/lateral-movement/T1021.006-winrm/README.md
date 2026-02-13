# T1021.006 - Remote Services: Windows Remote Management

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1021.006 |
| Tactic | Lateral Movement (TA0008) |
| Name | Remote Services: Windows Remote Management |
| Platforms | Windows |
| Data Sources | Network Traffic, Process, Command |

## Description

Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system.

## Attack Variations

### 001 - Enter-PSSession Remote Shell
Using PowerShell Enter-PSSession for remote access.
- **Detection:** Enter-PSSession, New-PSSession cmdlets
- **Severity:** HIGH

### 002 - Invoke-Command Remote Execution
Using Invoke-Command to run commands remotely.
- **Detection:** Invoke-Command with -ComputerName
- **Severity:** HIGH

### 003 - winrs.exe Remote Shell
Using winrs.exe for remote command execution.
- **Detection:** winrs.exe command execution
- **Severity:** HIGH

## Detection Logic

- Monitor for Enter-PSSession, Invoke-Command cmdlets
- Watch for winrs.exe execution
- Detect WinRM connections (port 5985/5986)
- Alert on remote PowerShell sessions

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-invoke-command.json | Invoke-Command lateral | HIGH - Should trigger |
| 002-winrs-shell.json | winrs remote shell | HIGH - Should trigger |
