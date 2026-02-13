# T1543.003 - Create or Modify System Process: Windows Service

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1543.003 |
| Tactic | Persistence (TA0003), Privilege Escalation (TA0004) |
| Name | Create or Modify System Process: Windows Service |
| Platforms | Windows |
| Data Sources | Windows Registry, Service, Process, Command |

## Description

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. Services are programs that perform system functions and run in the background. Windows service configuration information is stored in the Registry.

## Attack Variations

### 001 - sc.exe Service Creation
Service created using sc.exe command.
- **Detection:** sc.exe create command
- **Severity:** CRITICAL

### 002 - PowerShell New-Service
Service created via PowerShell New-Service cmdlet.
- **Detection:** New-Service PowerShell command
- **Severity:** CRITICAL

### 003 - Service Binary Path Modification
Modifying existing service to execute malicious binary.
- **Detection:** sc.exe config binpath modification
- **Severity:** CRITICAL

## Detection Logic

- Monitor sc.exe create/config commands
- Watch for PowerShell New-Service cmdlet usage
- Detect services pointing to suspicious binaries (Temp, AppData, Public)
- Alert on service creation with SYSTEM privileges

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-sc-service-create.json | sc.exe service creation | CRITICAL - Should trigger |
| 002-binpath-modification.json | Service binary hijack | CRITICAL - Should trigger |
