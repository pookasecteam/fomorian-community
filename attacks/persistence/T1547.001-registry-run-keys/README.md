# T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1547.001 |
| Tactic | Persistence (TA0003) |
| Name | Boot or Logon Autostart Execution: Registry Run Keys |
| Platforms | Windows |
| Data Sources | Windows Registry, Process |

## Description

Adversaries may achieve persistence by adding a program to a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.

## Common Registry Locations

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

## Attack Variations

### 001 - HKCU Run Key Persistence
User-level run key persistence via reg.exe.
- **Detection:** Sysmon Event 12/13 for Run key modification
- **Severity:** HIGH

### 002 - HKLM Run Key (Admin)
Machine-level run key requiring admin.
- **Detection:** Registry modification with elevated privileges
- **Severity:** CRITICAL

### 003 - PowerShell Registry Persistence
PowerShell used to set registry persistence.
- **Detection:** PowerShell Set-ItemProperty for Run keys
- **Severity:** HIGH

## Detection Logic

- Monitor Sysmon Event 12/13 for registry modifications
- Watch for reg.exe targeting Run/RunOnce keys
- Detect PowerShell registry cmdlets modifying autostart locations
- Alert on new entries pointing to suspicious locations (Temp, AppData, Public)

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-hkcu-run-key.json | User run key | HIGH - Should trigger |
| 002-hklm-run-key.json | Machine run key | CRITICAL - Should trigger |
| 003-powershell-registry.json | PS registry mod | HIGH - Should trigger |
