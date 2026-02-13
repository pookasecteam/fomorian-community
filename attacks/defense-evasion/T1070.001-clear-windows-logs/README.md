# T1070.001 - Indicator Removal on Host: Clear Windows Event Logs

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1070.001 |
| Tactic | Defense Evasion (TA0005) |
| Name | Indicator Removal on Host: Clear Windows Event Logs |
| Platforms | Windows |
| Data Sources | Process, Command, Windows Event Logs |

## Description

Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications.

## Attack Variations

### 001 - wevtutil Clear Logs
Using wevtutil to clear event logs.
- **Detection:** wevtutil cl command
- **Severity:** CRITICAL

### 002 - PowerShell Clear-EventLog
PowerShell Clear-EventLog cmdlet.
- **Detection:** Clear-EventLog PowerShell command
- **Severity:** CRITICAL

### 003 - Event Log Service Stop
Stopping the Windows Event Log service.
- **Detection:** net stop EventLog
- **Severity:** CRITICAL

## Detection Logic

- Monitor wevtutil.exe cl/clear-log commands
- Watch for Clear-EventLog PowerShell cmdlet
- Detect Windows Security Event 1102 (audit log cleared)
- Alert on Event Log service stop attempts

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-wevtutil-clear.json | wevtutil log clear | CRITICAL - Should trigger |
| 002-powershell-clear.json | PowerShell log clear | CRITICAL - Should trigger |
