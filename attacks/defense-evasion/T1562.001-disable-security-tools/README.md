# T1562.001 - Impair Defenses: Disable or Modify Tools

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1562.001 |
| Tactic | Defense Evasion (TA0005) |
| Name | Impair Defenses: Disable or Modify Tools |
| Platforms | Windows, Linux, macOS |
| Data Sources | Process, Command, Service, Windows Registry |

## Description

Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes, modifying registry keys or configuration files.

## Attack Variations

### 001 - Disable Windows Defender
Set-MpPreference or registry modifications to disable Defender.
- **Detection:** PowerShell Defender disable commands
- **Severity:** CRITICAL

### 002 - Stop Security Service
net stop or sc stop on security services.
- **Detection:** Security service stop commands
- **Severity:** CRITICAL

### 003 - Tamper Protection Bypass
Registry modifications to disable tamper protection.
- **Detection:** Defender registry modifications
- **Severity:** CRITICAL

### 004 - Firewall Disable
netsh commands to disable Windows Firewall.
- **Detection:** netsh advfirewall disable commands
- **Severity:** HIGH

## Detection Logic

- Monitor Set-MpPreference PowerShell commands
- Watch for net stop/sc stop on security services
- Detect registry modifications to Defender/security settings
- Alert on firewall disable commands

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-disable-defender.json | Defender disable | CRITICAL - Should trigger |
| 002-stop-security-service.json | Stop AV service | CRITICAL - Should trigger |
| 003-disable-firewall.json | Firewall disable | HIGH - Should trigger |
