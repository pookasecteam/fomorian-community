# T1021.002 - Remote Services: SMB/Windows Admin Shares

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1021.002 |
| Tactic | Lateral Movement (TA0008) |
| Name | Remote Services: SMB/Windows Admin Shares |
| Platforms | Windows |
| Data Sources | Network Traffic, Logon Session, Process |

## Description

Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). Adversaries may then perform actions as the logged-on user or use administrator shares (C$, ADMIN$) for lateral movement.

## Attack Variations

### 001 - PsExec Lateral Movement
PsExec deploying and executing payload on remote host.
- **Detection:** PsExec execution patterns
- **Severity:** HIGH

### 002 - Admin Share File Copy
Copying files via administrative shares.
- **Detection:** File copy to C$ or ADMIN$ shares
- **Severity:** MEDIUM

### 003 - Remote Service Creation
Creating service on remote host via SMB.
- **Detection:** Remote service creation
- **Severity:** CRITICAL

## Detection Logic

- Monitor for PsExec/PsExec variants
- Watch for net use to admin shares (C$, ADMIN$, IPC$)
- Detect remote service creation
- Alert on copy commands to network shares

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-psexec-remote.json | PsExec lateral movement | HIGH - Should trigger |
| 002-copy-to-admin-share.json | Admin share file copy | MEDIUM - Should trigger |
| 003-remote-service.json | Remote service creation | CRITICAL - Should trigger |
