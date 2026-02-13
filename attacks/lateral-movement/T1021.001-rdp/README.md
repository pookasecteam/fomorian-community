# T1021.001 - Remote Services: Remote Desktop Protocol

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1021.001 |
| Tactic | Lateral Movement (TA0008) |
| Name | Remote Services: Remote Desktop Protocol |
| Platforms | Windows |
| Data Sources | Logon Session, Network Traffic, Process |

## Description

Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). RDP is a common feature in operating systems that allows a user to log into an interactive session with a system.

## Attack Variations

### 001 - Standard RDP Lateral Movement
Using mstsc.exe to connect to remote host.
- **Detection:** RDP connections to unusual hosts
- **Severity:** MEDIUM

### 002 - RDP with Stolen Credentials
RDP login using compromised credentials.
- **Detection:** 4624 Type 10 from unusual source
- **Severity:** HIGH

### 003 - RDP Tunneling
RDP over SSH or other tunnel.
- **Detection:** RDP traffic on non-standard ports
- **Severity:** HIGH

## Detection Logic

- Monitor 4624 events with LogonType 10 (RemoteInteractive)
- Watch for mstsc.exe connections to internal hosts
- Detect unusual RDP source-destination pairs
- Alert on RDP from compromised accounts

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-rdp-lateral.json | RDP lateral movement | MEDIUM - Should trigger |
| 002-rdp-stolen-creds.json | RDP with stolen creds | HIGH - Should trigger |
