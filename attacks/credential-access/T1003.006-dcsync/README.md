# T1003.006 - OS Credential Dumping: DCSync

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1003.006 |
| Tactic | Credential Access (TA0006) |
| Name | OS Credential Dumping: DCSync |
| Platforms | Windows |
| Data Sources | Active Directory, Network Traffic |

## Description

Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.

## Attack Variations

### 001 - Mimikatz DCSync
Using Mimikatz lsadump::dcsync to extract credentials.
- **Detection:** 4662 events with replication GUIDs
- **Severity:** CRITICAL

### 002 - Impacket secretsdump
Using Impacket secretsdump.py for DCSync.
- **Detection:** DRSUAPI replication traffic
- **Severity:** CRITICAL

## Detection Logic

- Monitor 4662 events with DS-Replication-Get-Changes
- Watch for replication GUIDs accessed by non-DC accounts
- Detect Mimikatz dcsync patterns
- Alert on replication from non-DC IP addresses

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-mimikatz-dcsync.json | Mimikatz DCSync | CRITICAL - Should trigger |
