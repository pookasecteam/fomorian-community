# T1003.001 - LSASS Memory Credential Dumping

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1003.001 |
| Tactic | Credential Access (TA0006) |
| Name | OS Credential Dumping: LSASS Memory |
| Platforms | Windows |
| Permissions Required | Administrator, SYSTEM |
| Data Sources | Process: OS API Execution, Process: Process Access, Process: Process Creation |

## Description

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement.

## Attack Variations

### 001 - ProcDump (Sysinternals)
Legitimate Microsoft tool used to dump LSASS memory.
- **Detection:** Sysmon Event 10 (Process Access) to lsass.exe with suspicious access rights
- **Difficulty:** Easy to detect (known tool)

### 002 - comsvcs.dll MiniDump
Uses rundll32 to call comsvcs.dll export for memory dumping.
- **Detection:** Sysmon Event 1 with rundll32 + comsvcs + MiniDump
- **Difficulty:** Medium (legitimate DLL abuse)

### 003 - Mimikatz sekurlsa::logonpasswords
Direct LSASS memory reading via custom code.
- **Detection:** Process access to lsass.exe, suspicious tool names
- **Difficulty:** Varies (depends on obfuscation)

### 004 - Task Manager Dump
Built-in Windows feature to create process dump.
- **Detection:** taskmgr.exe accessing lsass.exe
- **Difficulty:** Hard (legitimate admin action)

### 005 - Silent Process Exit (Lsass Shtinkering)
Abuses Windows Error Reporting to dump LSASS.
- **Detection:** Registry modification + WerFault accessing LSASS
- **Difficulty:** Hard (novel technique)

### 006 - Legitimate Security Tool (False Positive)
Windows Defender, CrowdStrike, etc. legitimately accessing LSASS.
- **Expected:** Should NOT alert (allowlisted)

## Detection Logic

Our SOAR workflow (`credential-dumping-response.json`) detects:
- Tool names: mimikatz, procdump, comsvcs, sekurlsa, pypykatz, nanodump, etc.
- LSASS as target
- Suspicious access rights (0x1010, 0x1FFFFF)
- Subtracts score for legitimate security tools

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-procdump-lsass.json | ProcDump dumping LSASS | HIGH - Should trigger |
| 002-comsvcs-minidump.json | rundll32 comsvcs abuse | CRITICAL - Should trigger |
| 003-mimikatz-sekurlsa.json | Mimikatz execution | CRITICAL - Should trigger |
| 004-taskmgr-dump.json | Task Manager dump | MEDIUM - May trigger |
| 005-werfault-lsass.json | Silent process exit | LOW/NONE - Test coverage gap |
| 006-defender-lsass.json | Windows Defender scan | NONE - Should NOT trigger |

## References

- https://attack.mitre.org/techniques/T1003/001/
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
- https://lolbas-project.github.io/#/dump
