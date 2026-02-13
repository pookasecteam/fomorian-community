# T1055.001 - Process Injection: Dynamic-link Library Injection

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1055.001 |
| Tactic | Defense Evasion (TA0005), Privilege Escalation (TA0004) |
| Name | Process Injection: Dynamic-link Library Injection |
| Platforms | Windows |
| Data Sources | Process, Module |

## Description

Adversaries may inject dynamic-link libraries (DLLs) into processes to evade process-based defenses as well as possibly elevate privileges. DLL injection is commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread.

## Attack Variations

### 001 - Classic DLL Injection
Using CreateRemoteThread for DLL injection.
- **Detection:** Suspicious DLL loads, remote thread creation
- **Severity:** CRITICAL

### 002 - Reflective DLL Injection
Loading DLL directly from memory.
- **Detection:** Memory-only DLL patterns
- **Severity:** CRITICAL

## Detection Logic

- Monitor Sysmon Event 8 (CreateRemoteThread)
- Watch for unusual DLL loads (Event 7)
- Detect process hollowing patterns
- Alert on known injection tool signatures

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-createremotethread.json | Classic DLL injection | CRITICAL - Should trigger |
