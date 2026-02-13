# T1053.005 - Scheduled Task/Job: Scheduled Task

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1053.005 |
| Tactic | Persistence (TA0003), Execution (TA0002), Privilege Escalation (TA0004) |
| Name | Scheduled Task/Job: Scheduled Task |
| Platforms | Windows |
| Data Sources | Scheduled Job, Process, Command |

## Description

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. Task scheduling can be used for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run processes at specified times.

## Attack Variations

### 001 - schtasks.exe Creation
Direct task creation via schtasks.exe command.
- **Detection:** schtasks.exe /create command
- **Severity:** HIGH

### 002 - Scheduled Task via COM
Task created via COM object (harder to detect).
- **Detection:** TaskScheduler COM object usage
- **Severity:** HIGH

### 003 - SYSTEM Task for Privilege Escalation
Task created to run as SYSTEM.
- **Detection:** /ru SYSTEM in schtasks command
- **Severity:** CRITICAL

## Detection Logic

- Monitor schtasks.exe /create command lines
- Watch for suspicious task actions (PowerShell, cmd, living-off-the-land binaries)
- Detect tasks pointing to Temp/Public folders
- Alert on tasks with SYSTEM privileges

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-schtasks-create.json | Basic task creation | HIGH - Should trigger |
| 002-schtasks-system.json | SYSTEM privilege task | CRITICAL - Should trigger |
| 003-remote-task.json | Remote task creation | CRITICAL - Should trigger |
