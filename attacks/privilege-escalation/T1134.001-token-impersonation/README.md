# T1134.001 - Access Token Manipulation: Token Impersonation/Theft

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1134.001 |
| Tactic | Privilege Escalation (TA0004), Defense Evasion (TA0005) |
| Name | Access Token Manipulation: Token Impersonation/Theft |
| Platforms | Windows |
| Data Sources | Process, Command, Windows Registry |

## Description

Adversaries may duplicate then impersonate another user's token to escalate privileges and bypass access controls. An adversary can create a new access token that duplicates an existing token using DuplicateToken(Ex). The token can then be used with ImpersonateLoggedOnUser.

## Attack Variations

### 001 - Token Impersonation via PrintSpoofer
PrintSpoofer/Potato exploiting SeImpersonatePrivilege.
- **Detection:** PrintSpoofer execution patterns
- **Severity:** CRITICAL

### 002 - RunAs with Saved Credentials
Using RunAs to execute with different credentials.
- **Detection:** runas.exe /savecred usage
- **Severity:** HIGH

### 003 - Mimikatz Token Manipulation
Mimikatz token::elevate command.
- **Detection:** Mimikatz patterns in command line
- **Severity:** CRITICAL

## Detection Logic

- Monitor for processes with SeImpersonatePrivilege being exploited
- Watch for PrintSpoofer, JuicyPotato, RoguePotato execution
- Detect unusual parent-child relationships indicating impersonation
- Alert on token manipulation tool patterns

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-potato-attack.json | Potato privilege escalation | CRITICAL - Should trigger |
| 002-runas-savecred.json | RunAs credential theft | HIGH - Should trigger |
