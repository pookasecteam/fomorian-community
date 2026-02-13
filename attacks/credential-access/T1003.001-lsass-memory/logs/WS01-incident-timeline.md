# Incident Timeline Report

**Incident ID:** WS01-2026-0129-001
**Host:** WS01
**User:** Multiple (corp\attacker, corp\admin)
**Time Range:** 2026-01-28 19:00 to 2026-01-30 02:00
**Generated:** 2026-02-02

---

## Executive Summary

WS01 experienced a sophisticated multi-stage attack spanning 31 hours. Initial access via Office macro led to privilege escalation tools (SharpUp), credential theft (Rubeus, Golden/Silver tickets), lateral movement preparation, and defense evasion. Attack shows APT-level tradecraft with Kerberos abuse, C2 establishment, and persistence mechanisms.

---

## Timeline

| Time | Category | Detection | MITRE | Details |
|------|----------|-----------|-------|---------|
| 2026-01-28 19:00 | Recon | SharpUp PrivEsc Tool | T1082 | Privilege escalation enumeration (20 events) |
| 2026-01-28 21:00 | Recon | SharpUp PrivEsc Tool | T1082 | Continued enumeration |
| 2026-01-29 20:00 | Execution | SharpUp via cmd.exe | T1059.003 | cmd.exe → SharpUp execution |
| 2026-01-29 21:21 | Execution | mshta.exe execution | T1218.005 | LOLBin abuse - mshta.exe |
| 2026-01-29 21:21 | Execution | PowerShell execution | T1059.001 | Post-exploitation PowerShell |
| 2026-01-29 21:39 | Defense Evasion | certutil.exe abuse | T1140 | Decode/download via certutil |
| 2026-01-29 21:39 | Defense Evasion | bitsadmin.exe abuse | T1197 | BITS job for persistence/transfer |
| 2026-01-29 22:06 | Persistence | Sticky Key Backdoor | T1546.008 | Registry accessibility feature hijack |
| 2026-01-29 23:41 | Cred Access | Rubeus Execution | T1558 | C:\Users\Public\Rubeus.exe - Kerberos abuse |
| 2026-01-29 23:44 | C2 | F-Secure C3 Load | T1071 | rundll32 loading C3 framework |
| 2026-01-29 23:44 | Execution | regsvr32 abuse | T1218.010 | LOLBin regsvr32 execution |
| 2026-01-30 01:00 | Discovery | Domain Account Discovery | T1087.002 | Active Directory enumeration |
| 2026-01-30 01:00 | Discovery | Network Service Discovery | T1046 | Nmap scanning internal network |
| 2026-01-30 01:00 | Defense Evasion | Command History Cleared | T1070.003 | Covering tracks |
| 2026-01-30 01:00 | Defense Evasion | Evidence Removal | T1070.004 | File deletion |
| 2026-01-30 01:00 | C2 | Encrypted C2 Non-Standard | T1573 | Encrypted C2 traffic |
| 2026-01-30 01:00 | C2 | Web Service C2 | T1102 | Web-based C2 communication |
| 2026-01-30 02:00 | Cred Access | AS-REP Roasting | T1558.004 | Kerberos pre-auth attack |
| 2026-01-30 02:00 | Cred Access | Golden Ticket Attack | T1558.001 | Forged TGT creation (20 events) |
| 2026-01-30 02:00 | Cred Access | Silver Ticket Attack | T1558.002 | Forged service ticket |
| 2026-01-30 02:00 | Cred Access | Browser Cookie Theft | T1539 | Session cookie extraction |
| 2026-01-30 02:00 | Cred Access | Cloud Token Theft | T1528 | Cloud access tokens stolen |
| 2026-01-30 02:00 | Lateral | Lateral Tool Transfer | T1570 | Tools copied for lateral movement |
| 2026-01-30 02:00 | Lateral | NTLM Relay Attack | T1557.001 | NTLM relay tool execution |
| 2026-01-30 02:00 | Persistence | IFEO Debugger Injection | T1546.012 | Image File Execution Options abuse |
| 2026-01-30 02:00 | Impact | Critical Service Stop | T1489 | Service disruption |
| 2026-01-30 02:00 | Impact | System Shutdown/Reboot | T1529 | System disruption |

---

## Attack Flow Diagram

```
[Initial Access]     [Execution]        [Persistence]      [Cred Access]       [Lateral]         [Impact]
     │                   │                   │                  │                  │                 │
     └─ Office macro     └─ SharpUp          └─ Sticky Keys     └─ Rubeus          └─ NTLM Relay     └─ Service Stop
                         └─ PowerShell       └─ IFEO Debugger   └─ Golden Ticket   └─ Tool Transfer  └─ Shutdown
                         └─ mshta.exe                           └─ AS-REP Roast
                         └─ certutil                            └─ Silver Ticket
                         └─ bitsadmin                           └─ Cookie Theft
                         └─ F-Secure C3                         └─ Cloud Tokens
```

---

## Key Indicators

| Type | Value | Context |
|------|-------|---------|
| File | C:\Users\Public\Rubeus.exe | Kerberos attack tool |
| Tool | SharpUp.exe | Privilege escalation enumeration |
| Tool | F-Secure C3 | C2 framework |
| Technique | Sticky Keys | Accessibility feature backdoor |
| Technique | Golden Ticket | Domain persistence via forged TGT |
| Technique | NTLM Relay | Lateral movement via credential relay |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Execution | T1059.001 | PowerShell post-exploitation |
| Execution | T1218.005 | mshta.exe LOLBin |
| Execution | T1218.010 | regsvr32 LOLBin |
| Persistence | T1546.008 | Sticky Key backdoor (24 events) |
| Persistence | T1546.012 | IFEO Debugger Injection |
| Persistence | T1197 | BITS job abuse |
| Privilege Escalation | T1082 | SharpUp enumeration (776 events) |
| Defense Evasion | T1140 | certutil decode |
| Defense Evasion | T1070.003 | Command history cleared |
| Defense Evasion | T1070.004 | File deletion evidence removal |
| Credential Access | T1558.001 | Golden Ticket (20 events) |
| Credential Access | T1558.002 | Silver Ticket (10 events) |
| Credential Access | T1558.004 | AS-REP Roasting |
| Credential Access | T1539 | Browser cookie theft |
| Credential Access | T1528 | Cloud token theft |
| Discovery | T1087.002 | Domain account enumeration |
| Discovery | T1046 | Nmap network scanning |
| Lateral Movement | T1570 | Lateral tool transfer |
| Lateral Movement | T1557.001 | NTLM relay attack |
| Command & Control | T1071 | F-Secure C3 framework |
| Command & Control | T1102 | Web service C2 |
| Command & Control | T1573 | Encrypted C2 non-standard port |
| Impact | T1489 | Critical service stop |
| Impact | T1529 | System shutdown/reboot |

---

## Detection Statistics

| Rule | Count |
|------|-------|
| SharpUp PrivEsc Tool | 776 |
| Rubeus Execution | 45 |
| Remote Access Software | 37 |
| GPP Password Discovery | 36 |
| Shadow Copy Deletion | 34 |
| Parent PID Spoofing | 31 |
| Hidden Window Execution | 27 |
| Persistence Via Sticky Key | 24 |
| Golden Ticket Attack | 20 |
| **Total Sigma Detections** | **1,547+** |

---

## Affected Assets

- **WS01** - Primary compromised workstation
- **Active Directory** - Golden/Silver tickets indicate domain compromise
- **Cloud Services** - Token theft detected

---

## Recommendations

### Containment (Immediate)
1. **Isolate WS01** from network immediately
2. **Revoke all Kerberos tickets** - krbtgt password reset required twice
3. **Invalidate cloud tokens** for affected users
4. **Block F-Secure C3 C2** at perimeter

### Eradication
1. **Reimage WS01** - persistence mechanisms too extensive
2. **Reset all passwords** for accounts accessed from WS01
3. **Remove IFEO and Sticky Key backdoors** from AD domain-wide
4. **Audit all domain computers** for Rubeus/SharpUp artifacts

### Recovery
1. **Monitor for Golden Ticket usage** (valid for 10 years by default)
2. **Enable Credential Guard** on all endpoints
3. **Deploy EDR** with real-time behavioral detection
4. **Implement LAPS** for local admin passwords

### Lessons Learned
1. Initial Office macro execution indicates need for macro blocking
2. Public folder write access enabled tool staging - restrict
3. Kerberos delegation review needed
4. Consider Protected Users group for privileged accounts

---

*Generated by /incident-timeline skill*
