# T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1558.003 |
| Tactic | Credential Access (TA0006) |
| Name | Steal or Forge Kerberos Tickets: Kerberoasting |
| Platforms | Windows |
| Data Sources | Active Directory, Network Traffic |

## Description

Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force. Service tickets can be requested for any service with a registered service principal name (SPN).

## Attack Variations

### 001 - Rubeus Kerberoasting
Using Rubeus to request service tickets.
- **Detection:** Rubeus patterns, mass TGS requests
- **Severity:** CRITICAL

### 002 - PowerShell Kerberoasting
Using PowerShell to request service tickets.
- **Detection:** GetUserSPNs, Request-SPNTicket
- **Severity:** CRITICAL

### 003 - Impacket GetUserSPNs
Using Impacket tool for Kerberoasting.
- **Detection:** Mass 4769 events from single source
- **Severity:** CRITICAL

## Detection Logic

- Monitor for multiple 4769 (TGS request) events in short time
- Watch for encryption type 0x17 (RC4) in TGS requests
- Detect tools like Rubeus, PowerView, Impacket
- Alert on SPN enumeration queries

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-rubeus-kerberoast.json | Rubeus execution | CRITICAL - Should trigger |
| 002-powershell-spn.json | PowerShell SPN enum | CRITICAL - Should trigger |
