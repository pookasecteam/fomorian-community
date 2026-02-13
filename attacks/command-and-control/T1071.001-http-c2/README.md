# T1071.001 - Application Layer Protocol: Web Protocols (HTTP C2)

## MITRE ATT&CK Reference

| Field | Value |
|-------|-------|
| Technique | T1071.001 |
| Tactic | Command and Control (TA0011) |
| Name | Application Layer Protocol: Web Protocols |
| Platforms | Windows, Linux, macOS |
| Data Sources | Network Traffic, Process |

## Description

Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic.

## Attack Variations

### 001 - Cobalt Strike Beacon
HTTP/HTTPS beaconing with typical Cobalt Strike patterns.
- **Detection:** Known user agents, regular intervals, JA3 fingerprints
- **Severity:** CRITICAL

### 002 - PowerShell HTTP Connection
PowerShell making outbound HTTP connections to external IP.
- **Detection:** LOLBin (PowerShell) making HTTP connection
- **Severity:** HIGH

### 003 - DNS over HTTPS (DoH)
Using DoH providers for C2 communication.
- **Detection:** Connections to known DoH providers (cloudflare-dns.com, dns.google)
- **Severity:** MEDIUM

### 004 - Long DNS Query (Tunneling)
DNS queries with encoded data in subdomain.
- **Detection:** DNS query length > 50 chars, high entropy
- **Severity:** HIGH

### 005 - Suspicious User Agent
HTTP connections with minimal/empty user agent.
- **Detection:** Empty UA, generic "Mozilla/5.0" only
- **Severity:** MEDIUM

### 006 - Legitimate Windows Update (False Positive)
Normal Windows Update traffic.
- **Detection:** NONE - Should NOT alert

## Detection Logic

Our SOAR workflow (`c2-beaconing-detection.json`) detects:
- Known C2 frameworks (Cobalt Strike, Metasploit, etc.)
- DNS tunneling tools (dnscat, iodine)
- Long DNS queries (>50 chars)
- High entropy subdomains (>3.5 bits)
- Suspicious ports (4444, 5555, etc.)
- Suspicious user agents
- Known C2 JA3 fingerprints
- LOLBins making HTTP connections

## Log Files

| File | Variation | Expected Detection |
|------|-----------|-------------------|
| 001-cobalt-strike-beacon.json | CS HTTP beacon | CRITICAL - Should trigger |
| 002-powershell-http.json | PowerShell web request | HIGH - Should trigger |
| 003-dns-tunnel-long-query.json | Long DNS query | HIGH - Should trigger |
| 004-suspicious-user-agent.json | Empty/minimal UA | MEDIUM - Should trigger |
| 005-windows-update.json | Normal WU traffic | NONE - Should NOT trigger |
