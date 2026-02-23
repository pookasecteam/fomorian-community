# Fomorian Community Trial

<img src="https://img.shields.io/badge/PookaSec-Fomorian-8B0000?style=for-the-badge" alt="Fomorian"/> <img src="https://img.shields.io/badge/Community-Trial-blue?style=for-the-badge" alt="Community Trial"/> <img src="https://img.shields.io/badge/Open%20Source-For%20Wazuh%20Users-green?style=for-the-badge" alt="Open Source"/>

> *In Celtic mythology, the Fomorians were a supernatural race of adversaries. Dark, chaotic beings who emerged from the sea and the underworld to challenge the gods. They represented the forces that defenders must prepare to face.*

**Fomorian** is an open source adversary simulation framework for the Wazuh community. Generate realistic attack scenarios, inject them into your SIEM, and validate your detection coverage, without executing real attacks.

> **Community Trial:** This release includes 91 attack techniques (6-10 per kill chain phase), 2 engagement scenarios, and 585 attack logs. The full version contains 244+ techniques, 7 engagement types, and 1,371+ attack logs. [Contact PookaSec](https://github.com/pookasecteam) for the full release.

## Why Fomorian?

Most attack simulation tools execute real techniques on endpoints. Fomorian takes a different approach: generate realistic attack logs and inject them directly into your SIEM.

**What this tests:**
```
Real Attack:  Endpoint > Telemetry > Collection > Parsing > Enrichment > Detection > Alert

Fomorian:     Injects here --------+            +----------------------------------+
                                                  Tests everything from here on
```

Your endpoints might generate perfect telemetry. But if your SIEM drops fields, your parser is misconfigured, or your Sigma rule has broken logic, you will never see the alert.

Fomorian finds those gaps before attackers do.

| Atomic Red Team | Fomorian |
|-----------------|----------|
| Runs real attacks on endpoints | Generates logs, injects into SIEM |
| Tests: "Did the endpoint see it?" | Tests: "Will the SOC catch it?" |
| Requires test VMs, execution risk | Zero execution, production safe |
| One technique at a time | Full attack chains with correlation |
| Generic lab data | Your hostnames, users, IPs |

**Use both.** ART validates telemetry generation. Fomorian validates detection coverage.

See [COMPARISON.md](COMPARISON.md) for detailed analysis.

## Quick Start

```bash
# Clone and install
git clone https://github.com/pookasecteam/fomorian-community.git
cd fomorian-community
pip install -e .

# Generate a scenario with your environment config
fomorian generate \
  --config profiles/test-config \
  --engagement ransomware \
  --output scenario.json

# Inject via Wazuh Indexer (recommended, 95%+ success rate)
fomorian inject scenario.json -s wazuh \
  --inject-method indexer \
  --password YOUR_INDEXER_ADMIN_PASSWORD

# Or auto-detect the best injection method
fomorian inject scenario.json -s wazuh \
  --inject-method auto \
  --password YOUR_INDEXER_ADMIN_PASSWORD

# Detect your Wazuh installation
fomorian detect-wazuh --siem-password YOUR_INDEXER_ADMIN_PASSWORD
```

See [SIEM-IMPORT-GUIDE.md](SIEM-IMPORT-GUIDE.md) for all injection methods and troubleshooting.

## Community Trial Contents

### Attack Techniques (91 techniques)

| Kill Chain Phase | Techniques | Examples |
|------------------|:----------:|----------|
| Initial Access | 6 | Spearphishing Attachment/Link, Exploit Public App, Supply Chain, Cloud Accounts |
| Execution | 8 | PowerShell, CMD, WMI, Mshta, Rundll32, Python, Unix Shell |
| Persistence | 8 | Registry Run Keys, Scheduled Task, Services, Web Shell, Account Manipulation |
| Privilege Escalation | 7 | UAC Bypass, Token Impersonation, Container Escape, SUID Abuse, Exploitation |
| Defense Evasion | 10 | Disable Security Tools, Clear Logs, DLL Injection, NTFS ADS, Obfuscation, Registry |
| Credential Access | 9 | LSASS Dump, DCSync, Kerberoasting, AS-REP Roast, NTDS, Password Spray |
| Discovery | 8 | System Info, Domain Accounts, Network Shares, Remote Systems, Network Scanning |
| Lateral Movement | 7 | SMB/PsExec, RDP, WinRM, SSH, Pass the Hash, Exploitation of Remote Services |
| Collection | 7 | Local System Data, Network Shares, Email, Screen Capture, Keylogging, Archive |
| Command & Control | 7 | HTTP C2, DNS Tunneling, Ingress Tool Transfer, Remote Access Tools, Encrypted Channel |
| Exfiltration | 7 | Cloud Storage, Over C2 Channel, FTP, DNS Exfil, Cloud Account Transfer |
| Impact | 7 | Ransomware Encryption, Inhibit Recovery, Data Destruction, Service Stop, Cryptomining |

### Engagement Scenarios

| Engagement | Phases | Logs | Description |
|------------|:------:|:----:|-------------|
| ransomware | 11 | 148 | Full ransomware kill chain from phishing to encryption |
| exfiltration | 10 | 61 | Data theft scenario from compromise through cloud exfiltration |

### Sigma Rules

Includes Graylog pipeline detection rules and individual YAML Sigma rules matching the included attack techniques.

## Full Version

| Feature | Community Trial | Full Version |
|---------|:--------------:|:------------:|
| Attack Techniques | 91 | 244+ |
| Attack Logs | 585 | 1,371+ |
| Engagement Types | 2 | 7 |
| Generator Engine | Full | Full |
| Wazuh Indexer Injection | Full | Full |
| Sigma Rules | Subset | All |
| Support | Community | Direct |

## Features

- **Environment Configuration:** Define hosts, users, IPs, and domain settings via YAML
- **Attack Path Builder:** Define lateral movement sequences through your environment
- **Engagement Scenarios:** Full attack chains with correlated events across hosts
- **Multi Day Scenarios:** Support realistic APT dwell times (hours to weeks)
- **Randomization:** Realistic timestamps, GUIDs, and behavioral variations
- **SIEM Agnostic Output:** JSON, NDJSON, Syslog formats for any SIEM
- **Wazuh Indexer Injection:** Bulk inject via OpenSearch API (recommended, 95%+ success rate)
- **Multiple Injection Methods:** Indexer, alerts.json, archives, file monitoring, or Wazuh API
- **Non Root Detection:** Detects Wazuh installations without requiring root access

## Configuration

### Environment Configuration

```yaml
name: "acme-corp"
domain: "acme.local"

network:
  internal: "192.168.1.0/24"
  dmz: "10.0.0.0/24"

hosts:
  - hostname: "WORKSTATION01.acme.local"
    short_name: "WS01"
    agent_id: "007"
    ip: "192.168.1.50"
    os: "windows"
    users: ["jsmith", "mjones"]

  - hostname: "DC01.acme.local"
    short_name: "DC01"
    agent_id: "003"
    ip: "192.168.1.10"
    os: "windows"
    role: "domain_controller"
```

## Directory Structure

```
fomorian-community/
├── attacks/                    # Attack log templates by tactic (91 techniques)
│   ├── initial-access/
│   ├── execution/
│   ├── persistence/
│   └── ...
├── engagements/
│   ├── ransomware/             # Full 11-phase ransomware scenario
│   └── exfiltration/           # Full 10-phase data theft scenario
├── sigma-rules/                # Graylog pipeline detection rules
├── generator/                  # Core Fomorian engine
├── profiles/                   # Environment configuration templates
├── templates/                  # Log template definitions
├── scenarios/                  # Pre-built attack chains
└── scripts/
    ├── inject-logs.sh          # Attack log injection tool
    └── convert-to-ndjson.py    # Format conversion utility
```

## SIEM Integration

See [SIEM-IMPORT-GUIDE.md](SIEM-IMPORT-GUIDE.md) for all injection methods, troubleshooting, and environment variables.

**License:** MIT

---

*Built for Wazuh users, by Wazuh users.*
