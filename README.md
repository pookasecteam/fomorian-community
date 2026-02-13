# Fomorian Community Trial

<img src="https://img.shields.io/badge/PookaSec-Fomorian-8B0000?style=for-the-badge" alt="Fomorian"/> <img src="https://img.shields.io/badge/Community-Trial-blue?style=for-the-badge" alt="Community Trial"/> <img src="https://img.shields.io/badge/Open%20Source-For%20Wazuh%20Users-green?style=for-the-badge" alt="Open Source"/>

> *In Celtic mythology, the Fomorians (Fomóraig) were a supernatural race of adversaries. Dark, chaotic beings who emerged from the sea and the underworld to challenge the gods. They represented the forces that defenders must prepare to face.*

**Fomorian** is an open source adversary simulation framework for the Wazuh community. Generate realistic attack scenarios, inject them into your SIEM, and validate your detection coverage — without executing real attacks.

> **Community Trial:** This release includes ~45 attack techniques (3-4 per kill chain phase) and 1 full engagement scenario (ransomware). The full version contains 231+ techniques, 7 engagement types, and 1,273+ attack logs. [Contact PookaSec](https://github.com/pookasecteam) for the full release.

## Why Fomorian?

Most attack simulation tools execute real techniques on endpoints. Fomorian takes a different approach: generate realistic attack logs and inject them directly into your SIEM.

**What this tests:**
```
Real Attack:  Endpoint → Telemetry → Collection → Parsing → Enrichment → Detection → Alert

Fomorian:     Injects here ─────────┘            └─────────────────────────────────┘
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
# Clone the repo
git clone https://github.com/pookasecteam/fomorian-community.git
cd fomorian-community

# Install dependencies
pip install -r requirements.txt

# Option 1: Use the inject script (simplest)
# Edit TARGET in scripts/inject-logs.sh to point to your Wazuh host
./scripts/inject-logs.sh --dry-run attacks/execution/T1059.001-powershell/

# Option 2: Use the generator engine
pip install -e .
fomorian generate \
  --config profiles/test-config \
  --engagement ransomware \
  --output scenario.json

# Option 3: Docker
docker-compose up -d
docker-compose run fomorian generate \
  --config /app/profiles/test-config \
  --engagement ransomware \
  --output /app/output/scenario.json
```

## Community Trial Contents

### Attack Techniques (~45 techniques)

| Kill Chain Phase | Techniques | Examples |
|------------------|:----------:|----------|
| Initial Access | 3 | Spearphishing, Exploit Public App, Cloud Accounts |
| Execution | 4 | PowerShell, CMD, WMI, Rundll32 |
| Persistence | 4 | Registry Run Keys, Scheduled Task, Services, Account Manipulation |
| Privilege Escalation | 3 | UAC Bypass, Token Impersonation, Exploitation |
| Defense Evasion | 4 | Disable Security Tools, Clear Logs, Masquerading, DLL Injection |
| Credential Access | 4 | LSASS Dump, DCSync, Kerberoasting, Password Spray |
| Discovery | 4 | System Info, Domain Accounts, Network Shares, Remote Systems |
| Lateral Movement | 3 | SMB/Admin Shares, RDP, WinRM |
| Collection | 3 | Data from Local System, Data Staging, Archive |
| Command & Control | 3 | HTTP C2, DNS Tunneling, Ingress Tool Transfer |
| Exfiltration | 3 | Cloud Storage, Over C2 Channel, Alternative Protocol |
| Impact | 3 | Ransomware Encryption, Inhibit Recovery, Data Destruction |

### Engagement Scenario

| Engagement | Phases | Description |
|------------|--------|-------------|
| ransomware | 11 | Full ransomware kill chain from phishing to encryption |

### Sigma Rules

Includes Graylog pipeline detection rules and individual YAML Sigma rules matching the included attack techniques.

## Full Version

The full Fomorian release includes:

| Feature | Community Trial | Full Version |
|---------|:--------------:|:------------:|
| Attack Techniques | ~45 | 231+ |
| Attack Logs | ~100 | 1,273+ |
| Engagement Types | 1 (ransomware) | 7 |
| Generator Engine | Full | Full |
| Sigma Rules | Subset | All |
| Support | Community | Direct |

## Features

- **Environment Configuration:** Define hosts, users, IPs, and domain settings via YAML
- **Attack Path Builder:** Define lateral movement sequences through your environment
- **Engagement Scenarios:** Full attack chains with correlated events across hosts
- **Multi-Day Scenarios:** Support realistic APT dwell times (hours to weeks)
- **Randomization:** Realistic timestamps, GUIDs, and behavioral variations
- **SIEM-Agnostic Output:** JSON, NDJSON, Syslog formats for any SIEM
- **Direct Wazuh Injection:** Inject directly into Wazuh Manager (archives, alerts, or API)

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
├── attacks/                    # Attack log templates by tactic (~45 techniques)
│   ├── initial-access/
│   ├── execution/
│   ├── persistence/
│   └── ...
├── engagements/
│   └── ransomware/             # Full 11-phase ransomware scenario
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

See [WAZUH-INTEGRATION.md](WAZUH-INTEGRATION.md) for detailed Wazuh setup instructions.
See [SIEM-IMPORT-GUIDE.md](SIEM-IMPORT-GUIDE.md) for general SIEM import guidance.

## Contributing

We welcome contributions from the Wazuh community. See [CONTRIBUTING.md](CONTRIBUTING.md).

**License:** MIT

---

*Built for Wazuh users, by Wazuh users.*
