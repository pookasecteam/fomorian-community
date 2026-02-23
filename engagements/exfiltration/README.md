# Data Exfiltration - example-corp

**Type:** exfiltration
**Generated:** 2026-02-23T00:00:00.000000Z
**Duration:** 4h 1m
**Total Logs:** 61

## Overview

Full data exfiltration scenario covering 10 phases, from initial compromise through credential theft, data collection, and exfiltration to cloud storage.

## Phases

| # | Phase | File | Logs | Techniques |
|---|-------|------|------|------------|
| 0 | initial-access | `000-initial_access.json` | 8 | T1133, T1195.002, T1566.001 (+1 more) |
| 1 | execution | `001-execution.json` | 3 | T1059.001, T1218.005 |
| 2 | persistence | `002-persistence.json` | 1 | T1547.001 |
| 3 | privilege-escalation | `003-privilege_escalation.json` | 6 | T1134.001, T1548.002, T1574.001 |
| 4 | defense-evasion | `004-defense_evasion.json` | 1 | T1562.001 |
| 5 | credential-access | `005-credential_access.json` | 8 | T1003.001, T1003.002, T1558.003 |
| 6 | discovery | `006-discovery.json` | 9 | T1018, T1033, T1069.002 (+2 more) |
| 7 | collection | `007-collection.json` | 9 | T1005, T1039, T1056.001 (+2 more) |
| 8 | command-and-control | `008-command_and_control.json` | 9 | T1071.001, T1105, T1572 (+1 more) |
| 9 | exfiltration | `009-exfiltration.json` | 7 | T1041, T1048.003, T1567.002 |

## MITRE ATT&CK Coverage

**Techniques:** 31

```
T1003.001, T1003.002, T1005, T1018, T1033, T1039, T1041, T1048.003, T1056.001, T1059.001, T1069.002, T1071.001, T1087.002, T1105, T1113, T1133, T1134.001, T1195.002, T1218.005, T1518.001, T1547.001, T1548.002, T1558.003, T1560.001, T1562.001, T1566.001, T1566.002, T1567.002, T1572, T1573.002, T1574.001
```

## Hosts Involved

- WS01

## Usage

```bash
# Inject all phases
./scripts/inject-logs.sh engagements/exfiltration/

# Or use the generator for customized scenarios
fomorian generate \
  --config profiles/test-config \
  --engagement exfiltration \
  --output scenario.json

# Inject via Wazuh Indexer (recommended)
fomorian inject scenario.json -s wazuh \
  --inject-method indexer \
  --password YOUR_INDEXER_ADMIN_PASSWORD
```
