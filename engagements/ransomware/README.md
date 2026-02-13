# Ransomware - example-corp

**Type:** ransomware
**Generated:** 2026-01-30T11:39:31.808518Z
**Duration:** 35m 15s
**Total Logs:** 148

## Overview

Full kill chain simulation covering 11 phases.

## Phases

| # | Phase | File | Logs | Techniques |
|---|-------|------|------|------------|
| 0 | initial-access | `000-initial_access.json` | 7 | T1133, T1566.002, T1195.002 (+1 more) |
| 1 | execution | `001-execution.json` | 3 | T1059.001, T1218.005 |
| 2 | persistence | `002-persistence.json` | 1 | T1547.001 |
| 3 | privilege-escalation | `003-privilege_escalation.json` | 6 | T1134.001, T1574.001, T1548.002 |
| 4 | defense-evasion | `004-defense_evasion.json` | 36 | T1218.011, T1562.001, T1218.010 |
| 5 | credential-access | `005-credential_access.json` | 12 | T1003.001, T1003.002, T1558.003 (+2 more) |
| 6 | discovery | `006-discovery.json` | 9 | T1087.002, T1069.002, T1018 (+2 more) |
| 7 | lateral-movement | `007-lateral_movement.json` | 2 | T1021.002 |
| 8 | collection | `008-collection.json` | 9 | T1560.001, T1056.001, T1005 (+2 more) |
| 9 | command-and-control | `009-command_and_control.json` | 3 | T1105 |
| 10 | impact | `010-impact.json` | 60 | T1489, T1486, T1490 (+1 more) |

## MITRE ATT&CK Coverage

**Techniques:** 34

```
T1003.001, T1003.002, T1003.003, T1003.006, T1005, T1018, T1021.002, T1033, T1039, T1056.001, T1059.001, T1069.002, T1087.002, T1105, T1113, T1133, T1134.001, T1195.002, T1218.005, T1218.010
```

## Hosts Involved

- - WS01
- DC01
- FS01

## Usage

```bash
# Inject all phases
./scripts/inject-logs.sh engagements/ransomware/

# Inject specific phase
cat engagements/ransomware/logs/000-*.json | jq -c '.logs[].log' | \
  ssh your-wazuh-host 'docker exec -i wazuh-manager bash -c "cat >> /var/ossec/logs/alerts/alerts.json"'
```
