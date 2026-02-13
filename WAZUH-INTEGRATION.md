# Fomorian Wazuh Integration Guide

Fomorian supports direct injection into Wazuh regardless of how it's deployed - Docker, native Linux, agent-only, or remote.

## Quick Start

```bash
# Detect your Wazuh installation
fomorian detect-wazuh

# Generate and inject (auto-detects best method)
fomorian generate \
  --config ./profiles/test-config \
  --engagement ransomware \
  --inject wazuh
```

## Injection Methods

| Method | Description | Best For |
|--------|-------------|----------|
| `auto` | Auto-detect best method | Default, most users |
| `archives` | Direct write to archives.json | Docker/native with manager access |
| `alerts` | Direct write to alerts.json | Direct alert injection |
| `file` | Monitored log file | Agent-only, most compatible |
| `api` | Wazuh Manager API | Remote injection |

### Method Selection

```bash
# Explicit method selection
fomorian generate -c ./config -e ransomware --inject wazuh --inject-method archives

# Auto-detection (default)
fomorian generate -c ./config -e ransomware --inject wazuh
```

## Deployment Scenarios

### 1. Docker-based Wazuh (Most Common)

Fomorian auto-detects common container names:
- `wazuh-manager`
- `wazuh-manager`
- `wazuh.manager`

**Recommended: Direct archives injection (no setup required)**

```bash
# Check detection
fomorian detect-wazuh

# Generate and inject
fomorian generate \
  --config ./profiles/test-config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method archives
```

### 2. Native Linux Installation

For Wazuh installed directly on Linux (e.g., `/var/ossec`).

**Recommended: Direct archives injection**

```bash
# Must run as root or wazuh user for write access
sudo fomorian generate \
  --config ./profiles/test-config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method archives
```

### 3. Agent-Only Installation

When running Fomorian on a machine with only Wazuh agent (no manager).

**Option A: File injection with local monitoring**

```bash
# 1. Add to agent's ossec.conf
sudo tee -a /var/ossec/etc/ossec.conf << 'EOF'
<localfile>
  <log_format>json</log_format>
  <location>/var/log/fomorian/attacks.json</location>
  <label key="fomorian">true</label>
</localfile>
EOF

# 2. Create log directory
sudo mkdir -p /var/log/fomorian
sudo chown root:wazuh /var/log/fomorian

# 3. Restart agent
sudo systemctl restart wazuh-agent

# 4. Generate and inject
fomorian generate \
  --config ./profiles/test-config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method file
```

**Option B: Generate and manually copy**

```bash
# Generate scenario file
fomorian generate \
  --config ./profiles/test-config \
  --engagement ransomware \
  --output scenario.json

# Copy to Wazuh manager
scp scenario.json user@wazuh-server:/var/log/fomorian/
```

### 4. Remote Wazuh (API Injection)

When Wazuh manager is on a remote server.

```bash
# Set credentials
export PURPLE_TEAM_HOST=wazuh-manager.example.com
export PURPLE_TEAM_USERNAME=wazuh-wui
export PURPLE_TEAM_PASSWORD=your-password

# Generate and inject via API
fomorian generate \
  --config ./profiles/test-config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method api \
  --no-verify-ssl
```

Or with inline credentials:

```bash
fomorian generate \
  --config ./profiles/test-config \
  --engagement ransomware \
  --inject wazuh \
  --inject-method api \
  --siem-host wazuh-manager.example.com \
  --siem-user wazuh-wui \
  --siem-password your-password \
  --no-verify-ssl
```

## Detection Verification

### Check Wazuh Archives

```bash
# Docker
docker exec wazuh-manager tail -20 /var/ossec/logs/archives/archives.json | jq .

# Native
sudo tail -20 /var/ossec/logs/archives/archives.json | jq .
```

### Check Wazuh Alerts

```bash
# Docker
docker exec wazuh-manager tail -20 /var/ossec/logs/alerts/alerts.json | jq .

# Native
sudo tail -20 /var/ossec/logs/alerts/alerts.json | jq .
```

### Query via Wazuh API

```bash
# Get recent alerts
curl -k -u wazuh-wui:password \
  "https://localhost:55000/alerts?limit=10&q=rule.groups=fomorian"
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PURPLE_TEAM_HOST` | Wazuh manager hostname |
| `PURPLE_TEAM_PORT` | API port (default: 55000) |
| `PURPLE_TEAM_USERNAME` | API username |
| `PURPLE_TEAM_PASSWORD` | API password |
| `PURPLE_TEAM_TOKEN` | API token (alternative to user/pass) |

## Troubleshooting

### Permission Denied (Archives/Alerts)

```bash
# Docker - run with proper user
docker exec -u root wazuh-manager chown -R wazuh:wazuh /var/ossec/logs

# Native - use sudo
sudo fomorian generate ... --inject wazuh --inject-method archives
```

### Docker Container Not Detected

```bash
# List running containers
docker ps --format "{{.Names}}"

# Specify container manually in config
fomorian generate ... --inject wazuh
# Then check logs for detected container
```

### API Authentication Failed

```bash
# Verify credentials
curl -k -u wazuh-wui:password https://localhost:55000/

# Check API is enabled
docker exec wazuh-manager cat /var/ossec/api/configuration/api.yaml
```

### File Injection Not Working

1. Verify ossec.conf has the localfile block
2. Check file permissions on log directory
3. Restart Wazuh manager/agent
4. Check `/var/ossec/logs/ossec.log` for errors

## Alert Format

Fomorian generates Wazuh-compatible alerts with:

```json
{
  "timestamp": "2026-01-30T08:00:00Z",
  "rule": {
    "level": 12,
    "description": "Phishing attachment opened",
    "id": "100001",
    "mitre": {
      "id": ["T1566.001"],
      "tactic": ["initial-access"]
    },
    "groups": ["fomorian", "attack_simulation", "initial-access"]
  },
  "agent": {
    "id": "007",
    "name": "WS01"
  },
  "data": {
    "winlog": {
      "event_id": 1,
      "event_data": {
        "CommandLine": "...",
        "Image": "..."
      }
    }
  }
}
```

## Comparison: Injection Methods

| Feature | archives | alerts | file | api |
|---------|----------|--------|------|-----|
| Setup required | No | No | Yes (ossec.conf) | No |
| Manager required | Yes | Yes | No | Yes |
| Remote injection | No | No | No | Yes |
| Works with agent | No | No | Yes | No |
| Triggers rules | No | Yes | Depends | Yes |
| Best for | Log analysis | Alert testing | Agent scenarios | Remote |
