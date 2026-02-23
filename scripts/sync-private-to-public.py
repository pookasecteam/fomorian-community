#!/usr/bin/env python3
"""Sync private PookaSec attack logs to public fomorian-community format.

Converts PookaSec-specific attack log templates to portable format:
- Rule IDs: Wazuh-specific (200xxx, 60xxx, 80xxx, 92xxx) -> Fomorian 100xxx range
- Agent info: PookaSec lab IPs -> generic RFC 5737 documentation IPs
- Metadata: Strip PookaSec-specific fields, keep universal ones
"""

import json
import glob
import os
import shutil
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Rule ID mapping: Wazuh-specific -> Fomorian portable range
# ---------------------------------------------------------------------------
RULE_ID_MAP = {
    # Linux Sysmon (200xxx -> 100xxx)
    "200151": "100101",  # Sysmon Event 1 (Process Create)
    "200152": "100103",  # Sysmon Event 3 (Network Connection)
    "200153": "100103",  # Sysmon Event 3 alt
    "200155": "100111",  # Sysmon Event 11 (File Create)
    "200157": "100107",  # Sysmon Event 7 (Image Load)
    "200158": "100108",  # Sysmon Event 8 (CreateRemoteThread)
    "200160": "100110",  # Sysmon Event 10 (ProcessAccess)
    "200161": "100111",  # Sysmon Event 11 alt
    "200163": "100113",  # Sysmon Event 13 (Registry)
    "200167": "100117",  # Sysmon Event 17 (Pipe)
    "200172": "100122",  # Sysmon Event 22 (DNS)
    "200173": "100123",  # Sysmon Event 23 (FileDelete)
    # Windows Security (60xxx -> 100xxx)
    "60009": "100600",   # Generic Windows Event Channel
    "60106": "100624",   # Event 4624 (Logon)
    "60110": "100672",   # Event 4672 (Special Logon)
    "60104": "100688",   # Event 4688 (Process Create)
    "60122": "100625",   # Event 4625 (Failed Logon)
    "60132": "100720",   # Event 4720 (User Created)
    "60136": "100724",   # Event 4724 (Password Reset)
    "60140": "100738",   # Event 4738 (User Modified)
    "60144": "100648",   # Event 4648 (Explicit Logon)
    "60155": "100663",   # Event 4663 (Object Access)
    "61603": "100603",   # Windows Defender / Firewall
    "61604": "100604",   # Windows Defender / Firewall alt
    # AWS CloudTrail (80xxx -> 100xxx)
    "80202": "100802",   # CloudTrail API call
    "80302": "100803",   # CloudTrail management event
    # AWS Lambda / Serverless (92xxx -> 100xxx)
    "92000": "100900",   # Lambda generic
    "92011": "100901",   # Lambda execution
    "92052": "100905",   # Lambda config
    "92101": "100910",   # Lambda invocation
    "92150": "100915",   # Lambda function
    "92151": "100916",   # Lambda event
    "92152": "100917",   # Lambda runtime
    "92153": "100918",   # Lambda layer
    "92154": "100919",   # Lambda alias
    "92155": "100920",   # Lambda version
    "92157": "100922",   # Lambda concurrency
    "92159": "100924",   # Lambda policy
    "92160": "100925",   # Lambda URL
    "92161": "100926",   # Lambda code signing
    "92172": "100927",   # Lambda event source
    # PowerShell
    "91801": "100400",   # PowerShell ScriptBlock
    # Office 365
    "91550": "100365",   # Office 365
}

# ---------------------------------------------------------------------------
# Agent IP mapping: PookaSec lab IPs -> generic documentation IPs (RFC 5737)
# Using 198.51.100.0/24 (TEST-NET-2) for generic lab hosts
# ---------------------------------------------------------------------------
AGENT_IP_MAP = {
    # Old VirtualBox era
    "192.168.56.100": "198.51.100.10",
    "192.168.56.101": "198.51.100.11",
    "192.168.56.102": "198.51.100.12",
    "192.168.56.103": "198.51.100.20",
    "192.168.56.104": "198.51.100.1",
    "192.168.56.105": "198.51.100.30",
    # Old 10.0.10.x era
    "10.0.10.10": "198.51.100.10",
    "10.0.10.20": "198.51.100.20",
    "10.0.10.30": "198.51.100.30",
    "10.0.10.50": "198.51.100.50",
    "10.0.10.100": "198.51.100.100",
    "10.0.10.5": "198.51.100.5",
    # Current Proxmox era
    "10.10.10.10": "198.51.100.10",
    "10.10.10.11": "198.51.100.11",
    "10.10.10.12": "198.51.100.20",
    "10.10.20.10": "198.51.100.30",
    "10.10.30.10": "198.51.100.40",
    # Other PookaSec-specific
    "192.168.1.100": "198.51.100.100",
    "192.168.1.50": "198.51.100.1",
    "192.168.1.10": "198.51.100.10",
    "192.168.1.60": "198.51.100.60",
    "10.1.1.50": "198.51.100.50",
    "10.1.1.30": "198.51.100.30",
    "10.1.1.20": "198.51.100.20",
    "10.1.1.52": "198.51.100.52",
    "10.1.0.10": "198.51.100.10",
    "10.1.0.11": "198.51.100.11",
    "10.1.0.12": "198.51.100.20",
    "10.0.10.12": "198.51.100.12",
    "10.0.10.45": "198.51.100.45",
    "10.0.10.25": "198.51.100.25",
    "10.0.10.22": "198.51.100.22",
    "10.0.10.35": "198.51.100.35",
    "10.0.10.15": "198.51.100.15",
    "10.0.20.50": "198.51.100.50",
    "10.10.10.1": "198.51.100.1",
    "10.66.66.100": "198.51.100.66",
}

# Agent name mapping: PookaSec-specific names -> generic names
AGENT_NAME_MAP = {
    "pookasec-server": "wazuh.manager",
    "Leighs-MacBook-Air.local": "ANALYST01",
    "Leighs-MacBook-Air": "ANALYST01",
    "MacBook": "ANALYST01",
}

# Agent IDs: normalize to a consistent set
AGENT_ID_MAP = {
    # Old IDs -> consistent portable IDs
    "003": "010",  # DC01
    "007": "020",  # WS01
    "008": "020",  # WS01 alt
    "009": "020",  # WS01 alt
    "010": "030",  # Linux host
    "011": "040",  # Server
    "012": "010",  # DC01
    "013": "011",  # FS01
    "014": "020",  # WS01
    "016": "001",  # GW01
    "017": "030",  # VULN01
    "018": "010",  # DC01
    "019": "011",  # FS01
    "020": "020",  # WS01
    "021": "001",  # GW01
    "022": "030",  # VULN01
}

# ---------------------------------------------------------------------------
# Metadata fields to keep in public version
# ---------------------------------------------------------------------------
KEEP_METADATA = {
    "attack_id", "variation", "name", "description",
    "expected_detection", "kill_chain_phase", "kill_chain_phases",
    "format", "format_version", "platform", "os",
    "mitre_tactic", "mitre_technique", "mitre_techniques",
    "technique_id", "technique_name", "tactic",
    "references", "source_url", "tool", "tool_url",
    "malware_family", "threat_actor", "cve",
    "cloud_provider", "data_source",
    "total_logs", "severity",
    "ground_truth", "legitimate_explanation", "suspicious_explanation",
}


def convert_rule_id(rule_id: str) -> str:
    """Convert a Wazuh-specific rule ID to portable Fomorian range."""
    if rule_id in RULE_ID_MAP:
        return RULE_ID_MAP[rule_id]
    # Already in Fomorian range (100xxx)
    if rule_id.startswith("100"):
        return rule_id
    # Unknown ID: map to generic Fomorian ID
    return "100001"


def convert_ip(ip: str) -> str:
    """Convert PookaSec lab IP to generic documentation IP."""
    if ip in AGENT_IP_MAP:
        return AGENT_IP_MAP[ip]
    # Keep generic IPs as-is
    if ip in ("any", "127.0.0.1", "0.0.0.0", "::1"):
        return ip
    # Template variables
    if ip.startswith("{{"):
        return ip
    # Already in TEST-NET range
    if ip.startswith("198.51.100."):
        return ip
    # Catch-all: any remaining RFC 1918 private IPs -> map to TEST-NET-2
    # using last octet to maintain uniqueness
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                      "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                      "172.29.", "172.30.", "172.31.")):
        parts = ip.split(".")
        last_octet = parts[-1] if len(parts) == 4 else "99"
        return f"198.51.100.{last_octet}"
    # Public IP or other, keep it
    return ip


def convert_agent_id(agent_id: str) -> str:
    """Convert PookaSec agent ID to portable ID."""
    if agent_id in AGENT_ID_MAP:
        return AGENT_ID_MAP[agent_id]
    if agent_id.startswith("{{"):
        return agent_id
    return agent_id


import re

# ---------------------------------------------------------------------------
# String replacements: PookaSec-specific strings -> generic equivalents
# ---------------------------------------------------------------------------
STRING_REPLACEMENTS = {
    # Domain names
    "attacklab.local": "corp.local",
    "ATTACKLAB": "CORP",
    "attacklab": "corp",
    "pookasec.onmicrosoft.com": "contoso.onmicrosoft.com",
    "pookasec-monitoring": "cloudtrail-monitoring",
    "pookasec": "labnet",
    # Personal info
    "leighleinweber": "analyst",
    "Leighs-MacBook-Air.local": "ANALYST01",
    "Leighs-MacBook-Air": "ANALYST01",
}

# IP string replacements for IPs embedded in command lines and messages.
# Order matters: more specific (longer) IPs first to avoid partial matches.
IP_STRING_REPLACEMENTS = {
    # VirtualBox era (192.168.56.x)
    "192.168.56.110": "198.51.100.110",
    "192.168.56.200": "198.51.100.200",
    "192.168.56.100": "198.51.100.10",
    "192.168.56.101": "198.51.100.11",
    "192.168.56.102": "198.51.100.12",
    "192.168.56.103": "198.51.100.20",
    "192.168.56.104": "198.51.100.1",
    "192.168.56.105": "198.51.100.30",
    # Old 10.0.10.x era
    "10.0.10.100": "198.51.100.100",
    "10.0.10.50": "198.51.100.50",
    "10.0.10.45": "198.51.100.45",
    "10.0.10.35": "198.51.100.35",
    "10.0.10.30": "198.51.100.30",
    "10.0.10.25": "198.51.100.25",
    "10.0.10.22": "198.51.100.22",
    "10.0.10.20": "198.51.100.20",
    "10.0.10.15": "198.51.100.15",
    "10.0.10.12": "198.51.100.12",
    "10.0.10.10": "198.51.100.10",
    "10.0.10.5": "198.51.100.5",
    # Proxmox era
    "10.10.30.10": "198.51.100.40",
    "10.10.20.10": "198.51.100.30",
    "10.10.10.12": "198.51.100.20",
    "10.10.10.11": "198.51.100.11",
    "10.10.10.10": "198.51.100.10",
    "10.10.10.1": "198.51.100.1",
    # Other PookaSec-specific
    "192.168.1.100": "198.51.100.100",
    "192.168.1.60": "198.51.100.60",
    "192.168.1.50": "198.51.100.1",
    "192.168.1.10": "198.51.100.10",
    "10.66.66.100": "198.51.100.66",
    "10.1.1.52": "198.51.100.52",
    "10.1.1.50": "198.51.100.50",
    "10.1.1.30": "198.51.100.30",
    "10.1.1.20": "198.51.100.20",
    "10.1.0.12": "198.51.100.20",
    "10.1.0.11": "198.51.100.11",
    "10.1.0.10": "198.51.100.10",
    "10.0.20.50": "198.51.100.50",
}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

# Field names that likely contain IP addresses
_IP_FIELD_NAMES = {
    "srcip", "dstip", "sourceip", "destinationip",
    "sourceIp", "destinationIp", "ip", "ipAddress",
    "sourceIPAddress", "callerIp", "clientIP",
}


def _deep_convert_ips(obj):
    """Recursively walk a dict/list and convert any IP-like string values."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if isinstance(v, str) and k.lower() in {n.lower() for n in _IP_FIELD_NAMES}:
                result[k] = convert_ip(v)
            elif isinstance(v, str) and _IP_RE.match(v):
                # Check if it looks like an IP and is private
                result[k] = convert_ip(v)
            elif isinstance(v, (dict, list)):
                result[k] = _deep_convert_ips(v)
            else:
                result[k] = v
        return result
    elif isinstance(obj, list):
        return [_deep_convert_ips(item) for item in obj]
    return obj


def _deep_replace_strings(obj, replacements: dict):
    """Recursively walk a dict/list and replace PookaSec-specific strings."""
    if isinstance(obj, str):
        for old, new in replacements.items():
            obj = obj.replace(old, new)
        return obj
    elif isinstance(obj, dict):
        return {k: _deep_replace_strings(v, replacements) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_deep_replace_strings(item, replacements) for item in obj]
    return obj


# Regex to find any remaining RFC 1918 private IPs in strings
_PRIVATE_IP_RE = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    r"|\b(192\.168\.\d{1,3}\.\d{1,3})\b"
    r"|\b(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)


def _replace_private_ip_match(m):
    """Replace a matched private IP with a TEST-NET-2 equivalent."""
    ip = m.group(0)
    # Already converted
    if ip.startswith("198.51.100."):
        return ip
    parts = ip.split(".")
    last_octet = parts[-1] if len(parts) == 4 else "99"
    return f"198.51.100.{last_octet}"


def _deep_sanitize_private_ips(obj):
    """Final pass: regex-replace any remaining private IPs in all strings."""
    if isinstance(obj, str):
        return _PRIVATE_IP_RE.sub(_replace_private_ip_match, obj)
    elif isinstance(obj, dict):
        return {k: _deep_sanitize_private_ips(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_deep_sanitize_private_ips(item) for item in obj]
    return obj


def convert_log(log_data: dict) -> dict:
    """Convert a single log entry's inner log dict."""
    if not isinstance(log_data, dict):
        return log_data

    result = dict(log_data)

    # Convert rule ID
    rule = result.get("rule")
    if isinstance(rule, dict) and "id" in rule:
        rule["id"] = convert_rule_id(rule["id"])

    # Convert agent info
    agent = result.get("agent")
    if isinstance(agent, dict):
        if "ip" in agent:
            agent["ip"] = convert_ip(agent["ip"])
        if "id" in agent:
            agent["id"] = convert_agent_id(agent["id"])
        if "name" in agent and agent["name"] in AGENT_NAME_MAP:
            agent["name"] = AGENT_NAME_MAP[agent["name"]]

    # Convert manager name
    manager = result.get("manager")
    if isinstance(manager, dict):
        if "name" in manager and "pookasec" in manager["name"].lower():
            manager["name"] = "wazuh.manager"

    # Deep-walk all data fields to convert any embedded IPs and domain names
    if "data" in result and isinstance(result["data"], dict):
        result["data"] = _deep_convert_ips(result["data"])
        result["data"] = _deep_replace_strings(result["data"], STRING_REPLACEMENTS)

    # Strip empty timestamp in data (known indexer issue)
    if "timestamp" in result and result["timestamp"] == "":
        del result["timestamp"]

    # Final pass: replace PookaSec-specific strings across the entire log
    result = _deep_replace_strings(result, STRING_REPLACEMENTS)

    return result


def convert_metadata(meta: dict) -> dict:
    """Strip PookaSec-specific metadata, keep universal fields."""
    result = {}
    for key, value in meta.items():
        if key in KEEP_METADATA:
            result[key] = value
    # Ensure format markers
    result.setdefault("format", "wazuh-native")
    result.setdefault("format_version", "1.0")
    return result


def convert_file(src_path: str, dst_path: str) -> dict:
    """Convert a single attack log file from private to public format.

    Returns stats dict.
    """
    with open(src_path) as f:
        data = json.load(f)

    # Convert metadata
    if "_metadata" in data:
        data["_metadata"] = convert_metadata(data["_metadata"])

    # Convert each log entry
    rule_ids_changed = 0
    for log_entry in data.get("logs", []):
        # Some files nest the Wazuh alert inside a "log" key,
        # others put it directly on the log entry
        inner = log_entry.get("log", {})
        if isinstance(inner, dict) and inner:
            old_rule_id = inner.get("rule", {}).get("id", "")
            converted = convert_log(inner)
            log_entry["log"] = converted
            new_rule_id = converted.get("rule", {}).get("id", "")
            if old_rule_id != new_rule_id:
                rule_ids_changed += 1

        # Also convert the outer log entry itself (handles flat format)
        old_rule_id_outer = log_entry.get("rule", {}).get("id", "") if isinstance(log_entry.get("rule"), dict) else ""
        converted_outer = convert_log(log_entry)
        # Update the entry in place (convert_log returns a new dict)
        for k, v in converted_outer.items():
            log_entry[k] = v
        new_rule_id_outer = log_entry.get("rule", {}).get("id", "") if isinstance(log_entry.get("rule"), dict) else ""
        if old_rule_id_outer and old_rule_id_outer != new_rule_id_outer:
            rule_ids_changed += 1

    # Final safety net: replace any remaining PookaSec strings in the entire file
    data = _deep_replace_strings(data, IP_STRING_REPLACEMENTS)
    data = _deep_replace_strings(data, STRING_REPLACEMENTS)
    # Catch-all: regex-replace any remaining RFC 1918 IPs
    data = _deep_sanitize_private_ips(data)

    # Write output
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(dst_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
        f.write("\n")

    return {
        "logs": len(data.get("logs", [])),
        "rule_ids_changed": rule_ids_changed,
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: sync-private-to-public.py <private-attacks-dir> <public-attacks-dir>")
        print()
        print("Example:")
        print("  python3 scripts/sync-private-to-public.py \\")
        print("    ~/Projects/pookasec/fomorian/attacks \\")
        print("    ./attacks")
        sys.exit(1)

    src_dir = Path(sys.argv[1]).resolve()
    dst_dir = Path(sys.argv[2]).resolve()

    if not src_dir.is_dir():
        print(f"Error: source directory not found: {src_dir}")
        sys.exit(1)

    print(f"Source:      {src_dir}")
    print(f"Destination: {dst_dir}")
    print()

    # Find all JSON files
    json_files = sorted(glob.glob(str(src_dir / "**" / "*.json"), recursive=True))
    print(f"Found {len(json_files)} attack log files")
    print()

    total_files = 0
    total_logs = 0
    total_rule_changes = 0
    errors = []

    for src_path in json_files:
        rel_path = os.path.relpath(src_path, src_dir)
        dst_path = str(dst_dir / rel_path)

        try:
            stats = convert_file(src_path, dst_path)
            total_files += 1
            total_logs += stats["logs"]
            total_rule_changes += stats["rule_ids_changed"]
        except Exception as e:
            errors.append(f"{rel_path}: {e}")

    print(f"Converted:         {total_files} files")
    print(f"Total log entries: {total_logs}")
    print(f"Rule IDs changed:  {total_rule_changes}")
    print(f"Errors:            {len(errors)}")

    if errors:
        print()
        print("Errors:")
        for err in errors[:20]:
            print(f"  {err}")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
