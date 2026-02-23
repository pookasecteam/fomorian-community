"""Universal Wazuh injector supporting multiple deployment types.

Supports:
- Docker-based Wazuh (single-node, multi-node)
- Native Linux installation
- Local agent-only installations
- Remote injection via SSH

Injection Methods:
- api: Wazuh Manager API (requires API access)
- file: Monitored log file (default, most compatible)
- archives: Direct write to archives.json (manager only)
- alerts: Direct write to alerts.json (manager only)
"""

import copy
import json
import os
import subprocess
import urllib.request
import urllib.error
import ssl
import base64
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

from .base import SIEMInjector, InjectorConfig, LogEntry


@dataclass
class WazuhInstallation:
    """Detected Wazuh installation details."""
    type: str  # 'docker', 'native', 'agent', 'none'
    manager_available: bool
    base_path: str
    container_name: Optional[str]
    version: Optional[str]
    api_available: bool


class WazuhInjector(SIEMInjector):
    """
    Universal Wazuh injector supporting multiple deployment scenarios.

    Configuration:
        host: Wazuh manager hostname (for API)
        port: Wazuh API port (default: 55000)
        protocol: 'https' (default)
        username: API username (default: 'wazuh-wui')
        password: API password
        extra:
            method: Injection method - 'api', 'file', 'archives', 'alerts', 'auto' (default: auto)
            log_file: Path for file injection (default: /var/log/fomorian/attacks.json)
            container: Docker container name (auto-detected if not specified)
            ssh_host: Remote SSH host for remote injection
            ssh_user: SSH username (default: root)
            facility: Facility name for logs (default: fomorian)

    Methods:
        'auto': Auto-detect best method based on installation
        'api': Use Wazuh Manager API
        'file': Write to monitored log file (requires ossec.conf setup)
        'archives': Write directly to archives.json (manager only)
        'alerts': Write directly to alerts.json (manager only)
    """

    name = "wazuh"
    default_port = 55000
    supports_batch = True

    # Common Wazuh paths
    NATIVE_PATHS = [
        "/var/ossec",
        "/usr/share/wazuh-manager",
    ]
    DOCKER_CONTAINERS = [
        "wazuh-manager",
        "wazuh-manager",
        "wazuh.manager",
    ]

    def __init__(self, config: InjectorConfig):
        super().__init__(config)
        self._token: Optional[str] = None
        self._method = config.extra.get("method", "auto")
        self._installation: Optional[WazuhInstallation] = None
        self._effective_method: Optional[str] = None

    def connect(self) -> bool:
        """Test connection and auto-detect best injection method."""
        # Detect installation
        self._installation = self._detect_installation()

        if self._method == "auto":
            self._effective_method = self._select_best_method()
        else:
            self._effective_method = self._method

        # Validate the selected method works
        if self._effective_method == "api":
            return self._authenticate()
        elif self._effective_method == "file":
            return self._test_file_access()
        elif self._effective_method in ("archives", "alerts"):
            return self._test_direct_write_access()
        else:
            return self._test_file_access()  # Fallback

    def _detect_installation(self) -> WazuhInstallation:
        """Detect how Wazuh is installed on the system."""
        # Check for Docker containers first
        docker_container = self._detect_docker_container()
        if docker_container:
            return WazuhInstallation(
                type="docker",
                manager_available=True,
                base_path="/var/ossec",  # Path inside container
                container_name=docker_container,
                version=self._get_wazuh_version(docker_container),
                api_available=self._test_api_connectivity(),
            )

        # Check for native installation
        native_path = self._detect_native_installation()
        if native_path:
            is_manager = self._is_wazuh_manager(native_path)
            return WazuhInstallation(
                type="native",
                manager_available=is_manager,
                base_path=native_path,
                container_name=None,
                version=self._get_native_version(native_path),
                api_available=is_manager and self._test_api_connectivity(),
            )

        # Check for agent-only installation
        agent_path = self._detect_agent_only()
        if agent_path:
            return WazuhInstallation(
                type="agent",
                manager_available=False,
                base_path=agent_path,
                container_name=None,
                version=None,
                api_available=False,
            )

        # No Wazuh detected - file injection will still work
        return WazuhInstallation(
            type="none",
            manager_available=False,
            base_path="",
            container_name=None,
            version=None,
            api_available=self._test_api_connectivity(),
        )

    def _detect_docker_container(self) -> Optional[str]:
        """Detect if Wazuh is running in a Docker container."""
        try:
            # Check for common Wazuh container names
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                running_containers = result.stdout.strip().split("\n")
                for container in self.DOCKER_CONTAINERS:
                    if container in running_containers:
                        return container

                # Also check for partial matches
                for running in running_containers:
                    if "wazuh" in running.lower() and "manager" in running.lower():
                        return running
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _detect_native_installation(self) -> Optional[str]:
        """Detect native Wazuh installation path."""
        for path in self.NATIVE_PATHS:
            if os.path.isdir(path) and os.path.isdir(os.path.join(path, "etc")):
                return path
        return None

    def _detect_agent_only(self) -> Optional[str]:
        """Detect Wazuh agent installation (no manager)."""
        agent_paths = ["/var/ossec", "/Library/Ossec"]
        for path in agent_paths:
            if os.path.isdir(path):
                # Agent has ossec.conf but no manager-specific dirs
                if os.path.isfile(os.path.join(path, "etc", "ossec.conf")):
                    if not os.path.isdir(os.path.join(path, "logs", "alerts")):
                        return path
        return None

    def _is_wazuh_manager(self, base_path: str) -> bool:
        """Check if the installation is a Wazuh manager (not just agent)."""
        manager_indicators = [
            os.path.join(base_path, "logs", "alerts"),
            os.path.join(base_path, "logs", "archives"),
            os.path.join(base_path, "bin", "wazuh-analysisd"),
        ]
        return any(os.path.exists(p) for p in manager_indicators)

    def _get_wazuh_version(self, container: str) -> Optional[str]:
        """Get Wazuh version from Docker container."""
        try:
            result = subprocess.run(
                ["docker", "exec", container, "/var/ossec/bin/wazuh-control", "info", "-v"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _get_native_version(self, base_path: str) -> Optional[str]:
        """Get Wazuh version from native installation."""
        try:
            result = subprocess.run(
                [os.path.join(base_path, "bin", "wazuh-control"), "info", "-v"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None

    def _test_api_connectivity(self) -> bool:
        """Test if Wazuh API is reachable."""
        if not self.config.password:
            return False
        try:
            return self._authenticate()
        except Exception:
            return False

    def _select_best_method(self) -> str:
        """Select the best injection method based on detected installation."""
        inst = self._installation

        # If manager is available, prefer alerts for direct injection
        # (alerts.json is what Filebeat tails and indexes)
        if inst.manager_available:
            return "alerts"

        # If API is available and configured, use it
        if inst.api_available and self.config.password:
            return "api"

        # Default to file-based injection (most universal)
        return "file"

    def _test_file_access(self) -> bool:
        """Test if we can write to the log file."""
        log_file = Path(self.config.extra.get("log_file", "/var/log/fomorian/attacks.json"))
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(log_file, "a") as f:
                pass
            return True
        except Exception:
            return False

    def _test_direct_write_access(self) -> bool:
        """Test if we can write to archives/alerts directory."""
        inst = self._installation
        if not inst or not inst.manager_available:
            return False

        if inst.type == "docker":
            # Test write access in container
            test_cmd = f"touch /var/ossec/logs/archives/.fomorian_test && rm /var/ossec/logs/archives/.fomorian_test"
            try:
                result = subprocess.run(
                    ["docker", "exec", inst.container_name, "sh", "-c", test_cmd],
                    capture_output=True,
                    timeout=10,
                )
                return result.returncode == 0
            except Exception:
                return False
        else:
            # Native installation
            test_file = Path(inst.base_path) / "logs" / "archives" / ".fomorian_test"
            try:
                test_file.touch()
                test_file.unlink()
                return True
            except Exception:
                return False

    def _authenticate(self) -> bool:
        """Authenticate with Wazuh API and get token."""
        try:
            url = f"{self.get_base_url()}/security/user/authenticate"

            credentials = base64.b64encode(
                f"{self.config.username or 'wazuh-wui'}:{self.config.password}".encode()
            ).decode()

            req = urllib.request.Request(url, method="POST")
            req.add_header("Authorization", f"Basic {credentials}")
            req.add_header("Content-Type", "application/json")

            context = self._get_ssl_context()

            with urllib.request.urlopen(req, timeout=30, context=context) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                self._token = result.get("data", {}).get("token")
                return bool(self._token)
        except Exception:
            return False

    def _get_ssl_context(self):
        """Get SSL context for API requests."""
        if not self.config.verify_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        return None

    def _api_request(self, endpoint: str, method: str = "GET", data: Any = None) -> Optional[Dict]:
        """Make authenticated API request."""
        if not self._token:
            if not self._authenticate():
                return None

        url = f"{self.get_base_url()}{endpoint}"
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Content-Type", "application/json")

        if data:
            req.data = json.dumps(data).encode("utf-8")

        try:
            context = self._get_ssl_context()
            with urllib.request.urlopen(req, timeout=30, context=context) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self._token = None
                if self._authenticate():
                    return self._api_request(endpoint, method, data)
            return None
        except Exception:
            return None

    def send_log(self, log: Dict[str, Any]) -> bool:
        """Send a single log using the selected method."""
        method = self._effective_method or "file"

        if method == "api":
            return self._send_to_api(log)
        elif method == "file":
            return self._send_to_file([log])
        elif method == "archives":
            return self._send_to_archives(log)
        elif method == "alerts":
            return self._send_to_alerts(log)
        else:
            return self._send_to_file([log])

    def send_batch(self, logs: List[Dict[str, Any]]) -> int:
        """Send batch of logs."""
        method = self._effective_method or "file"

        if method == "file":
            if self._send_to_file(logs):
                return len(logs)
            return 0
        elif method in ("archives", "alerts"):
            success = 0
            for log in logs:
                if method == "archives":
                    if self._send_to_archives(log):
                        success += 1
                else:
                    if self._send_to_alerts(log):
                        success += 1
            return success
        else:
            success = 0
            for log in logs:
                if self._send_to_api(log):
                    success += 1
            return success

    def _send_to_file(self, logs: List[Dict[str, Any]]) -> bool:
        """Write logs to file for Wazuh to read."""
        log_file = Path(self.config.extra.get("log_file", "/var/log/fomorian/attacks.json"))

        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)

            with open(log_file, "a") as f:
                for log in logs:
                    f.write(json.dumps(log, default=str) + "\n")
            return True
        except Exception:
            return False

    def _send_to_api(self, log: Dict[str, Any]) -> bool:
        """Send log via Wazuh API."""
        result = self._api_request(
            "/events",
            method="POST",
            data={"events": [log]},
        )

        if result and result.get("error") == 0:
            return True

        # Fallback to manager logs
        alert = self._to_wazuh_alert(log)
        result = self._api_request(
            "/manager/logs",
            method="POST",
            data={"message": json.dumps(alert)},
        )

        return result is not None and result.get("error") == 0

    def _send_to_archives(self, log: Dict[str, Any]) -> bool:
        """Write directly to archives.json."""
        inst = self._installation
        if not inst or not inst.manager_available:
            return False

        archive_entry = self._prepare_alert(log)
        archive_json = json.dumps(archive_entry, default=str)

        if inst.type == "docker":
            try:
                result = subprocess.run(
                    [
                        "docker", "exec", inst.container_name,
                        "sh", "-c",
                        f"echo '{archive_json}' >> /var/ossec/logs/archives/archives.json"
                    ],
                    capture_output=True,
                    timeout=10,
                )
                return result.returncode == 0
            except Exception:
                return False
        else:
            archive_file = Path(inst.base_path) / "logs" / "archives" / "archives.json"
            try:
                with open(archive_file, "a") as f:
                    f.write(archive_json + "\n")
                return True
            except Exception:
                return False

    def _prepare_alert(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare a log for writing to alerts.json.

        Native-format logs (rule+agent+decoder+data) are written directly
        with minimal decoration. Non-native logs go through the full
        _to_wazuh_alert() wrapping.
        """
        # Extract metadata before checking format
        pt = log.get("_purple_team", {})
        now = datetime.utcnow()
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"

        # Check if the inner log data is native Wazuh format
        # Native logs have: rule (with id), agent, decoder, data
        inner = log.get("log") if isinstance(log.get("log"), dict) else None
        native_source = inner if (inner and self._is_wazuh_native(inner)) else (
            log if self._is_wazuh_native(log) else None
        )

        if native_source is not None:
            # Native path: copy the native alert structure directly
            alert = {}
            # Only copy known Wazuh alert keys from the native source
            wazuh_keys = (
                "rule", "agent", "manager", "decoder", "location",
                "data", "id", "full_log",
            )
            for key in wazuh_keys:
                if key in native_source:
                    alert[key] = copy.deepcopy(native_source[key]) if isinstance(native_source[key], (dict, list)) else native_source[key]

            # Set fresh timestamp
            alert["timestamp"] = timestamp

            # Mark as fomorian
            decoder = alert.get("decoder", {})
            if decoder.get("name") != "fomorian":
                alert["decoder"] = {"parent": decoder.get("name", ""), "name": "fomorian"}

            # Add fomorian group
            groups = alert.get("rule", {}).get("groups", [])
            if "fomorian" not in groups:
                alert.setdefault("rule", {})["groups"] = ["fomorian"] + groups

            # Add id if missing
            if not alert.get("id"):
                alert["id"] = f"fomorian.{pt.get('sequence', 0)}.{int(now.timestamp())}"

            # Clean data: remove empty timestamp (mapper_parsing_exception)
            if "data" in alert and isinstance(alert["data"], dict):
                alert["data"] = {
                    k: v for k, v in alert["data"].items()
                    if not (k == "timestamp" and v == "")
                }

            # Clean MITRE arrays: remove empty strings
            mitre = alert.get("rule", {}).get("mitre", {})
            if mitre:
                for key in ("id", "tactic", "technique"):
                    if key in mitre and isinstance(mitre[key], list):
                        mitre[key] = [v for v in mitre[key] if v]

            return alert

        # Non-native fallback: use full wrapping
        return self._to_wazuh_alert(log)

    def _send_to_alerts(self, log: Dict[str, Any]) -> bool:
        """Write directly to alerts.json.

        For native-format logs (already have rule/agent/decoder/data), write
        them with minimal decoration: fresh timestamp, fomorian decoder tag,
        and fomorian group. This avoids the re-wrapping that was causing
        bloated data fields and silent indexing failures.
        """
        inst = self._installation
        if not inst or not inst.manager_available:
            return False

        alert = self._prepare_alert(log)
        alert_json = json.dumps(alert, default=str)

        if inst.type == "docker":
            try:
                result = subprocess.run(
                    [
                        "docker", "exec", inst.container_name,
                        "sh", "-c",
                        f"echo '{alert_json}' >> /var/ossec/logs/alerts/alerts.json"
                    ],
                    capture_output=True,
                    timeout=10,
                )
                return result.returncode == 0
            except Exception:
                return False
        else:
            alerts_file = Path(inst.base_path) / "logs" / "alerts" / "alerts.json"
            try:
                with open(alerts_file, "a") as f:
                    f.write(alert_json + "\n")
                return True
            except Exception:
                return False

    def _to_archive_format(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Convert log to Wazuh archives format."""
        pt = log.get("_purple_team", {})
        timestamp = log.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"

        return {
            "timestamp": timestamp,
            "agent": {
                "id": log.get("agent", {}).get("id", "000"),
                "name": log.get("agent", {}).get("name", log.get("host", "fomorian")),
                "ip": log.get("agent", {}).get("ip", "any"),
            },
            "manager": {
                "name": "wazuh-manager",
            },
            "data": log,
            "decoder": {
                "name": "fomorian",
            },
            "location": "fomorian-generator",
            "full_log": json.dumps(log, default=str),
        }

    def _is_wazuh_native(self, log: Dict[str, Any]) -> bool:
        """Check if a log is already in Wazuh native alert format."""
        return (
            "rule" in log
            and "agent" in log
            and isinstance(log.get("rule"), dict)
            and "id" in log.get("rule", {})
            and "decoder" in log
        )

    def _to_wazuh_alert(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Convert log to Wazuh alert format.

        If the log is already in Wazuh native format (has rule, agent, decoder),
        it is passed through with minimal fixups. Otherwise it is wrapped in a
        new alert envelope.
        """
        pt = log.get("_purple_team", {})
        timestamp = log.get("timestamp") or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"

        # If already Wazuh native format, pass through with fixups
        if self._is_wazuh_native(log):
            alert = dict(log)
            alert["timestamp"] = timestamp
            # Strip internal metadata
            alert.pop("_purple_team", None)
            # Ensure decoder marks this as fomorian
            if alert.get("decoder", {}).get("name") != "fomorian":
                alert.setdefault("decoder", {})["parent"] = alert["decoder"].get("name", "")
                alert["decoder"]["name"] = "fomorian"
            # Add fomorian group if not present
            groups = alert.get("rule", {}).get("groups", [])
            if "fomorian" not in groups:
                alert["rule"]["groups"] = ["fomorian"] + groups
            # Add id if missing
            if not alert.get("id"):
                alert["id"] = f"fomorian.{pt.get('sequence', 0)}.{int(datetime.utcnow().timestamp())}"
            # Clean empty timestamp in data subfield
            if "data" in alert and isinstance(alert["data"], dict):
                alert["data"] = {
                    k: v for k, v in alert["data"].items()
                    if not (k == "timestamp" and not v)
                }
            # Clean empty MITRE arrays
            mitre = alert.get("rule", {}).get("mitre", {})
            if mitre:
                for key in ("id", "tactic", "technique"):
                    if key in mitre:
                        mitre[key] = [v for v in mitre[key] if v]
            return alert

        # Non-native format: wrap in alert envelope
        technique = pt.get("technique") or log.get("technique") or "T0000"
        phase = pt.get("attack_phase") or log.get("attack_phase") or "unknown"
        comment = pt.get("comment") or log.get("_comment") or "Fomorian Attack Simulation"

        # Map phase to MITRE tactic
        phase_to_tactic = {
            "initial-access": "initial-access",
            "execution": "execution",
            "persistence": "persistence",
            "privilege-escalation": "privilege-escalation",
            "defense-evasion": "defense-evasion",
            "credential-access": "credential-access",
            "discovery": "discovery",
            "lateral-movement": "lateral-movement",
            "collection": "collection",
            "command-and-control": "command-and-control",
            "exfiltration": "exfiltration",
            "impact": "impact",
        }

        # Build data dict, excluding fields that conflict with Wazuh index mappings
        data = {}
        for k, v in log.items():
            if k == "timestamp" and not v:
                continue  # Skip empty timestamps
            if k == "data" and isinstance(v, dict):
                # Hoist inner data fields to avoid data.data nesting conflict
                data.update(v)
                continue
            data[k] = v

        alert = {
            "timestamp": timestamp,
            "rule": {
                "level": 12,
                "description": comment,
                "id": "100001",
                "mitre": {
                    "id": [technique],
                    "tactic": [phase_to_tactic.get(phase, phase)],
                    "technique": [technique],
                },
                "groups": ["fomorian", "attack_simulation", phase],
                "firedtimes": 1,
            },
            "agent": {
                "id": log.get("agent", {}).get("id", "000"),
                "name": log.get("agent", {}).get("name", log.get("host", "fomorian")),
                "ip": log.get("agent", {}).get("ip", "any"),
            },
            "manager": {
                "name": "wazuh-manager",
            },
            "id": f"fomorian.{pt.get('sequence', 0)}.{int(datetime.utcnow().timestamp())}",
            "decoder": {
                "name": "fomorian",
            },
            "location": "fomorian-generator",
            "full_log": json.dumps(log, default=str),
            "data": data,
        }

        # Clean up empty values in data that would cause indexer mapping failures
        inner_rule = alert["data"].get("rule", {})
        inner_mitre = inner_rule.get("mitre", {})
        if inner_mitre:
            # Remove empty string entries from MITRE arrays
            for key in ("id", "tactic", "technique"):
                if key in inner_mitre:
                    inner_mitre[key] = [v for v in inner_mitre[key] if v]

        # Add Windows-specific fields if present
        if "winlog" in log:
            winlog = log["winlog"]
            alert["data"]["win"] = {
                "system": {
                    "eventID": str(winlog.get("event_id", "")),
                    "providerName": winlog.get("provider_name", ""),
                    "channel": winlog.get("channel", ""),
                    "computer": winlog.get("computer_name", ""),
                },
                "eventdata": winlog.get("event_data", {}),
            }

        return alert

    def prepare_log(self, log_entry: LogEntry) -> Dict[str, Any]:
        """Prepare log with Wazuh-friendly structure.

        If the inner log is already in native Wazuh format (has rule with id,
        agent, decoder), preserve the original fields instead of overwriting.
        """
        prepared = super().prepare_log(log_entry)

        # Check if the original log is already in native Wazuh format
        if self._is_wazuh_native(log_entry.log):
            # Native format: don't overwrite rule/decoder from template
            return prepared

        # Non-native: add Wazuh-specific fields
        facility = self.config.extra.get("facility", "fomorian")
        prepared["decoder"] = {"name": facility}
        prepared["location"] = f"{facility}-generator"

        # Add rule info for easier processing
        prepared["rule"] = {
            "level": 10,
            "description": log_entry.comment,
            "groups": [facility, log_entry.attack_phase],
            "mitre": {
                "id": [log_entry.technique],
                "tactic": [log_entry.attack_phase],
            },
        }

        return prepared

    def get_installation_info(self) -> Dict[str, Any]:
        """Get information about detected Wazuh installation."""
        if not self._installation:
            self._installation = self._detect_installation()

        inst = self._installation
        return {
            "type": inst.type,
            "manager_available": inst.manager_available,
            "base_path": inst.base_path,
            "container_name": inst.container_name,
            "version": inst.version,
            "api_available": inst.api_available,
            "effective_method": self._effective_method,
            "configured_method": self._method,
        }

    def get_setup_instructions(self) -> str:
        """Get setup instructions based on detected installation."""
        if not self._installation:
            self._installation = self._detect_installation()

        inst = self._installation
        log_file = self.config.extra.get("log_file", "/var/log/fomorian/attacks.json")
        facility = self.config.extra.get("facility", "fomorian")

        instructions = f"""
=== Fomorian Wazuh Integration Setup ===

Detected Installation: {inst.type.upper()}
"""

        if inst.type == "docker":
            instructions += f"""
Container: {inst.container_name}
Version: {inst.version or 'Unknown'}

Option 1: Direct Archives Injection (Recommended - No Config Required)
----------------------------------------------------------------------
Use --inject-method archives to write directly to Wazuh archives:

    fomorian generate \\
      --config ./my-config \\
      --engagement ransomware \\
      --inject wazuh \\
      --inject-method archives

Option 2: File-based Injection
------------------------------
1. Create monitored log file location:
   docker exec {inst.container_name} mkdir -p /var/log/fomorian
   docker exec {inst.container_name} chown wazuh:wazuh /var/log/fomorian

2. Add to ossec.conf inside container:
   docker exec {inst.container_name} bash -c 'cat >> /var/ossec/etc/ossec.conf << EOF
   <localfile>
     <log_format>json</log_format>
     <location>{log_file}</location>
     <label key="{facility}">true</label>
   </localfile>
   EOF'

3. Restart Wazuh:
   docker exec {inst.container_name} /var/ossec/bin/wazuh-control restart

4. Generate and inject:
   fomorian generate --config ./my-config --engagement ransomware --inject wazuh
"""

        elif inst.type == "native":
            if inst.manager_available:
                instructions += f"""
Manager Path: {inst.base_path}
Version: {inst.version or 'Unknown'}

Option 1: Direct Archives Injection (Recommended)
-------------------------------------------------
    fomorian generate \\
      --config ./my-config \\
      --engagement ransomware \\
      --inject wazuh \\
      --inject-method archives

Option 2: File-based Injection
------------------------------
1. Create log directory:
   sudo mkdir -p /var/log/fomorian
   sudo chown wazuh:wazuh /var/log/fomorian

2. Add to /var/ossec/etc/ossec.conf:
   <localfile>
     <log_format>json</log_format>
     <location>{log_file}</location>
     <label key="{facility}">true</label>
   </localfile>

3. Restart Wazuh manager:
   sudo systemctl restart wazuh-manager

4. Generate and inject:
   fomorian generate --config ./my-config --engagement ransomware --inject wazuh
"""
            else:
                instructions += """
Agent-only installation detected. Use file injection method.
"""

        elif inst.type == "agent":
            instructions += f"""
Agent-only installation detected at: {inst.base_path}

For agent-only installations, use file injection with local analysis:

1. Create log directory on agent:
   sudo mkdir -p /var/log/fomorian
   sudo chown root:wazuh /var/log/fomorian

2. Add to agent's /var/ossec/etc/ossec.conf:
   <localfile>
     <log_format>json</log_format>
     <location>{log_file}</location>
     <label key="{facility}">true</label>
   </localfile>

3. Restart agent:
   sudo systemctl restart wazuh-agent

4. Generate and copy scenario:
   fomorian generate --config ./my-config --engagement ransomware --output scenario.json
   # Copy scenario.json to agent and append to log file
"""

        else:
            instructions += f"""
No Wazuh installation detected locally.

Option 1: Remote API Injection
------------------------------
Set environment variables and use API injection:

    export PURPLE_TEAM_HOST=your-wazuh-manager
    export PURPLE_TEAM_USERNAME=wazuh-wui
    export PURPLE_TEAM_PASSWORD=your-password

    fomorian generate \\
      --config ./my-config \\
      --engagement ransomware \\
      --inject wazuh \\
      --inject-method api

Option 2: File Output + Manual Copy
-----------------------------------
Generate scenario file and copy to Wazuh manager:

    fomorian generate --config ./my-config --engagement ransomware --output scenario.json
    scp scenario.json user@wazuh-server:/var/log/fomorian/
"""

        return instructions
