"""
Wazuh Connection Management

Handles connections to Wazuh Manager for log injection.
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum


class InjectionMethod(str, Enum):
    """Log injection methods."""
    ALERTS = "alerts"      # Direct write to alerts.json
    ARCHIVES = "archives"  # Direct write to archives.json
    API = "api"            # Via Wazuh Manager API
    FILE = "file"          # Write to monitored log file
    NONE = "none"          # Generate only, no injection


@dataclass
class ConnectionConfig:
    """Configuration for Wazuh connection."""
    # Connection type
    connection_type: str = "docker"  # docker, native, ssh, api

    # Docker settings
    container_name: Optional[str] = None

    # SSH settings
    ssh_host: Optional[str] = None
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key: Optional[str] = None

    # API settings
    api_url: Optional[str] = None
    api_user: Optional[str] = None
    api_password: Optional[str] = None
    verify_ssl: bool = False

    # Paths
    alerts_path: str = "/var/ossec/logs/alerts/alerts.json"
    archives_path: str = "/var/ossec/logs/archives/archives.json"

    # Injection settings
    method: InjectionMethod = InjectionMethod.ALERTS
    batch_size: int = 100
    delay_between_batches: float = 0.0


@dataclass
class ConnectionResult:
    """Result of a connection operation."""
    success: bool
    message: str = ""
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class WazuhConnector:
    """
    Manages connections to Wazuh Manager.

    Supports Docker, native, SSH, and API connections.
    """

    def __init__(self, config: ConnectionConfig):
        """
        Initialize connector.

        Args:
            config: Connection configuration
        """
        self.config = config
        self._connected = False

    def test_connection(self) -> ConnectionResult:
        """
        Test the connection to Wazuh.

        Returns:
            ConnectionResult indicating success/failure
        """
        if self.config.connection_type == "docker":
            return self._test_docker_connection()
        elif self.config.connection_type == "native":
            return self._test_native_connection()
        elif self.config.connection_type == "ssh":
            return self._test_ssh_connection()
        elif self.config.connection_type == "api":
            return self._test_api_connection()
        else:
            return ConnectionResult(
                success=False,
                message=f"Unknown connection type: {self.config.connection_type}"
            )

    def inject_logs(self, logs: List[Dict[str, Any]]) -> ConnectionResult:
        """
        Inject logs into Wazuh.

        Args:
            logs: List of log entries to inject

        Returns:
            ConnectionResult indicating success/failure
        """
        if self.config.method == InjectionMethod.NONE:
            return ConnectionResult(success=True, message="No injection (generate-only mode)")

        if self.config.method == InjectionMethod.ALERTS:
            return self._inject_to_file(logs, self.config.alerts_path)
        elif self.config.method == InjectionMethod.ARCHIVES:
            return self._inject_to_file(logs, self.config.archives_path)
        elif self.config.method == InjectionMethod.API:
            return self._inject_via_api(logs)
        else:
            return ConnectionResult(
                success=False,
                message=f"Unknown injection method: {self.config.method}"
            )

    def _test_docker_connection(self) -> ConnectionResult:
        """Test Docker container connection."""
        container = self.config.container_name
        if not container:
            return ConnectionResult(success=False, message="Container name not specified")

        try:
            # Check container is running
            result = subprocess.run(
                ["docker", "ps", "-q", "-f", f"name={container}"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if not result.stdout.strip():
                return ConnectionResult(
                    success=False,
                    message=f"Container '{container}' is not running"
                )

            # Check Wazuh is installed
            result = subprocess.run(
                ["docker", "exec", container, "test", "-f", "/var/ossec/bin/wazuh-control"],
                capture_output=True,
                timeout=10
            )

            if result.returncode != 0:
                return ConnectionResult(
                    success=False,
                    message="Wazuh not found in container"
                )

            # Check alerts.json exists and is writable
            result = subprocess.run(
                ["docker", "exec", container, "test", "-w", self.config.alerts_path],
                capture_output=True,
                timeout=10
            )

            write_access = result.returncode == 0

            self._connected = True
            return ConnectionResult(
                success=True,
                message=f"Connected to Docker container '{container}'",
                details={"write_access": write_access}
            )

        except subprocess.TimeoutExpired:
            return ConnectionResult(success=False, message="Connection timed out")
        except FileNotFoundError:
            return ConnectionResult(success=False, message="Docker not found")

    def _test_native_connection(self) -> ConnectionResult:
        """Test native installation connection."""
        alerts_path = Path(self.config.alerts_path)

        # Check path exists
        if not alerts_path.parent.exists():
            return ConnectionResult(
                success=False,
                message=f"Directory not found: {alerts_path.parent}"
            )

        # Check write permission
        import os
        write_access = os.access(alerts_path if alerts_path.exists() else alerts_path.parent, os.W_OK)

        self._connected = True
        return ConnectionResult(
            success=True,
            message=f"Native Wazuh installation at {alerts_path.parent.parent}",
            details={"write_access": write_access}
        )

    def _test_ssh_connection(self) -> ConnectionResult:
        """Test SSH connection."""
        if not self.config.ssh_host:
            return ConnectionResult(success=False, message="SSH host not specified")

        try:
            ssh_cmd = self._build_ssh_command(["echo", "ok"])
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode == 0:
                self._connected = True
                return ConnectionResult(
                    success=True,
                    message=f"SSH connection to {self.config.ssh_host} successful"
                )
            else:
                return ConnectionResult(
                    success=False,
                    message=f"SSH failed: {result.stderr}"
                )

        except subprocess.TimeoutExpired:
            return ConnectionResult(success=False, message="SSH connection timed out")
        except FileNotFoundError:
            return ConnectionResult(success=False, message="SSH not found")

    def _test_api_connection(self) -> ConnectionResult:
        """Test API connection."""
        if not self.config.api_url:
            return ConnectionResult(success=False, message="API URL not specified")

        try:
            import urllib.request
            import ssl

            # Create SSL context
            ctx = ssl.create_default_context()
            if not self.config.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            # Test API endpoint
            url = f"{self.config.api_url}/"
            req = urllib.request.Request(url)

            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                if response.status == 200:
                    self._connected = True
                    return ConnectionResult(
                        success=True,
                        message=f"API connection to {self.config.api_url} successful"
                    )

        except Exception as e:
            return ConnectionResult(success=False, message=f"API connection failed: {e}")

        return ConnectionResult(success=False, message="API connection failed")

    def _inject_to_file(self, logs: List[Dict[str, Any]], file_path: str) -> ConnectionResult:
        """Inject logs by writing to a file."""
        # Convert logs to NDJSON
        ndjson_lines = [json.dumps(log) for log in logs]
        ndjson_content = "\n".join(ndjson_lines) + "\n"

        if self.config.connection_type == "docker":
            return self._docker_inject(ndjson_content, file_path)
        elif self.config.connection_type == "native":
            return self._native_inject(ndjson_content, file_path)
        elif self.config.connection_type == "ssh":
            return self._ssh_inject(ndjson_content, file_path)
        else:
            return ConnectionResult(
                success=False,
                message=f"Cannot inject to file with connection type: {self.config.connection_type}"
            )

    def _docker_inject(self, content: str, file_path: str) -> ConnectionResult:
        """Inject via Docker."""
        container = self.config.container_name

        try:
            # Write content to temp file in container
            temp_file = "/tmp/fomorian_inject.ndjson"

            # Use docker exec with stdin
            process = subprocess.Popen(
                ["docker", "exec", "-i", container, "sh", "-c", f"cat > {temp_file}"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=content, timeout=30)

            if process.returncode != 0:
                return ConnectionResult(
                    success=False,
                    message=f"Failed to write temp file: {stderr}"
                )

            # Append to target file
            result = subprocess.run(
                ["docker", "exec", container, "sh", "-c", f"cat {temp_file} >> {file_path}"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return ConnectionResult(
                    success=False,
                    message=f"Failed to append to {file_path}: {result.stderr}"
                )

            # Cleanup temp file
            subprocess.run(
                ["docker", "exec", container, "rm", "-f", temp_file],
                capture_output=True,
                timeout=10
            )

            return ConnectionResult(
                success=True,
                message=f"Injected {len(content.splitlines())} logs to {file_path}"
            )

        except subprocess.TimeoutExpired:
            return ConnectionResult(success=False, message="Injection timed out")
        except Exception as e:
            return ConnectionResult(success=False, message=str(e))

    def _native_inject(self, content: str, file_path: str) -> ConnectionResult:
        """Inject to native installation."""
        try:
            with open(file_path, "a") as f:
                f.write(content)

            return ConnectionResult(
                success=True,
                message=f"Injected {len(content.splitlines())} logs to {file_path}"
            )
        except PermissionError:
            return ConnectionResult(
                success=False,
                message=f"Permission denied writing to {file_path}"
            )
        except Exception as e:
            return ConnectionResult(success=False, message=str(e))

    def _ssh_inject(self, content: str, file_path: str) -> ConnectionResult:
        """Inject via SSH."""
        try:
            # Use SSH to append content
            ssh_cmd = self._build_ssh_command([
                "sh", "-c", f"cat >> {file_path}"
            ])

            process = subprocess.Popen(
                ssh_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=content, timeout=60)

            if process.returncode == 0:
                return ConnectionResult(
                    success=True,
                    message=f"Injected {len(content.splitlines())} logs via SSH"
                )
            else:
                return ConnectionResult(
                    success=False,
                    message=f"SSH injection failed: {stderr}"
                )

        except subprocess.TimeoutExpired:
            return ConnectionResult(success=False, message="SSH injection timed out")
        except Exception as e:
            return ConnectionResult(success=False, message=str(e))

    def _inject_via_api(self, logs: List[Dict[str, Any]]) -> ConnectionResult:
        """Inject via Wazuh API."""
        # Note: Direct log injection via API is limited
        # This is a placeholder for future API-based injection
        return ConnectionResult(
            success=False,
            message="API injection not yet implemented. Use 'alerts' method instead."
        )

    def _build_ssh_command(self, remote_cmd: List[str]) -> List[str]:
        """Build SSH command with proper options."""
        ssh_cmd = [
            "ssh",
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
        ]

        if self.config.ssh_key:
            ssh_cmd.extend(["-i", self.config.ssh_key])

        if self.config.ssh_port != 22:
            ssh_cmd.extend(["-p", str(self.config.ssh_port)])

        ssh_cmd.append(f"{self.config.ssh_user}@{self.config.ssh_host}")
        ssh_cmd.extend(remote_cmd)

        return ssh_cmd

    @property
    def is_connected(self) -> bool:
        """Check if connector is connected."""
        return self._connected
