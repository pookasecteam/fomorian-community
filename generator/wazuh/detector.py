"""
Wazuh Auto-Detection

Automatically detects Wazuh installations in various deployment scenarios.
"""

import os
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional


class InstallationType(str, Enum):
    """Types of Wazuh installations."""
    DOCKER = "docker"
    NATIVE = "native"
    AGENT_ONLY = "agent_only"
    REMOTE = "remote"
    NONE = "none"


@dataclass
class WazuhInstallation:
    """Represents a detected Wazuh installation."""
    install_type: InstallationType
    location: str
    version: Optional[str] = None
    container_name: Optional[str] = None
    alerts_path: Optional[str] = None
    archives_path: Optional[str] = None
    api_url: Optional[str] = None
    ssh_host: Optional[str] = None
    ssh_user: Optional[str] = None
    ssh_port: int = 22
    recommended_method: str = "alerts"

    @property
    def is_manager(self) -> bool:
        """Check if this is a Wazuh Manager (not agent-only)."""
        return self.install_type in (
            InstallationType.DOCKER,
            InstallationType.NATIVE,
            InstallationType.REMOTE
        )


class WazuhDetector:
    """
    Auto-detects Wazuh installations.

    Detection order:
    1. Docker containers
    2. Native Linux installation
    3. Agent-only installation
    4. Environment variables (remote)
    5. SSH config for remote Wazuh
    """

    # Common Docker container names for Wazuh Manager
    DOCKER_CONTAINERS = [
        "wazuh-manager",
        "wazuh.manager",
        "wazuh-manager",
        "wazuh_manager",
        "wazuh",
    ]

    # Native installation paths
    NATIVE_PATHS = [
        "/var/ossec",
        "/opt/wazuh",
    ]

    # Agent-only paths
    AGENT_PATHS = [
        "/var/ossec",
    ]

    def __init__(self):
        """Initialize the detector."""
        self._docker_available: Optional[bool] = None

    def detect(self) -> Optional[WazuhInstallation]:
        """
        Detect Wazuh installation.

        Returns:
            WazuhInstallation if found, None otherwise.
        """
        # Try each detection method in order
        detectors = [
            self._detect_docker,
            self._detect_native,
            self._detect_agent_only,
            self._detect_from_environment,
        ]

        for detector in detectors:
            result = detector()
            if result:
                return result

        return None

    def detect_all(self) -> List[WazuhInstallation]:
        """
        Detect all Wazuh installations.

        Returns:
            List of all detected installations.
        """
        installations = []

        # Docker containers
        docker_results = self._detect_all_docker_containers()
        installations.extend(docker_results)

        # Native
        native = self._detect_native()
        if native:
            installations.append(native)

        # Environment
        env_result = self._detect_from_environment()
        if env_result:
            installations.append(env_result)

        return installations

    def _is_docker_available(self) -> bool:
        """Check if Docker is available."""
        if self._docker_available is not None:
            return self._docker_available

        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5
            )
            self._docker_available = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self._docker_available = False

        return self._docker_available

    def _detect_docker(self) -> Optional[WazuhInstallation]:
        """Detect Wazuh running in Docker."""
        if not self._is_docker_available():
            return None

        try:
            # Get running container names
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return None

            running = result.stdout.strip().split("\n")

            # Check for known Wazuh containers
            for container in self.DOCKER_CONTAINERS:
                if container in running:
                    # Verify it's actually Wazuh
                    version = self._get_docker_version(container)
                    if version:
                        return WazuhInstallation(
                            install_type=InstallationType.DOCKER,
                            location=f"docker://{container}",
                            version=version,
                            container_name=container,
                            alerts_path="/var/ossec/logs/alerts/alerts.json",
                            archives_path="/var/ossec/logs/archives/archives.json",
                            api_url=f"https://localhost:55000",
                            recommended_method="alerts",
                        )

            return None

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _detect_all_docker_containers(self) -> List[WazuhInstallation]:
        """Detect all Wazuh Docker containers."""
        if not self._is_docker_available():
            return []

        installations = []

        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return []

            running = result.stdout.strip().split("\n")

            for container in running:
                # Check if it's a Wazuh container
                if any(wazuh in container.lower() for wazuh in ["wazuh", "ossec"]):
                    version = self._get_docker_version(container)
                    if version:
                        installations.append(WazuhInstallation(
                            install_type=InstallationType.DOCKER,
                            location=f"docker://{container}",
                            version=version,
                            container_name=container,
                            alerts_path="/var/ossec/logs/alerts/alerts.json",
                            archives_path="/var/ossec/logs/archives/archives.json",
                            api_url=f"https://localhost:55000",
                            recommended_method="alerts",
                        ))

            return installations

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _get_docker_version(self, container: str) -> Optional[str]:
        """Get Wazuh version from Docker container."""
        try:
            result = subprocess.run(
                ["docker", "exec", container, "/var/ossec/bin/wazuh-control", "info", "-v"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return result.stdout.strip()
            return "unknown"

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _detect_native(self) -> Optional[WazuhInstallation]:
        """Detect native Wazuh installation."""
        for path in self.NATIVE_PATHS:
            ossec_path = Path(path)
            control_path = ossec_path / "bin" / "wazuh-control"

            if control_path.exists():
                # This is a manager installation
                version = self._get_native_version(ossec_path)
                return WazuhInstallation(
                    install_type=InstallationType.NATIVE,
                    location=str(ossec_path),
                    version=version,
                    alerts_path=str(ossec_path / "logs" / "alerts" / "alerts.json"),
                    archives_path=str(ossec_path / "logs" / "archives" / "archives.json"),
                    api_url="https://localhost:55000",
                    recommended_method="alerts",
                )

        return None

    def _detect_agent_only(self) -> Optional[WazuhInstallation]:
        """Detect Wazuh agent-only installation."""
        for path in self.AGENT_PATHS:
            ossec_path = Path(path)
            agent_control = ossec_path / "bin" / "wazuh-agentd"

            if agent_control.exists():
                # Check it's not a manager
                manager_control = ossec_path / "bin" / "wazuh-control"
                if not manager_control.exists():
                    return WazuhInstallation(
                        install_type=InstallationType.AGENT_ONLY,
                        location=str(ossec_path),
                        version=self._get_native_version(ossec_path),
                        recommended_method="none",
                    )

        return None

    def _get_native_version(self, path: Path) -> Optional[str]:
        """Get Wazuh version from native installation."""
        try:
            control = path / "bin" / "wazuh-control"
            result = subprocess.run(
                [str(control), "info", "-v"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return result.stdout.strip()
            return "unknown"

        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return None

    def _detect_from_environment(self) -> Optional[WazuhInstallation]:
        """Detect Wazuh from environment variables."""
        # Check for common environment variables
        host = os.environ.get("WAZUH_HOST") or os.environ.get("PURPLE_TEAM_HOST")

        if not host:
            return None

        port = int(os.environ.get("WAZUH_PORT", "55000"))

        return WazuhInstallation(
            install_type=InstallationType.REMOTE,
            location=f"remote://{host}:{port}",
            api_url=f"https://{host}:{port}",
            recommended_method="api",
        )

    def detect_ssh_config(self, host_alias: str = "your-wazuh-host") -> Optional[WazuhInstallation]:
        """
        Detect Wazuh via SSH config.

        Args:
            host_alias: SSH config host alias to check

        Returns:
            WazuhInstallation if found via SSH
        """
        ssh_config = Path.home() / ".ssh" / "config"

        if not ssh_config.exists():
            return None

        # Parse SSH config for the alias
        try:
            content = ssh_config.read_text()
            # Simple parsing - look for Host entry
            if f"Host {host_alias}" in content or f"Host {host_alias}\n" in content:
                return WazuhInstallation(
                    install_type=InstallationType.REMOTE,
                    location=f"ssh://{host_alias}",
                    ssh_host=host_alias,
                    ssh_user="root",
                    recommended_method="alerts",
                    alerts_path="/var/ossec/logs/alerts/alerts.json",
                )
        except Exception:
            pass

        return None
