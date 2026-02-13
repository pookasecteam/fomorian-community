"""
Wazuh Connectivity Validation

Validates Wazuh connection settings and accessibility.
"""

import subprocess
from pathlib import Path
from typing import Any, Dict, List

from ..models import CheckResult, CheckSeverity


def validate_wazuh(wazuh_config: Dict[str, Any]) -> List[CheckResult]:
    """
    Validate Wazuh connection configuration.

    Args:
        wazuh_config: Wazuh configuration dictionary

    Returns:
        List of check results
    """
    results = []

    # Check if Wazuh is configured
    if not wazuh_config or wazuh_config.get("method") == "none":
        results.append(CheckResult(
            name="Wazuh Configuration",
            passed=True,
            severity=CheckSeverity.INFO,
            message="Wazuh not configured (generate-only mode)"
        ))
        return results

    # Check configuration completeness
    results.append(_check_wazuh_config(wazuh_config))

    # Check connectivity
    conn_type = wazuh_config.get("type")
    if conn_type == "docker":
        results.append(_check_docker_connectivity(wazuh_config))
    elif conn_type == "native":
        results.append(_check_native_connectivity(wazuh_config))
    elif conn_type == "remote_ssh":
        results.append(_check_ssh_connectivity(wazuh_config))

    # Check write permission
    results.append(_check_write_permission(wazuh_config))

    return results


def _check_wazuh_config(config: Dict[str, Any]) -> CheckResult:
    """Check Wazuh configuration completeness."""
    conn_type = config.get("type")

    if not conn_type:
        return CheckResult(
            name="Wazuh Config",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="Wazuh connection type not specified",
            details=["Set 'type' to: docker, native, remote_ssh, or api"]
        )

    if conn_type == "docker" and not config.get("container"):
        return CheckResult(
            name="Wazuh Config",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="Docker container name not specified"
        )

    if conn_type == "remote_ssh" and not config.get("host"):
        return CheckResult(
            name="Wazuh Config",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="SSH host not specified"
        )

    return CheckResult(
        name="Wazuh Config",
        passed=True,
        severity=CheckSeverity.INFO,
        message=f"Configuration type: {conn_type}"
    )


def _check_docker_connectivity(config: Dict[str, Any]) -> CheckResult:
    """Check Docker container connectivity."""
    container = config.get("container", "")

    try:
        # Check container is running
        result = subprocess.run(
            ["docker", "ps", "-q", "-f", f"name={container}"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if not result.stdout.strip():
            return CheckResult(
                name="Wazuh Connectivity",
                passed=False,
                severity=CheckSeverity.ERROR,
                message=f"Container '{container}' is not running",
                details=["Start the container with: docker start " + container]
            )

        # Check Wazuh is accessible
        result = subprocess.run(
            ["docker", "exec", container, "test", "-f", "/var/ossec/bin/wazuh-control"],
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            return CheckResult(
                name="Wazuh Connectivity",
                passed=False,
                severity=CheckSeverity.ERROR,
                message="Wazuh not found in container"
            )

        return CheckResult(
            name="Wazuh Connectivity",
            passed=True,
            severity=CheckSeverity.INFO,
            message=f"Docker container '{container}' accessible"
        )

    except subprocess.TimeoutExpired:
        return CheckResult(
            name="Wazuh Connectivity",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="Connection timed out"
        )
    except FileNotFoundError:
        return CheckResult(
            name="Wazuh Connectivity",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="Docker not found",
            details=["Install Docker or choose a different connection type"]
        )


def _check_native_connectivity(config: Dict[str, Any]) -> CheckResult:
    """Check native Wazuh installation."""
    location = config.get("location", "/var/ossec")
    path = Path(location)

    if not path.exists():
        return CheckResult(
            name="Wazuh Connectivity",
            passed=False,
            severity=CheckSeverity.ERROR,
            message=f"Wazuh installation not found at {location}"
        )

    control = path / "bin" / "wazuh-control"
    if not control.exists():
        return CheckResult(
            name="Wazuh Connectivity",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="wazuh-control not found"
        )

    return CheckResult(
        name="Wazuh Connectivity",
        passed=True,
        severity=CheckSeverity.INFO,
        message=f"Native installation at {location}"
    )


def _check_ssh_connectivity(config: Dict[str, Any]) -> CheckResult:
    """Check SSH connectivity."""
    host = config.get("host", "")
    user = config.get("ssh_user", "root")
    port = config.get("ssh_port", 22)

    try:
        ssh_cmd = [
            "ssh",
            "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-p", str(port),
            f"{user}@{host}",
            "echo", "ok"
        ]

        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            return CheckResult(
                name="Wazuh Connectivity",
                passed=True,
                severity=CheckSeverity.INFO,
                message=f"SSH connection to {host} successful"
            )

        return CheckResult(
            name="Wazuh Connectivity",
            passed=False,
            severity=CheckSeverity.ERROR,
            message=f"SSH connection failed: {result.stderr.strip()}"
        )

    except subprocess.TimeoutExpired:
        return CheckResult(
            name="Wazuh Connectivity",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="SSH connection timed out"
        )
    except FileNotFoundError:
        return CheckResult(
            name="Wazuh Connectivity",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="SSH client not found"
        )


def _check_write_permission(config: Dict[str, Any]) -> CheckResult:
    """Check write permission for alerts.json."""
    method = config.get("method", "alerts")
    if method not in ("alerts", "archives"):
        return CheckResult(
            name="Write Permission",
            passed=True,
            severity=CheckSeverity.INFO,
            message=f"Using {method} method (no file write needed)"
        )

    conn_type = config.get("type")
    alerts_path = config.get("alerts_path", "/var/ossec/logs/alerts/alerts.json")

    if conn_type == "docker":
        container = config.get("container", "")
        try:
            result = subprocess.run(
                ["docker", "exec", container, "test", "-w", alerts_path],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                return CheckResult(
                    name="Write Permission",
                    passed=True,
                    severity=CheckSeverity.INFO,
                    message=f"Can write to {alerts_path}"
                )

            return CheckResult(
                name="Write Permission",
                passed=False,
                severity=CheckSeverity.WARNING,
                message=f"No write permission to {alerts_path}",
                details=["May need to run as root in the container"]
            )

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return CheckResult(
                name="Write Permission",
                passed=True,
                severity=CheckSeverity.INFO,
                message="Could not verify write permission"
            )

    elif conn_type == "native":
        import os
        path = Path(alerts_path)

        if path.exists():
            if os.access(path, os.W_OK):
                return CheckResult(
                    name="Write Permission",
                    passed=True,
                    severity=CheckSeverity.INFO,
                    message=f"Write access to {alerts_path}"
                )
            return CheckResult(
                name="Write Permission",
                passed=False,
                severity=CheckSeverity.WARNING,
                message="No write permission",
                details=["Run with sudo or as root"]
            )

        # Check parent directory
        if path.parent.exists() and os.access(path.parent, os.W_OK):
            return CheckResult(
                name="Write Permission",
                passed=True,
                severity=CheckSeverity.INFO,
                message="Can create alerts.json"
            )

        return CheckResult(
            name="Write Permission",
            passed=False,
            severity=CheckSeverity.WARNING,
            message="Cannot write to alerts directory"
        )

    return CheckResult(
        name="Write Permission",
        passed=True,
        severity=CheckSeverity.INFO,
        message="Write permission check not applicable"
    )
