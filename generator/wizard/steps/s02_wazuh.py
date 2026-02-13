"""
Step 2: Wazuh Connection

Configure connection to Wazuh Manager.
"""

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .base import WizardStep
from ..state import WizardState, StepResult


class WazuhStep(WizardStep):
    """Wazuh connection step - configure Wazuh Manager connection."""

    name = "Wazuh Connection"
    description = "Configure how to connect to your Wazuh Manager"
    required = True
    can_skip = False

    # Common Docker container names
    DOCKER_CONTAINERS = [
        "wazuh-manager",
        "wazuh.manager",
        "wazuh-manager",
        "wazuh_manager",
    ]

    # Native installation paths
    NATIVE_PATHS = [
        "/var/ossec",
        "/opt/wazuh",
    ]

    # Injection methods
    INJECTION_METHODS = [
        ("alerts", "Direct write to alerts.json (recommended)"),
        ("archives", "Direct write to archives.json"),
        ("api", "Via Wazuh Manager API"),
        ("file", "Write to monitored log file"),
    ]

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the Wazuh connection step."""

        # Show current values if resuming
        self.show_current_values(state, console)

        # Auto-detect Wazuh installation
        console.print("[bold]Detecting Wazuh installation...[/bold]")
        console.print()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            detected = self._detect_wazuh(progress, task)

        if detected:
            console.print()
            console.print(Panel.fit(
                f"[green]✓ Wazuh installation found![/green]\n\n"
                f"Type: [cyan]{detected['type']}[/cyan]\n"
                f"Location: [cyan]{detected['location']}[/cyan]\n"
                f"Method: [cyan]{detected['method']}[/cyan] (recommended)",
                title="Detection Result",
                border_style="green"
            ))

            if self.prompt_confirm(
                console,
                "\nUse detected settings?",
                default=True
            ):
                # Test the connection
                if self._test_connection(detected, console):
                    return self.success(data=detected)
                else:
                    console.print("[yellow]Connection test failed. Let's configure manually.[/yellow]")

        # Manual configuration
        console.print()
        console.print("[bold]Manual Wazuh Configuration[/bold]")
        console.print()

        # Get installation type
        install_type = self.prompt_choice(
            console,
            "Select your Wazuh installation type",
            ["Docker", "Native Linux", "Remote SSH", "None (generate only)"],
            default="Docker"
        )

        wazuh_config: Dict[str, Any] = {
            "type": install_type.lower().replace(" ", "_"),
        }

        if install_type == "Docker":
            wazuh_config.update(self._configure_docker(console))
        elif install_type == "Native Linux":
            wazuh_config.update(self._configure_native(console))
        elif install_type == "Remote SSH":
            wazuh_config.update(self._configure_ssh(console))
        else:
            wazuh_config["method"] = "none"
            console.print("[yellow]Skipping Wazuh connection. Scenarios will be generated but not injected.[/yellow]")
            return self.success(data=wazuh_config)

        # Select injection method
        console.print()
        console.print("[bold]Select log injection method:[/bold]")
        for method, desc in self.INJECTION_METHODS:
            console.print(f"  [cyan]{method}[/cyan]: {desc}")
        console.print()

        method = self.prompt_choice(
            console,
            "Injection method",
            [m[0] for m in self.INJECTION_METHODS],
            default="alerts"
        )
        wazuh_config["method"] = method

        # Test connection
        if self._test_connection(wazuh_config, console):
            return self.success(data=wazuh_config)
        else:
            if self.prompt_confirm(
                console,
                "Connection test failed. Continue anyway?",
                default=False
            ):
                wazuh_config["verified"] = False
                return self.success(data=wazuh_config)
            else:
                return self.failure("Wazuh connection not configured")

    def validate(self, state: WizardState) -> List[str]:
        """Validate Wazuh configuration."""
        errors = []
        wazuh = state.get_config("wazuh")

        if not wazuh:
            errors.append("Wazuh configuration is missing")
            return errors

        if wazuh.get("method") == "none":
            return []  # OK to not have Wazuh

        if wazuh.get("type") == "docker" and not wazuh.get("container"):
            errors.append("Docker container name is required")

        if wazuh.get("type") == "remote_ssh" and not wazuh.get("host"):
            errors.append("SSH host is required for remote connection")

        return errors

    def _detect_wazuh(self, progress, task) -> Optional[Dict[str, Any]]:
        """
        Auto-detect Wazuh installation.

        Checks in order:
        1. Docker containers
        2. Native installation
        3. Environment variables
        """
        # Check Docker
        progress.update(task, description="Checking Docker containers...")
        docker_result = self._detect_docker()
        if docker_result:
            return docker_result

        # Check native
        progress.update(task, description="Checking native installation...")
        native_result = self._detect_native()
        if native_result:
            return native_result

        # Check environment variables
        progress.update(task, description="Checking environment variables...")
        env_result = self._detect_from_env()
        if env_result:
            return env_result

        return None

    def _detect_docker(self) -> Optional[Dict[str, Any]]:
        """Detect Wazuh running in Docker."""
        try:
            # List running containers
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return None

            running_containers = result.stdout.strip().split("\n")

            for container in self.DOCKER_CONTAINERS:
                if container in running_containers:
                    return {
                        "type": "docker",
                        "container": container,
                        "location": f"docker://{container}",
                        "method": "alerts",
                        "alerts_path": "/var/ossec/logs/alerts/alerts.json",
                    }

            return None

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def _detect_native(self) -> Optional[Dict[str, Any]]:
        """Detect native Wazuh installation."""
        for path in self.NATIVE_PATHS:
            ossec_path = Path(path)
            if ossec_path.exists() and (ossec_path / "bin" / "wazuh-control").exists():
                return {
                    "type": "native",
                    "location": str(ossec_path),
                    "method": "alerts",
                    "alerts_path": str(ossec_path / "logs" / "alerts" / "alerts.json"),
                }
        return None

    def _detect_from_env(self) -> Optional[Dict[str, Any]]:
        """Detect from environment variables."""
        # Check for PURPLE_TEAM_HOST or similar
        host = os.environ.get("PURPLE_TEAM_HOST") or os.environ.get("WAZUH_HOST")
        if host:
            return {
                "type": "remote",
                "host": host,
                "location": f"remote://{host}",
                "method": "api",
                "port": int(os.environ.get("WAZUH_PORT", "55000")),
            }
        return None

    def _configure_docker(self, console: Console) -> Dict[str, Any]:
        """Configure Docker connection."""
        container = self.prompt_text(
            console,
            "Docker container name",
            default="wazuh-manager"
        )

        return {
            "container": container,
            "location": f"docker://{container}",
            "alerts_path": "/var/ossec/logs/alerts/alerts.json",
        }

    def _configure_native(self, console: Console) -> Dict[str, Any]:
        """Configure native installation."""
        path = self.prompt_text(
            console,
            "Wazuh installation path",
            default="/var/ossec"
        )

        return {
            "location": path,
            "alerts_path": f"{path}/logs/alerts/alerts.json",
        }

    def _configure_ssh(self, console: Console) -> Dict[str, Any]:
        """Configure SSH remote connection."""
        host = self.prompt_text(console, "SSH host", required=True)
        user = self.prompt_text(console, "SSH user", default="root")
        port = self.prompt_int(console, "SSH port", default=22, min_val=1, max_val=65535)

        # Check for key file
        key_file = self.prompt_text(
            console,
            "SSH key file (leave empty for default)",
            required=False
        )

        return {
            "host": host,
            "ssh_user": user,
            "ssh_port": port,
            "ssh_key": key_file or None,
            "location": f"ssh://{user}@{host}:{port}",
            "alerts_path": "/var/ossec/logs/alerts/alerts.json",
        }

    def _test_connection(self, config: Dict[str, Any], console: Console) -> bool:
        """Test the Wazuh connection."""
        console.print()
        console.print("[bold]Testing connection...[/bold]")

        try:
            if config.get("type") == "docker":
                return self._test_docker(config, console)
            elif config.get("type") == "native":
                return self._test_native(config, console)
            elif config.get("type") == "remote_ssh":
                return self._test_ssh(config, console)
            elif config.get("type") == "remote":
                return self._test_api(config, console)
            else:
                return True  # No test needed
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return False

    def _test_docker(self, config: Dict[str, Any], console: Console) -> bool:
        """Test Docker connection."""
        container = config.get("container")

        try:
            # Test container is running
            result = subprocess.run(
                ["docker", "exec", container, "ls", "/var/ossec/bin/wazuh-control"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                console.print("[green]✓ Container accessible[/green]")
            else:
                console.print("[red]✗ Container not accessible[/red]")
                return False

            # Test alerts.json writability
            alerts_path = config.get("alerts_path", "/var/ossec/logs/alerts/alerts.json")
            result = subprocess.run(
                ["docker", "exec", container, "test", "-w", alerts_path],
                capture_output=True,
                timeout=10
            )

            if result.returncode == 0:
                console.print("[green]✓ alerts.json writable[/green]")
                config["verified"] = True
                return True
            else:
                console.print("[yellow]⚠ alerts.json not writable (may need root)[/yellow]")
                return True  # Still usable

        except subprocess.TimeoutExpired:
            console.print("[red]✗ Connection timed out[/red]")
            return False
        except FileNotFoundError:
            console.print("[red]✗ Docker not found[/red]")
            return False

    def _test_native(self, config: Dict[str, Any], console: Console) -> bool:
        """Test native installation."""
        alerts_path = Path(config.get("alerts_path", "/var/ossec/logs/alerts/alerts.json"))

        if alerts_path.exists():
            console.print("[green]✓ alerts.json exists[/green]")

            if os.access(alerts_path, os.W_OK):
                console.print("[green]✓ alerts.json writable[/green]")
                config["verified"] = True
                return True
            else:
                console.print("[yellow]⚠ alerts.json not writable (may need sudo)[/yellow]")
                return True
        else:
            console.print("[red]✗ alerts.json not found[/red]")
            return False

    def _test_ssh(self, config: Dict[str, Any], console: Console) -> bool:
        """Test SSH connection."""
        host = config.get("host")
        user = config.get("ssh_user", "root")
        port = config.get("ssh_port", 22)
        key = config.get("ssh_key")

        ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no"]
        if key:
            ssh_cmd.extend(["-i", key])
        ssh_cmd.extend(["-p", str(port), f"{user}@{host}", "echo", "ok"])

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                console.print("[green]✓ SSH connection successful[/green]")
                config["verified"] = True
                return True
            else:
                console.print(f"[red]✗ SSH failed: {result.stderr}[/red]")
                return False

        except subprocess.TimeoutExpired:
            console.print("[red]✗ SSH connection timed out[/red]")
            return False

    def _test_api(self, config: Dict[str, Any], console: Console) -> bool:
        """Test API connection."""
        # API testing would require credentials
        console.print("[yellow]⚠ API connection requires credentials (will verify during injection)[/yellow]")
        return True

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        return {
            "type": "docker",
            "container": "wazuh-manager",
            "method": "alerts",
        }
