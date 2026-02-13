"""
Step 10: Pre-flight Check

Validate all configuration before running the scenario.
"""

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .base import WizardStep
from ..state import WizardState, StepResult


class PreflightStep(WizardStep):
    """Pre-flight step - validate all configuration before generation."""

    name = "Pre-flight Check"
    description = "Validate configuration and test connectivity"
    required = True
    can_skip = False

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the pre-flight check step."""

        console.print(Panel.fit(
            "Running pre-flight checks to validate your configuration.\n"
            "This ensures everything is ready for scenario generation.",
            title="Pre-flight Validation",
            border_style="blue"
        ))
        console.print()

        # Run all checks
        results: List[Tuple[str, str, str, List[str]]] = []  # (name, status, severity, messages)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running checks...", total=None)

            # Configuration checks
            progress.update(task, description="Validating configuration...")
            results.append(self._check_config(state))

            # Host references
            progress.update(task, description="Checking host references...")
            results.append(self._check_host_references(state))

            # Wazuh connectivity
            progress.update(task, description="Testing Wazuh connection...")
            results.append(self._check_wazuh_connection(state))

            # Write permission
            progress.update(task, description="Checking write permissions...")
            results.append(self._check_write_permission(state))

            # Template availability
            progress.update(task, description="Checking templates...")
            results.append(self._check_templates(state))

            # Disk space
            progress.update(task, description="Checking disk space...")
            results.append(self._check_disk_space())

        # Display results
        console.print()
        console.print("[bold]Pre-flight Check Results:[/bold]")
        console.print()

        self._show_results_table(results, console)

        # Count errors and warnings
        errors = [r for r in results if r[1] == "FAIL" and r[2] == "error"]
        warnings = [r for r in results if r[1] == "FAIL" and r[2] == "warning"]

        console.print()

        if errors:
            console.print(f"[red]✗ {len(errors)} error(s) found[/red]")
            for name, _, _, messages in errors:
                for msg in messages:
                    console.print(f"  [red]• {name}: {msg}[/red]")
            console.print()

            if not self.prompt_confirm(
                console,
                "Errors found. Continue anyway?",
                default=False
            ):
                return self.failure(
                    "Pre-flight checks failed",
                    [f"{r[0]}: {m}" for r in errors for m in r[3]]
                )

        if warnings:
            console.print(f"[yellow]⚠ {len(warnings)} warning(s)[/yellow]")
            for name, _, _, messages in warnings:
                for msg in messages:
                    console.print(f"  [yellow]• {name}: {msg}[/yellow]")
            console.print()

        if not errors and not warnings:
            console.print("[green]✓ All checks passed![/green]")

        # Ready to proceed
        console.print()
        console.print(Panel.fit(
            "[bold green]Configuration is ready![/bold green]\n\n"
            "The wizard will now export your configuration files.\n"
            "You can then generate and inject your scenario.",
            border_style="green"
        ))

        return self.success(data={"checks": results, "ready": True})

    def validate(self, state: WizardState) -> List[str]:
        """Validate pre-flight step - always valid."""
        return []

    def _check_config(self, state: WizardState) -> Tuple[str, str, str, List[str]]:
        """Check basic configuration validity."""
        errors = []

        # Check required sections
        if not state.get_config("environment"):
            errors.append("Environment configuration missing")

        if not state.get_config("hosts"):
            errors.append("No hosts configured")

        if not state.get_config("attack_path"):
            errors.append("Attack path not configured")

        if not state.get_config("engagement"):
            errors.append("Engagement type not selected")

        if errors:
            return ("Configuration", "FAIL", "error", errors)
        return ("Configuration", "PASS", "info", ["All required sections present"])

    def _check_host_references(self, state: WizardState) -> Tuple[str, str, str, List[str]]:
        """Check that attack path hosts exist in environment."""
        errors = []

        hosts = state.get_config("hosts") or []
        attack_path = state.get_config("attack_path") or {}

        # Build set of valid host names
        valid_hosts = set()
        for host in hosts:
            valid_hosts.add(host.get("short_name", ""))
            valid_hosts.add(host.get("hostname", ""))

        # Check attack path
        for step in attack_path.get("path", []):
            host = step.get("host", "")
            if host and host not in valid_hosts:
                errors.append(f"Host '{host}' not found in environment")

            pivot = step.get("pivot_from", "")
            if pivot and pivot not in valid_hosts:
                errors.append(f"Pivot host '{pivot}' not found in environment")

        if errors:
            return ("Host References", "FAIL", "error", errors)
        return ("Host References", "PASS", "info", ["All references valid"])

    def _check_wazuh_connection(self, state: WizardState) -> Tuple[str, str, str, List[str]]:
        """Check Wazuh connectivity."""
        wazuh = state.get_config("wazuh") or {}

        if not wazuh or wazuh.get("method") == "none":
            return ("Wazuh Connection", "SKIP", "warning", ["Wazuh not configured (generate-only mode)"])

        if wazuh.get("verified"):
            return ("Wazuh Connection", "PASS", "info", ["Connection verified"])

        # Try to verify now
        wazuh_type = wazuh.get("type")

        try:
            if wazuh_type == "docker":
                container = wazuh.get("container", "")
                result = subprocess.run(
                    ["docker", "exec", container, "test", "-d", "/var/ossec"],
                    capture_output=True,
                    timeout=10
                )
                if result.returncode == 0:
                    return ("Wazuh Connection", "PASS", "info", [f"Docker container '{container}' accessible"])
                else:
                    return ("Wazuh Connection", "FAIL", "error", [f"Cannot access container '{container}'"])

            elif wazuh_type == "native":
                path = Path(wazuh.get("location", "/var/ossec"))
                if path.exists():
                    return ("Wazuh Connection", "PASS", "info", [f"Native installation at {path}"])
                else:
                    return ("Wazuh Connection", "FAIL", "error", [f"Path {path} does not exist"])

            elif wazuh_type == "remote_ssh":
                host = wazuh.get("host", "")
                return ("Wazuh Connection", "WARN", "warning", [f"SSH to {host} not verified (will test during injection)"])

            else:
                return ("Wazuh Connection", "WARN", "warning", ["Connection not verified"])

        except subprocess.TimeoutExpired:
            return ("Wazuh Connection", "FAIL", "error", ["Connection timed out"])
        except Exception as e:
            return ("Wazuh Connection", "FAIL", "error", [str(e)])

    def _check_write_permission(self, state: WizardState) -> Tuple[str, str, str, List[str]]:
        """Check write permissions for alerts.json."""
        wazuh = state.get_config("wazuh") or {}

        if not wazuh or wazuh.get("method") == "none":
            return ("Write Permission", "SKIP", "info", ["Not applicable (generate-only mode)"])

        method = wazuh.get("method", "alerts")
        if method not in ["alerts", "archives"]:
            return ("Write Permission", "SKIP", "info", [f"Using {method} method (different permissions)"])

        wazuh_type = wazuh.get("type")

        try:
            if wazuh_type == "docker":
                container = wazuh.get("container", "")
                alerts_path = wazuh.get("alerts_path", "/var/ossec/logs/alerts/alerts.json")

                result = subprocess.run(
                    ["docker", "exec", container, "test", "-w", alerts_path],
                    capture_output=True,
                    timeout=10
                )

                if result.returncode == 0:
                    return ("Write Permission", "PASS", "info", [f"Can write to {alerts_path}"])
                else:
                    return ("Write Permission", "FAIL", "warning", [f"Cannot write to {alerts_path} (may need root)"])

            elif wazuh_type == "native":
                alerts_path = Path(wazuh.get("alerts_path", "/var/ossec/logs/alerts/alerts.json"))
                if alerts_path.exists():
                    import os
                    if os.access(alerts_path, os.W_OK):
                        return ("Write Permission", "PASS", "info", ["Write access confirmed"])
                    else:
                        return ("Write Permission", "FAIL", "warning", ["No write permission (may need sudo)"])
                else:
                    return ("Write Permission", "FAIL", "warning", ["alerts.json not found"])

            else:
                return ("Write Permission", "SKIP", "info", ["Cannot verify (remote)"])

        except Exception as e:
            return ("Write Permission", "WARN", "warning", [f"Check failed: {e}"])

    def _check_templates(self, state: WizardState) -> Tuple[str, str, str, List[str]]:
        """Check template availability for selected techniques."""
        attack_path = state.get_config("attack_path") or {}
        warnings = []

        # Collect all techniques
        techniques = set()
        for step in attack_path.get("path", []):
            for tech in step.get("techniques", []):
                techniques.add(tech)

        if not techniques:
            return ("Templates", "PASS", "info", ["No techniques specified"])

        # Check template directory
        template_dirs = [
            Path(__file__).parent.parent.parent.parent.parent / "attacks",
            Path.cwd() / "attacks",
        ]

        found_templates = set()
        for template_dir in template_dirs:
            if template_dir.exists():
                # Search for technique IDs in template files
                for json_file in template_dir.rglob("*.json"):
                    for tech in techniques:
                        if tech in str(json_file):
                            found_templates.add(tech)

        missing = techniques - found_templates
        if missing:
            warnings.append(f"Templates not found for: {', '.join(sorted(missing)[:5])}")
            if len(missing) > 5:
                warnings.append(f"...and {len(missing) - 5} more")

        if warnings:
            return ("Templates", "WARN", "warning", warnings)
        return ("Templates", "PASS", "info", [f"Found templates for {len(found_templates)} techniques"])

    def _check_disk_space(self) -> Tuple[str, str, str, List[str]]:
        """Check available disk space."""
        import shutil

        try:
            total, used, free = shutil.disk_usage(".")
            free_mb = free // (1024 * 1024)
            free_gb = free_mb / 1024

            if free_mb < 100:
                return ("Disk Space", "FAIL", "warning", [f"Low disk space: {free_mb}MB available"])
            elif free_mb < 500:
                return ("Disk Space", "WARN", "warning", [f"Limited disk space: {free_mb}MB available"])
            else:
                return ("Disk Space", "PASS", "info", [f"{free_gb:.1f}GB available"])

        except Exception as e:
            return ("Disk Space", "WARN", "warning", [f"Could not check: {e}"])

    def _show_results_table(self, results: List[Tuple[str, str, str, List[str]]], console: Console) -> None:
        """Display check results in a table."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Details")

        for name, status, severity, messages in results:
            if status == "PASS":
                status_str = "[green]✓ PASS[/green]"
            elif status == "FAIL" and severity == "error":
                status_str = "[red]✗ FAIL[/red]"
            elif status == "FAIL" or status == "WARN":
                status_str = "[yellow]⚠ WARN[/yellow]"
            else:
                status_str = "[dim]○ SKIP[/dim]"

            details = messages[0] if messages else ""
            table.add_row(name, status_str, details)

        console.print(table)

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        return {}
