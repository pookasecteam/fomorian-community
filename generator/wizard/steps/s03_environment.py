"""
Step 3: Environment

Configure environment name, domain, and network settings.
"""

from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel

from .base import WizardStep
from ..state import WizardState, StepResult


class EnvironmentStep(WizardStep):
    """Environment step - configure basic environment settings."""

    name = "Environment"
    description = "Define your environment name, domain, and network"
    required = True
    can_skip = False

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the environment step."""

        # Show current values if resuming
        existing = state.get_config("environment")
        if existing:
            console.print("[dim]Current values (press Enter to keep):[/dim]")
            console.print(f"  Name: [cyan]{existing.get('name', 'N/A')}[/cyan]")
            console.print(f"  Domain: [cyan]{existing.get('domain', 'N/A')}[/cyan]")
            console.print()

        console.print(Panel.fit(
            "The environment defines your simulated network.\n"
            "This information will be used to make attack logs realistic.",
            title="Environment Setup",
            border_style="blue"
        ))
        console.print()

        # Environment name
        env_name = self.prompt_text(
            console,
            "Environment name (e.g., 'production', 'lab')",
            default=existing.get("name", "purple-team-lab")
        )

        # Domain
        domain = self.prompt_domain(
            console,
            "Active Directory domain (e.g., 'corp.local')",
            default=existing.get("domain", "corp.local")
        )

        # Network configuration
        console.print()
        console.print("[bold]Network Configuration[/bold]")
        console.print()

        existing_network = existing.get("network", {})

        internal_cidr = self.prompt_cidr(
            console,
            "Internal network CIDR",
            default=existing_network.get("internal", "10.0.0.0/24")
        )

        # Optional: DMZ
        dmz_cidr = None
        if self.prompt_confirm(console, "Do you have a DMZ network?", default=False):
            dmz_cidr = self.prompt_cidr(
                console,
                "DMZ network CIDR",
                default=existing_network.get("dmz", "10.1.0.0/24")
            )

        # Optional: Management
        mgmt_cidr = None
        if self.prompt_confirm(console, "Do you have a management network?", default=False):
            mgmt_cidr = self.prompt_cidr(
                console,
                "Management network CIDR",
                default=existing_network.get("management", "10.255.0.0/24")
            )

        # Build network config
        network = {"internal": internal_cidr}
        if dmz_cidr:
            network["dmz"] = dmz_cidr
        if mgmt_cidr:
            network["management"] = mgmt_cidr

        # Summary
        console.print()
        console.print("[bold]Environment Summary:[/bold]")
        console.print(f"  Name: [green]{env_name}[/green]")
        console.print(f"  Domain: [green]{domain}[/green]")
        console.print(f"  Internal: [green]{internal_cidr}[/green]")
        if dmz_cidr:
            console.print(f"  DMZ: [green]{dmz_cidr}[/green]")
        if mgmt_cidr:
            console.print(f"  Management: [green]{mgmt_cidr}[/green]")

        return self.success(data={
            "name": env_name,
            "domain": domain,
            "network": network,
        })

    def validate(self, state: WizardState) -> List[str]:
        """Validate environment configuration."""
        errors = []
        env = state.get_config("environment")

        if not env:
            errors.append("Environment configuration is missing")
            return errors

        if not env.get("name"):
            errors.append("Environment name is required")

        if not env.get("domain"):
            errors.append("Domain is required")

        network = env.get("network", {})
        if not network.get("internal"):
            errors.append("Internal network CIDR is required")

        return errors

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        return {
            "name": "purple-team-lab",
            "domain": "corp.local",
            "network": {
                "internal": "10.0.0.0/24"
            }
        }
