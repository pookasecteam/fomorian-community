"""
Step 1: Welcome

Introduction to the wizard and detection of existing configuration.
"""

from pathlib import Path
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel

from .base import WizardStep
from ..state import WizardState, StepResult


class WelcomeStep(WizardStep):
    """Welcome step - introduces the wizard and checks for existing config."""

    name = "Welcome"
    description = "Introduction and existing configuration detection"
    required = True
    can_skip = False

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the welcome step."""

        # Show welcome message
        console.print(Panel.fit(
            "[bold]Welcome to the Fomorian Setup Wizard![/bold]\n\n"
            "This wizard will help you configure:\n"
            "  • Wazuh Manager connection\n"
            "  • Target environment (hosts, users, network)\n"
            "  • Attack scenario parameters\n"
            "  • C2 infrastructure simulation\n\n"
            "[dim]All settings can be modified later by editing YAML files.[/dim]",
            title="⚔ Fomorian",
            border_style="blue"
        ))

        # Check for existing configuration
        existing_config = self._detect_existing_config(console)
        if existing_config:
            console.print()
            console.print("[yellow]Existing configuration detected![/yellow]")
            console.print()

            for config_type, path in existing_config.items():
                console.print(f"  [cyan]{config_type}[/cyan]: {path}")

            console.print()

            if self.prompt_confirm(
                console,
                "Would you like to use the existing configuration as a starting point?",
                default=True
            ):
                # Load existing config
                loaded = self._load_existing_config(existing_config, state, console)
                if loaded:
                    console.print("[green]Configuration loaded successfully![/green]")
                    return self.success(data={"loaded_config": True, "paths": existing_config})

        # No existing config or user chose not to use it
        console.print()
        console.print("[dim]Starting with fresh configuration...[/dim]")

        return self.success(data={"loaded_config": False})

    def validate(self, state: WizardState) -> List[str]:
        """Validate welcome step - always valid."""
        return []

    def _detect_existing_config(self, console: Console) -> Dict[str, str]:
        """
        Detect existing configuration files.

        Checks common locations:
        - ./config/
        - ~/.fomorian/config/
        - Environment variable FOMORIAN_CONFIG_DIR
        """
        import os

        existing = {}

        # Check locations in order of priority
        locations = [
            Path("./config"),
            Path.home() / ".fomorian" / "config",
        ]

        env_config = os.environ.get("FOMORIAN_CONFIG_DIR")
        if env_config:
            locations.insert(0, Path(env_config))

        config_files = {
            "environment": ["environment.yaml", "environment.yml"],
            "attack_path": ["attack_path.yaml", "attack_path.yml"],
            "engagement": ["engagement.yaml", "engagement.yml"],
            "timing": ["timing.yaml", "timing.yml"],
        }

        for location in locations:
            if not location.exists():
                continue

            for config_type, filenames in config_files.items():
                if config_type in existing:
                    continue

                for filename in filenames:
                    filepath = location / filename
                    if filepath.exists():
                        existing[config_type] = str(filepath)
                        break

        return existing

    def _load_existing_config(
        self,
        config_paths: Dict[str, str],
        state: WizardState,
        console: Console
    ) -> bool:
        """
        Load existing configuration files into wizard state.

        Args:
            config_paths: Dictionary of config type to file path
            state: Wizard state to update
            console: Console for output

        Returns:
            True if loaded successfully
        """
        import yaml

        try:
            for config_type, path in config_paths.items():
                with open(path, "r") as f:
                    data = yaml.safe_load(f)

                if config_type == "environment":
                    # Extract environment data
                    state.update_config("environment", {
                        "name": data.get("name", ""),
                        "domain": data.get("domain", ""),
                        "network": data.get("network", {}),
                    })

                    # Extract hosts
                    if "hosts" in data:
                        state.update_config("hosts", data["hosts"])

                    # Extract users
                    if "users" in data:
                        state.update_config("users", data["users"])

                    # Extract C2
                    if "c2" in data:
                        state.update_config("c2", data["c2"])

                elif config_type == "attack_path":
                    state.update_config("attack_path", data)

                elif config_type == "engagement":
                    state.update_config("engagement", data)

                elif config_type == "timing":
                    state.update_config("params", data)

            return True

        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            return False

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        return {}
