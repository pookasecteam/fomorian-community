"""
Wizard Runner

Orchestrates the wizard flow and manages step execution.
"""

import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .state import WizardState, StepResult, StepStatus
from .navigator import Navigator, NavigationAction
from .steps.base import WizardStep


class WizardRunner:
    """
    Orchestrates the Fomorian setup wizard.

    Manages step execution, navigation, and state persistence.
    """

    BANNER = """
╔═══════════════════════════════════════════════════════════╗
║        ⚔  FOMORIAN SETUP WIZARD  ⚔                        ║
║        Attack Scenario Generator for Wazuh                ║
╚═══════════════════════════════════════════════════════════╝
"""

    def __init__(
        self,
        console: Optional[Console] = None,
        state_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
    ):
        """
        Initialize the wizard runner.

        Args:
            console: Rich console for output
            state_dir: Directory for wizard state files
            output_dir: Directory for generated configuration
        """
        self.console = console or Console()
        self.state = WizardState(state_dir=state_dir)
        self.navigator = Navigator(self.state, self.console)
        self.output_dir = output_dir or Path("./config")

        # Steps will be registered here
        self.steps: List[WizardStep] = []
        self._steps_initialized = False

    def register_steps(self, step_classes: List[Type[WizardStep]]) -> None:
        """
        Register wizard step classes.

        Args:
            step_classes: List of WizardStep subclasses in order
        """
        self.steps = [cls() for cls in step_classes]
        self._steps_initialized = True

    def _initialize_steps(self) -> None:
        """Initialize default steps if not already registered."""
        if self._steps_initialized:
            return

        # Import here to avoid circular imports
        from .steps import (
            WelcomeStep,
            WazuhStep,
            EnvironmentStep,
            HostsStep,
            UsersStep,
            C2Step,
            AttackPathStep,
            EngagementStep,
            ParamsStep,
            PreflightStep,
        )

        self.register_steps([
            WelcomeStep,
            WazuhStep,
            EnvironmentStep,
            HostsStep,
            UsersStep,
            C2Step,
            AttackPathStep,
            EngagementStep,
            ParamsStep,
            PreflightStep,
        ])

    def run(self, mode: str = "full", resume: bool = False) -> bool:
        """
        Run the wizard.

        Args:
            mode: Wizard mode (full, quick, random)
            resume: Whether to try resuming from checkpoint

        Returns:
            True if wizard completed successfully
        """
        self._initialize_steps()

        # Show banner
        self.console.print(self.BANNER, style="bold blue")

        # Handle resume
        start_step = 0
        if resume:
            result = self.navigator.handle_resume()
            if result == -1:  # User chose to quit
                return False
            if result is not None:
                start_step = result
                self.console.print(f"\n[green]Resuming from step {start_step + 1}...[/green]\n")

        # Initialize state for new session
        if start_step == 0:
            step_names = [step.name for step in self.steps]
            self.state.initialize(mode=mode, step_names=step_names)

        # Show intro
        self._show_intro()

        # Run wizard loop
        current_step = start_step
        while 0 <= current_step < len(self.steps):
            step = self.steps[current_step]

            # Show step header
            self._show_step_header(current_step, step)

            # Mark step as started
            self.state.mark_step_started(current_step)

            # Execute step
            result = step.execute(self.state, self.console)

            if result.success:
                # Store step data
                self.state.mark_step_completed(current_step, result.data)

                # Update config
                if result.data:
                    self._update_config_from_step(step, result.data)
            else:
                # Handle failure
                self.console.print(f"\n[red]{result.message}[/red]")
                for error in result.errors:
                    self.console.print(f"  [red]• {error}[/red]")

            # Handle navigation
            if result.next_step is not None:
                # Step requested specific navigation
                current_step = result.next_step
            else:
                # Show navigation options
                action = self.navigator.show_navigation_prompt(
                    step_number=current_step,
                    can_skip=step.can_skip,
                    can_go_back=current_step > 0,
                )

                if action == NavigationAction.QUIT:
                    if self.navigator.confirm_quit():
                        self.console.print("\n[yellow]Progress saved. Run 'fomorian wizard resume' to continue.[/yellow]")
                        return False
                    continue

                current_step, should_continue = self.navigator.get_next_step(
                    current_step, action, len(self.steps)
                )

                if not should_continue and action == NavigationAction.CONTINUE:
                    # Wizard completed
                    break

        # Wizard completed
        self._show_completion()
        return True

    def run_quick(self) -> bool:
        """Run wizard in quick mode with sensible defaults."""
        return self.run(mode="quick")

    def _show_intro(self) -> None:
        """Show wizard introduction."""
        self.console.print("This wizard will guide you through:")
        self.console.print("  1. Connecting to your Wazuh Manager")
        self.console.print("  2. Defining your environment (hosts, users, network)")
        self.console.print("  3. Configuring your attack scenario")
        self.console.print("  4. Validating everything works")
        self.console.print()
        self.console.print("[dim]Press Enter to continue, or Ctrl+C to cancel...[/dim]")

        try:
            input()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Wizard cancelled.[/yellow]")
            sys.exit(0)

    def _show_step_header(self, step_number: int, step: WizardStep) -> None:
        """Show header for a wizard step."""
        self.console.print()
        self.console.rule(
            f"[bold]Step {step_number + 1} of {len(self.steps)}: {step.name}[/bold]",
            style="cyan"
        )
        self.console.print()

        if step.description:
            self.console.print(f"[dim]{step.description}[/dim]")
            self.console.print()

    def _update_config_from_step(self, step: WizardStep, data: Dict) -> None:
        """Update config data from step result."""
        # Map step names to config sections
        section_map = {
            "Wazuh Connection": "wazuh",
            "Environment": "environment",
            "Hosts": "hosts",
            "Users": "users",
            "C2 Infrastructure": "c2",
            "Attack Path": "attack_path",
            "Engagement Type": "engagement",
            "Scenario Parameters": "params",
        }

        section = section_map.get(step.name)
        if section:
            self.state.update_config(section, data)

    def _show_completion(self) -> None:
        """Show wizard completion message."""
        self.console.print()
        self.console.print(Panel.fit(
            "[bold green]Wizard Complete![/bold green]\n\n"
            f"Configuration saved to: [cyan]{self.output_dir}[/cyan]\n\n"
            "[bold]Next steps:[/bold]\n"
            "1. Generate scenario: [yellow]fomorian generate --config ./config[/yellow]\n"
            "2. Inject into Wazuh: [yellow]fomorian inject --scenario ./output/scenario.json[/yellow]",
            title="✓ Success",
            border_style="green"
        ))

        # Show summary
        self.console.print()
        self.console.print("[bold]Configuration Summary:[/bold]")
        self._show_config_summary()

    def _show_config_summary(self) -> None:
        """Show summary of collected configuration."""
        config = self.state.config_data

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Section", style="dim")
        table.add_column("Details")

        # Wazuh
        wazuh = config.get("wazuh", {})
        if wazuh:
            wazuh_details = f"Host: {wazuh.get('host', 'N/A')}, Method: {wazuh.get('method', 'N/A')}"
            table.add_row("Wazuh", wazuh_details)

        # Environment
        env = config.get("environment", {})
        if env:
            env_details = f"Name: {env.get('name', 'N/A')}, Domain: {env.get('domain', 'N/A')}"
            table.add_row("Environment", env_details)

        # Hosts
        hosts = config.get("hosts", [])
        if hosts:
            table.add_row("Hosts", f"{len(hosts)} configured")

        # Users
        users = config.get("users", [])
        if users:
            table.add_row("Users", f"{len(users)} configured")

        # Engagement
        engagement = config.get("engagement", {})
        if engagement:
            table.add_row("Engagement", engagement.get("type", "N/A"))

        self.console.print(table)

    def get_state(self) -> WizardState:
        """Get the current wizard state."""
        return self.state

    def export_config(self, output_dir: Optional[Path] = None) -> Path:
        """
        Export the collected configuration to files.

        Args:
            output_dir: Directory to write config files

        Returns:
            Path to the output directory
        """
        import yaml

        output_dir = output_dir or self.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        config = self.state.config_data

        # Write environment.yaml
        env_data = {
            "name": config.get("environment", {}).get("name", "my-environment"),
            "domain": config.get("environment", {}).get("domain", "corp.local"),
            "network": config.get("environment", {}).get("network", {"internal": "10.0.0.0/24"}),
            "hosts": config.get("hosts", []),
            "users": config.get("users", []),
        }

        if config.get("c2"):
            env_data["c2"] = config["c2"]

        with open(output_dir / "environment.yaml", "w") as f:
            yaml.dump(env_data, f, default_flow_style=False, sort_keys=False)

        # Write attack_path.yaml
        if config.get("attack_path"):
            with open(output_dir / "attack_path.yaml", "w") as f:
                yaml.dump(config["attack_path"], f, default_flow_style=False, sort_keys=False)

        # Write engagement.yaml
        if config.get("engagement"):
            with open(output_dir / "engagement.yaml", "w") as f:
                yaml.dump(config["engagement"], f, default_flow_style=False, sort_keys=False)

        # Write timing.yaml
        if config.get("params"):
            with open(output_dir / "timing.yaml", "w") as f:
                yaml.dump(config["params"], f, default_flow_style=False, sort_keys=False)

        return output_dir
