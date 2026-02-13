"""
Step 7: Attack Path

Configure the attack path through the environment.
"""

from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .base import WizardStep
from ..state import WizardState, StepResult


class AttackPathStep(WizardStep):
    """Attack path step - configure the sequence of hosts in the attack."""

    name = "Attack Path"
    description = "Define how the attacker moves through your environment"
    required = True
    can_skip = True  # Can auto-generate

    # Common techniques by role
    ROLE_TECHNIQUES = {
        "initial_compromise": ["T1566.001", "T1059.001", "T1204.002"],
        "discovery": ["T1087.001", "T1082", "T1083", "T1018"],
        "credential_access": ["T1003.001", "T1558.003"],
        "lateral_movement": ["T1021.002", "T1021.001"],
        "domain_dominance": ["T1003.006", "T1078.002"],
        "data_staging": ["T1074.001", "T1560.001"],
        "objective": ["T1486", "T1567", "T1490"],
    }

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the attack path step."""

        existing_path = state.get_config("attack_path") or {}
        hosts = state.get_config("hosts") or []

        if not hosts:
            console.print("[red]No hosts configured. Please go back and add hosts.[/red]")
            return self.failure("No hosts available for attack path")

        console.print(Panel.fit(
            "Define the attack path - the sequence of hosts the attacker targets.\n"
            "This determines the order and techniques used at each stage.\n\n"
            "[dim]The path starts at the entry point and progresses through pivots.[/dim]",
            title="Attack Path Configuration",
            border_style="blue"
        ))
        console.print()

        # Show available hosts
        console.print("[bold]Available hosts:[/bold]")
        self._show_hosts_summary(hosts, console)
        console.print()

        # Show existing path
        if existing_path and existing_path.get("path"):
            console.print("[bold]Current attack path:[/bold]")
            self._show_path_table(existing_path.get("path", []), console)
            console.print()

            if self.prompt_confirm(console, "Keep current path?", default=True):
                return self.success(data=existing_path)

        # Quick setup options
        console.print("[bold]Quick Setup Options:[/bold]")
        console.print("  [1] Auto-generate based on hosts")
        console.print("  [2] Use template (WS → DC → FS)")
        console.print("  [3] Custom path")
        console.print()

        choice = self.prompt_choice(
            console,
            "Choose setup",
            ["Auto-generate", "Use template", "Custom"],
            default="Auto-generate"
        )

        if choice == "Auto-generate":
            attack_path = self._auto_generate_path(hosts, state)
        elif choice == "Use template":
            attack_path = self._generate_template_path(hosts, state)
        else:
            attack_path = self._configure_custom_path(hosts, console, state)

        if not attack_path:
            return self.failure("Failed to create attack path")

        # Show final path
        console.print()
        console.print("[bold]Attack Path:[/bold]")
        console.print(f"  Name: [green]{attack_path['name']}[/green]")
        console.print(f"  Entry Point: [green]{attack_path['entry_point']}[/green]")
        console.print()
        self._show_path_table(attack_path.get("path", []), console)

        return self.success(data=attack_path)

    def validate(self, state: WizardState) -> List[str]:
        """Validate attack path configuration."""
        errors = []
        path = state.get_config("attack_path")
        hosts = state.get_config("hosts") or []

        if not path:
            errors.append("Attack path is not configured")
            return errors

        if not path.get("entry_point"):
            errors.append("Entry point is required")

        if not path.get("path"):
            errors.append("At least one path step is required")
            return errors

        # Get list of valid hostnames
        valid_hosts = {h["short_name"] for h in hosts}
        valid_hosts.update({h["hostname"] for h in hosts})

        # Validate each step
        for i, step in enumerate(path.get("path", [])):
            host = step.get("host")
            if not host:
                errors.append(f"Path step {i+1}: host is required")
            elif host not in valid_hosts:
                errors.append(f"Path step {i+1}: host '{host}' not found in environment")

        return errors

    def _auto_generate_path(self, hosts: List[Dict], state: WizardState) -> Dict[str, Any]:
        """Auto-generate attack path based on host roles."""
        path_steps = []

        # Find hosts by role
        workstations = [h for h in hosts if h.get("role") == "workstation"]
        dcs = [h for h in hosts if h.get("role") == "domain_controller"]
        file_servers = [h for h in hosts if h.get("role") == "file_server"]
        other_servers = [h for h in hosts if h.get("role") not in ["workstation", "domain_controller", "file_server"]]

        # Entry point is first workstation
        entry_host = workstations[0] if workstations else hosts[0]
        entry_name = entry_host["short_name"]

        # Initial compromise
        path_steps.append({
            "host": entry_name,
            "role": "initial_compromise",
            "techniques": self.ROLE_TECHNIQUES["initial_compromise"],
            "dwell_time": "30m",
        })

        # Discovery phase
        path_steps.append({
            "host": entry_name,
            "role": "discovery",
            "techniques": self.ROLE_TECHNIQUES["discovery"],
            "dwell_time": "15m",
        })

        # Credential access
        path_steps.append({
            "host": entry_name,
            "role": "credential_access",
            "techniques": self.ROLE_TECHNIQUES["credential_access"],
            "dwell_time": "10m",
        })

        # Lateral movement to DC
        if dcs:
            dc = dcs[0]
            path_steps.append({
                "host": dc["short_name"],
                "pivot_from": entry_name,
                "role": "lateral_movement",
                "techniques": self.ROLE_TECHNIQUES["lateral_movement"],
                "dwell_time": "20m",
            })

            # Domain dominance
            path_steps.append({
                "host": dc["short_name"],
                "role": "domain_dominance",
                "techniques": self.ROLE_TECHNIQUES["domain_dominance"],
                "dwell_time": "15m",
            })

        # Data staging on file server
        if file_servers:
            fs = file_servers[0]
            path_steps.append({
                "host": fs["short_name"],
                "pivot_from": dc["short_name"] if dcs else entry_name,
                "role": "data_staging",
                "techniques": self.ROLE_TECHNIQUES["data_staging"],
                "dwell_time": "30m",
            })

        # Objective
        objective_host = file_servers[0] if file_servers else (dcs[0] if dcs else entry_host)
        path_steps.append({
            "host": objective_host["short_name"],
            "role": "objective",
            "techniques": self.ROLE_TECHNIQUES["objective"][:2],
            "dwell_time": "15m",
        })

        return {
            "name": "Auto-Generated Attack Path",
            "description": "Automatically generated based on environment topology",
            "entry_point": entry_name,
            "path": path_steps,
        }

    def _generate_template_path(self, hosts: List[Dict], state: WizardState) -> Dict[str, Any]:
        """Generate a standard WS → DC → FS path."""
        # Find suitable hosts
        ws = None
        dc = None
        fs = None

        for host in hosts:
            role = host.get("role", "").lower()
            if "workstation" in role and not ws:
                ws = host
            elif "domain_controller" in role and not dc:
                dc = host
            elif "file_server" in role and not fs:
                fs = host

        # Fall back to first hosts if not found
        if not ws:
            ws = hosts[0]
        if not dc and len(hosts) > 1:
            dc = hosts[1]
        if not fs and len(hosts) > 2:
            fs = hosts[2]

        path_steps = [
            {
                "host": ws["short_name"],
                "role": "initial_compromise",
                "techniques": ["T1566.001", "T1059.001"],
                "dwell_time": "30m",
            },
        ]

        if dc:
            path_steps.append({
                "host": dc["short_name"],
                "pivot_from": ws["short_name"],
                "role": "lateral_movement",
                "techniques": ["T1021.002", "T1003.006"],
                "dwell_time": "20m",
            })

        if fs:
            path_steps.append({
                "host": fs["short_name"],
                "pivot_from": dc["short_name"] if dc else ws["short_name"],
                "role": "objective",
                "techniques": ["T1486"],
                "dwell_time": "15m",
            })

        return {
            "name": "Standard Attack Path",
            "description": "Workstation to Domain Controller to File Server",
            "entry_point": ws["short_name"],
            "path": path_steps,
        }

    def _configure_custom_path(self, hosts: List[Dict], console: Console, state: WizardState) -> Optional[Dict[str, Any]]:
        """Configure attack path manually."""
        host_names = [h["short_name"] for h in hosts]

        # Path name
        name = self.prompt_text(
            console,
            "Attack path name",
            default="Custom Attack Path"
        )

        # Entry point
        entry_point = self.prompt_choice(
            console,
            "Select entry point (initial compromise host)",
            host_names,
            default=host_names[0]
        )

        # Build path
        path_steps = []
        console.print()
        console.print("[bold]Define path steps:[/bold]")
        console.print("[dim]Enter empty host to finish[/dim]")
        console.print()

        # First step is always the entry point
        path_steps.append({
            "host": entry_point,
            "role": "initial_compromise",
            "techniques": self.ROLE_TECHNIQUES["initial_compromise"],
            "dwell_time": "30m",
        })

        previous_host = entry_point
        while True:
            console.print(f"\n[bold]Step {len(path_steps) + 1}:[/bold]")

            # Select host
            host = self.prompt_text(
                console,
                f"Host (available: {', '.join(host_names)})",
                required=False
            )

            if not host:
                break

            if host not in host_names:
                console.print(f"[red]Invalid host. Choose from: {', '.join(host_names)}[/red]")
                continue

            # Select role
            roles = list(self.ROLE_TECHNIQUES.keys())
            role = self.prompt_choice(
                console,
                "Role for this step",
                roles,
                default="discovery"
            )

            # Techniques (show suggestions)
            suggested = self.ROLE_TECHNIQUES.get(role, [])
            console.print(f"[dim]Suggested techniques: {', '.join(suggested)}[/dim]")
            techniques_str = self.prompt_text(
                console,
                "Techniques (comma-separated)",
                default=",".join(suggested[:3])
            )
            techniques = [t.strip() for t in techniques_str.split(",") if t.strip()]

            # Dwell time
            dwell_time = self.prompt_text(
                console,
                "Dwell time (e.g., 30m, 1h)",
                default="30m"
            )

            step = {
                "host": host,
                "role": role,
                "techniques": techniques,
                "dwell_time": dwell_time,
            }

            if host != previous_host:
                step["pivot_from"] = previous_host

            path_steps.append(step)
            previous_host = host

        return {
            "name": name,
            "entry_point": entry_point,
            "path": path_steps,
        }

    def _show_hosts_summary(self, hosts: List[Dict], console: Console) -> None:
        """Show brief hosts summary."""
        for host in hosts:
            console.print(f"  [cyan]{host['short_name']}[/cyan] ({host.get('role', 'unknown')})")

    def _show_path_table(self, path: List[Dict], console: Console) -> None:
        """Display attack path in a table."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim")
        table.add_column("Host")
        table.add_column("Role")
        table.add_column("Techniques")
        table.add_column("Dwell")

        for i, step in enumerate(path, 1):
            pivot = f" (from {step['pivot_from']})" if step.get("pivot_from") else ""
            techniques = ", ".join(step.get("techniques", [])[:3])
            if len(step.get("techniques", [])) > 3:
                techniques += "..."

            table.add_row(
                str(i),
                step.get("host", "") + pivot,
                step.get("role", ""),
                techniques,
                step.get("dwell_time", ""),
            )

        console.print(table)

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        hosts = state.get_config("hosts") or []
        if hosts:
            return self._auto_generate_path(hosts, state)
        return {}
