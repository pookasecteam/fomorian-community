"""
Step 4: Hosts

Configure workstations, domain controllers, and servers.
"""

import ipaddress
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .base import WizardStep
from ..state import WizardState, StepResult


class HostsStep(WizardStep):
    """Hosts step - configure target hosts for the scenario."""

    name = "Hosts"
    description = "Define workstations, servers, and domain controllers"
    required = True
    can_skip = False

    # Host role choices
    HOST_ROLES = [
        "workstation",
        "domain_controller",
        "file_server",
        "web_server",
        "database_server",
        "mail_server",
        "backup_server",
        "generic",
    ]

    # OS choices
    OS_CHOICES = ["windows", "linux", "macos"]

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the hosts step."""

        # Get existing hosts
        existing_hosts = state.get_config("hosts") or []
        env = state.get_config("environment") or {}

        console.print(Panel.fit(
            "Define the hosts in your environment.\n"
            "At minimum, you need one workstation (entry point).\n"
            "For realistic scenarios, include a domain controller.",
            title="Host Configuration",
            border_style="blue"
        ))
        console.print()

        # Show existing hosts if any
        if existing_hosts:
            console.print("[bold]Existing hosts:[/bold]")
            self._show_hosts_table(existing_hosts, console)
            console.print()

            if self.prompt_confirm(console, "Keep existing hosts?", default=True):
                if self.prompt_confirm(console, "Add more hosts?", default=False):
                    hosts = list(existing_hosts)
                else:
                    return self.success(data=existing_hosts)
            else:
                hosts = []
        else:
            hosts = []

        # Suggest default hosts based on engagement type
        if not hosts:
            console.print("[bold]Quick Setup Options:[/bold]")
            console.print("  [1] Minimal (1 workstation)")
            console.print("  [2] Standard (workstation + DC)")
            console.print("  [3] Enterprise (workstation + DC + file server)")
            console.print("  [4] Custom (define each host)")
            console.print()

            choice = self.prompt_choice(
                console,
                "Choose setup",
                ["Minimal", "Standard", "Enterprise", "Custom"],
                default="Standard"
            )

            if choice != "Custom":
                hosts = self._generate_preset_hosts(choice, env)
                console.print()
                console.print("[bold]Generated hosts:[/bold]")
                self._show_hosts_table(hosts, console)
                console.print()

                if self.prompt_confirm(console, "Use these hosts?", default=True):
                    # Allow editing
                    if self.prompt_confirm(console, "Would you like to customize any host?", default=False):
                        hosts = self._edit_hosts(hosts, console, env)
                    return self.success(data=hosts)
                else:
                    hosts = []

        # Manual host entry
        console.print()
        console.print("[bold]Define hosts manually:[/bold]")
        console.print("[dim](Enter empty hostname to finish)[/dim]")
        console.print()

        agent_id_counter = len(hosts) + 1
        while True:
            host = self._configure_host(console, env, agent_id_counter)
            if host is None:
                break
            hosts.append(host)
            agent_id_counter += 1

            console.print()
            self._show_hosts_table(hosts, console)
            console.print()

        if not hosts:
            # Add at least one default host
            console.print("[yellow]At least one host is required. Adding default workstation.[/yellow]")
            hosts = self._generate_preset_hosts("Minimal", env)

        return self.success(data=hosts)

    def validate(self, state: WizardState) -> List[str]:
        """Validate hosts configuration."""
        errors = []
        hosts = state.get_config("hosts")

        if not hosts or len(hosts) == 0:
            errors.append("At least one host is required")
            return errors

        hostnames = set()
        ips = set()

        for i, host in enumerate(hosts):
            if not host.get("hostname"):
                errors.append(f"Host {i+1}: hostname is required")
            else:
                if host["hostname"] in hostnames:
                    errors.append(f"Duplicate hostname: {host['hostname']}")
                hostnames.add(host["hostname"])

            if not host.get("ip"):
                errors.append(f"Host {i+1}: IP address is required")
            else:
                if host["ip"] in ips:
                    errors.append(f"Duplicate IP: {host['ip']}")
                ips.add(host["ip"])

            if not host.get("agent_id"):
                errors.append(f"Host {i+1}: agent_id is required")

        return errors

    def _generate_preset_hosts(self, preset: str, env: Dict) -> List[Dict[str, Any]]:
        """Generate preset host configurations."""
        domain = env.get("domain", "corp.local")
        network = env.get("network", {}).get("internal", "10.0.0.0/24")

        # Parse network to get base IP
        net = ipaddress.ip_network(network, strict=False)
        base_ip = str(list(net.hosts())[49])  # Start at .50

        hosts = []

        if preset in ["Minimal", "Standard", "Enterprise"]:
            hosts.append({
                "hostname": f"WS01.{domain}",
                "short_name": "WS01",
                "ip": base_ip,
                "os": "windows",
                "agent_id": "007",
                "agent_name": "WS01",
                "role": "workstation",
                "users": ["jsmith"],
            })

        if preset in ["Standard", "Enterprise"]:
            dc_ip = str(list(net.hosts())[9])  # .10 for DC
            hosts.append({
                "hostname": f"DC01.{domain}",
                "short_name": "DC01",
                "ip": dc_ip,
                "os": "windows",
                "agent_id": "002",
                "agent_name": "DC01",
                "role": "domain_controller",
                "users": ["administrator"],
            })

        if preset == "Enterprise":
            fs_ip = str(list(net.hosts())[19])  # .20 for file server
            hosts.append({
                "hostname": f"FS01.{domain}",
                "short_name": "FS01",
                "ip": fs_ip,
                "os": "windows",
                "agent_id": "003",
                "agent_name": "FS01",
                "role": "file_server",
                "users": ["svc_backup"],
            })

        return hosts

    def _configure_host(self, console: Console, env: Dict, agent_id: int) -> Optional[Dict[str, Any]]:
        """Configure a single host interactively."""
        domain = env.get("domain", "corp.local")

        # Hostname
        hostname = self.prompt_text(
            console,
            f"Hostname (e.g., WS01.{domain})",
            required=False
        )

        if not hostname:
            return None

        # Auto-generate short_name
        short_name = hostname.split(".")[0]

        # IP address
        ip = self.prompt_ip(console, "IP address")

        # OS
        os_type = self.prompt_choice(
            console,
            "Operating system",
            self.OS_CHOICES,
            default="windows"
        )

        # Role
        role = self.prompt_choice(
            console,
            "Host role",
            self.HOST_ROLES,
            default="workstation"
        )

        # Agent ID
        agent_id_str = self.prompt_text(
            console,
            "Wazuh agent ID",
            default=str(agent_id).zfill(3)
        )

        # Users (comma-separated)
        users_str = self.prompt_text(
            console,
            "Users on this host (comma-separated)",
            default="user1",
            required=False
        )
        users = [u.strip() for u in users_str.split(",") if u.strip()]

        return {
            "hostname": hostname,
            "short_name": short_name,
            "ip": ip,
            "os": os_type,
            "agent_id": agent_id_str,
            "agent_name": short_name,
            "role": role,
            "users": users,
        }

    def _edit_hosts(self, hosts: List[Dict], console: Console, env: Dict) -> List[Dict]:
        """Allow editing of hosts."""
        for i, host in enumerate(hosts):
            console.print(f"\n[bold]Host {i+1}: {host['hostname']}[/bold]")

            if self.prompt_confirm(console, "Edit this host?", default=False):
                # Edit each field
                host["hostname"] = self.prompt_text(
                    console, "Hostname", default=host["hostname"]
                )
                host["short_name"] = host["hostname"].split(".")[0]
                host["ip"] = self.prompt_ip(console, "IP", default=host["ip"])
                host["os"] = self.prompt_choice(
                    console, "OS", self.OS_CHOICES, default=host["os"]
                )
                host["role"] = self.prompt_choice(
                    console, "Role", self.HOST_ROLES, default=host["role"]
                )
                host["agent_id"] = self.prompt_text(
                    console, "Agent ID", default=host["agent_id"]
                )
                users_str = self.prompt_text(
                    console, "Users (comma-separated)",
                    default=",".join(host.get("users", []))
                )
                host["users"] = [u.strip() for u in users_str.split(",") if u.strip()]

        return hosts

    def _show_hosts_table(self, hosts: List[Dict], console: Console) -> None:
        """Display hosts in a table."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Hostname")
        table.add_column("IP")
        table.add_column("OS")
        table.add_column("Role")
        table.add_column("Agent ID")

        for host in hosts:
            table.add_row(
                host.get("hostname", ""),
                host.get("ip", ""),
                host.get("os", ""),
                host.get("role", ""),
                host.get("agent_id", ""),
            )

        console.print(table)

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        env = state.get_config("environment") or {}
        return self._generate_preset_hosts("Standard", env)
