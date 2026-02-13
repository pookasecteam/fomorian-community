"""
Step 6: C2 Infrastructure

Configure Command and Control infrastructure settings.
"""

import random
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel

from .base import WizardStep
from ..state import WizardState, StepResult


class C2Step(WizardStep):
    """C2 step - configure Command and Control infrastructure."""

    name = "C2 Infrastructure"
    description = "Define the simulated Command and Control server"
    required = True
    can_skip = True  # Can use defaults

    # Common C2 protocols
    C2_PROTOCOLS = ["https", "http", "dns", "tcp"]

    # Realistic C2 domains
    FAKE_C2_DOMAINS = [
        "update-cdn.com",
        "cloud-sync.net",
        "api-services.io",
        "static-content.org",
        "secure-update.net",
        "cdn-assets.com",
        "global-analytics.io",
        "content-delivery.net",
        "update-service.org",
        "api-gateway.net",
    ]

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the C2 configuration step."""

        existing_c2 = state.get_config("c2") or {}

        console.print(Panel.fit(
            "Configure the simulated C2 (Command & Control) server.\n"
            "This is used to generate realistic beacon traffic in logs.\n\n"
            "[dim]Note: These are fake IPs/domains for simulation only.[/dim]",
            title="C2 Infrastructure",
            border_style="blue"
        ))
        console.print()

        # Show current values if resuming
        if existing_c2:
            console.print("[bold]Current C2 configuration:[/bold]")
            console.print(f"  IP: [cyan]{existing_c2.get('ip', 'N/A')}[/cyan]")
            console.print(f"  Domain: [cyan]{existing_c2.get('domain', 'N/A')}[/cyan]")
            console.print(f"  Port: [cyan]{existing_c2.get('port', 'N/A')}[/cyan]")
            console.print()

            if self.prompt_confirm(console, "Keep current configuration?", default=True):
                return self.success(data=existing_c2)

        # Quick setup options
        console.print("[bold]Quick Setup Options:[/bold]")
        console.print("  [1] Use realistic defaults")
        console.print("  [2] Generate random C2")
        console.print("  [3] Custom configuration")
        console.print()

        choice = self.prompt_choice(
            console,
            "Choose setup",
            ["Use defaults", "Generate random", "Custom"],
            default="Use defaults"
        )

        if choice == "Use defaults":
            c2_config = self._get_default_c2()
        elif choice == "Generate random":
            c2_config = self._generate_random_c2()
        else:
            c2_config = self._configure_custom_c2(console)

        # Show summary
        console.print()
        console.print("[bold]C2 Configuration:[/bold]")
        console.print(f"  IP: [green]{c2_config['ip']}[/green]")
        console.print(f"  Domain: [green]{c2_config['domain']}[/green]")
        console.print(f"  Port: [green]{c2_config['port']}[/green]")
        console.print(f"  Protocol: [green]{c2_config['protocol']}[/green]")
        console.print(f"  Beacon Interval: [green]{c2_config['beacon_interval']}s[/green]")
        console.print(f"  Jitter: [green]{c2_config['jitter'] * 100}%[/green]")

        return self.success(data=c2_config)

    def validate(self, state: WizardState) -> List[str]:
        """Validate C2 configuration."""
        errors = []
        c2 = state.get_config("c2")

        if not c2:
            # C2 is optional
            return []

        if c2.get("ip"):
            import ipaddress
            try:
                ipaddress.ip_address(c2["ip"])
            except ValueError:
                errors.append("Invalid C2 IP address")

        if c2.get("port"):
            port = c2["port"]
            if not isinstance(port, int) or port < 1 or port > 65535:
                errors.append("C2 port must be between 1 and 65535")

        if c2.get("jitter"):
            jitter = c2["jitter"]
            if not isinstance(jitter, (int, float)) or jitter < 0 or jitter > 1:
                errors.append("Jitter must be between 0 and 1")

        return errors

    def _get_default_c2(self) -> Dict[str, Any]:
        """Get default C2 configuration."""
        return {
            "ip": "203.0.113.50",  # TEST-NET-3 documentation range
            "domain": "update-cdn.com",
            "port": 443,
            "protocol": "https",
            "beacon_interval": 60,
            "jitter": 0.2,
        }

    def _generate_random_c2(self) -> Dict[str, Any]:
        """Generate random C2 configuration."""
        # Generate random IP from documentation ranges (RFC 5737)
        ip_ranges = [
            (192, 0, 2),      # TEST-NET-1
            (198, 51, 100),   # TEST-NET-2
            (203, 0, 113),    # TEST-NET-3
        ]
        base = random.choice(ip_ranges)
        ip = f"{base[0]}.{base[1]}.{base[2]}.{random.randint(1, 254)}"

        return {
            "ip": ip,
            "domain": random.choice(self.FAKE_C2_DOMAINS),
            "port": random.choice([80, 443, 8080, 8443]),
            "protocol": random.choice(["http", "https"]),
            "beacon_interval": random.choice([30, 60, 120, 300]),
            "jitter": round(random.uniform(0.1, 0.3), 2),
        }

    def _configure_custom_c2(self, console: Console) -> Dict[str, Any]:
        """Configure C2 manually."""
        defaults = self._get_default_c2()

        # IP address
        ip = self.prompt_ip(
            console,
            "C2 server IP address",
            default=defaults["ip"]
        )

        # Domain
        domain = self.prompt_text(
            console,
            "C2 domain (for DNS/HTTPS)",
            default=defaults["domain"]
        )

        # Port
        port = self.prompt_int(
            console,
            "C2 port",
            default=defaults["port"],
            min_val=1,
            max_val=65535
        )

        # Protocol
        protocol = self.prompt_choice(
            console,
            "C2 protocol",
            self.C2_PROTOCOLS,
            default=defaults["protocol"]
        )

        # Beacon interval
        console.print()
        console.print("[dim]Beacon interval: How often the implant calls back to C2[/dim]")
        beacon_interval = self.prompt_int(
            console,
            "Beacon interval (seconds)",
            default=defaults["beacon_interval"],
            min_val=5,
            max_val=3600
        )

        # Jitter
        console.print()
        console.print("[dim]Jitter: Random variation in beacon timing (0-1, e.g., 0.2 = 20%)[/dim]")
        jitter_pct = self.prompt_int(
            console,
            "Jitter percentage",
            default=int(defaults["jitter"] * 100),
            min_val=0,
            max_val=100
        )
        jitter = jitter_pct / 100.0

        return {
            "ip": ip,
            "domain": domain,
            "port": port,
            "protocol": protocol,
            "beacon_interval": beacon_interval,
            "jitter": jitter,
        }

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        return self._get_default_c2()
