"""
Command-line interface for the Purple Team Attack Scenario Generator.

Provides commands for configuring environments, generating scenarios,
and managing profiles.
"""

import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn
import yaml

from .config import ConfigLoader, EnvironmentConfig, AttackPathConfig, EngagementConfig, TimingConfig
from .config.defaults import (
    get_default_environment,
    get_default_attack_path,
    get_default_engagement,
    get_default_timing,
    PROFILE_TEMPLATES,
)
from .config.models import EngagementType, HostConfig, UserConfig, NetworkConfig, C2Config
from .builder import ScenarioBuilder
from .output.formatters import get_formatter

console = Console()


# ============================================================
# Main CLI Group
# ============================================================

@click.group()
@click.version_option(version="1.0.0", prog_name="purple-team-gen")
@click.pass_context
def cli(ctx):
    """
    Purple Team Attack Scenario Generator

    Generate realistic attack scenarios for security testing.
    Supports ransomware, exfiltration, APT, and insider threat simulations.
    """
    ctx.ensure_object(dict)


# ============================================================
# INIT Command
# ============================================================

@cli.command()
@click.option(
    "--template",
    "-t",
    type=click.Choice(["enterprise", "small_business", "cloud_hybrid", "minimal"]),
    default="enterprise",
    help="Profile template to use",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./config",
    help="Output directory for configuration files",
)
def init(template: str, output: str):
    """Initialize a new configuration from a template."""
    output_path = Path(output)

    console.print(f"\n[bold blue]Initializing configuration from '{template}' template...[/bold blue]\n")

    if output_path.exists() and any(output_path.iterdir()):
        if not Confirm.ask(f"[yellow]Directory {output} is not empty. Overwrite?[/yellow]"):
            console.print("[red]Aborted.[/red]")
            return

    output_path.mkdir(parents=True, exist_ok=True)

    # Get template data
    if template == "minimal":
        env_data = {
            "name": "my-environment",
            "domain": "corp.local",
            "network": {"internal": "10.0.0.0/24"},
            "hosts": [
                {
                    "hostname": "WS01.corp.local",
                    "short_name": "WS01",
                    "ip": "10.0.0.50",
                    "os": "windows",
                    "agent_id": "001",
                    "role": "workstation",
                    "users": ["user1"],
                }
            ],
            "users": [{"username": "user1", "display_name": "User One", "groups": ["Domain Users"]}],
        }
        path_data = {
            "name": "Basic Attack Path",
            "entry_point": "WS01",
            "path": [{"host": "WS01", "role": "initial_compromise", "techniques": ["T1059.001"]}],
        }
    else:
        profile = PROFILE_TEMPLATES.get(template, PROFILE_TEMPLATES["enterprise"])
        env_data = profile.get("environment", get_default_environment())
        path_data = profile.get("attack_path", get_default_attack_path())

    # Write configuration files
    files_written = []

    env_file = output_path / "environment.yaml"
    with open(env_file, "w") as f:
        yaml.dump(env_data, f, default_flow_style=False, sort_keys=False)
    files_written.append(env_file)

    path_file = output_path / "attack_path.yaml"
    with open(path_file, "w") as f:
        yaml.dump(path_data, f, default_flow_style=False, sort_keys=False)
    files_written.append(path_file)

    timing_file = output_path / "timing.yaml"
    with open(timing_file, "w") as f:
        yaml.dump(get_default_timing("realistic"), f, default_flow_style=False, sort_keys=False)
    files_written.append(timing_file)

    # Create engagement files for each type
    engagements_dir = output_path / "engagements"
    engagements_dir.mkdir(exist_ok=True)
    for eng_type in ["ransomware", "exfiltration", "persistent_c2", "insider_threat", "business_email_compromise"]:
        eng_file = engagements_dir / f"{eng_type}.yaml"
        with open(eng_file, "w") as f:
            yaml.dump(get_default_engagement(eng_type), f, default_flow_style=False, sort_keys=False)
        files_written.append(eng_file)

    # Display summary
    console.print(Panel.fit(
        f"[green]Configuration initialized successfully![/green]\n\n"
        f"Created {len(files_written)} files in [cyan]{output}[/cyan]\n\n"
        f"[bold]Next steps:[/bold]\n"
        f"1. Edit [cyan]environment.yaml[/cyan] with your hosts, users, and IPs\n"
        f"2. Edit [cyan]attack_path.yaml[/cyan] to define the attack sequence\n"
        f"3. Run: [yellow]purple-team-gen generate --config {output} --engagement ransomware[/yellow]",
        title="Initialization Complete",
    ))


# ============================================================
# CONFIGURE Command
# ============================================================

@cli.command()
@click.option("--interactive", "-i", is_flag=True, help="Interactive configuration wizard")
@click.option("--file", "-f", type=click.Path(exists=True), help="Load from YAML file")
@click.option("--output", "-o", type=click.Path(), default="./config", help="Output directory")
def configure(interactive: bool, file: str, output: str):
    """Configure environment, attack path, and engagement settings."""
    if file:
        # Load and validate existing config
        try:
            loader = ConfigLoader(file)
            loader.load()
            loader.validate()
            console.print(f"[green]Configuration loaded and validated from {file}[/green]")

            # Show summary
            if loader.environment:
                table = Table(title="Environment Configuration")
                table.add_column("Property", style="cyan")
                table.add_column("Value", style="green")
                table.add_row("Name", loader.environment.name)
                table.add_row("Domain", loader.environment.domain)
                table.add_row("Hosts", str(len(loader.environment.hosts)))
                table.add_row("Users", str(len(loader.environment.users)))
                console.print(table)
        except Exception as e:
            console.print(f"[red]Error loading configuration: {e}[/red]")
            sys.exit(1)

    elif interactive:
        _run_interactive_wizard(output)

    else:
        console.print("[yellow]Use --interactive for wizard mode or --file to load existing config[/yellow]")


def _run_interactive_wizard(output_dir: str):
    """Run the interactive configuration wizard with examples and guidance."""
    console.print(Panel.fit(
        "[bold blue]Fomorian Setup Wizard[/bold blue]\n\n"
        "This wizard helps you configure your environment for attack simulation.\n"
        "Each step includes examples to guide you.\n\n"
        "Press Ctrl+C at any time to cancel.",
        title="Welcome",
    ))

    # ────────────────────────────────────────────────────────────────────────
    # Step 1: Environment basics
    # ────────────────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Step 1: Environment Basics[/bold cyan]")
    console.print("[dim]Define your organization and network.[/dim]\n")

    console.print("  [yellow]Examples:[/yellow]")
    console.print("    Environment name:  acme-corp, contoso, my-lab")
    console.print("    Domain:            acme.local, corp.contoso.com")
    console.print("    Network CIDR:      10.0.0.0/24, 192.168.1.0/24\n")

    env_name = Prompt.ask("Environment name", default="my-corp")
    domain = Prompt.ask("Active Directory domain", default="corp.local")
    internal_cidr = Prompt.ask("Internal network CIDR", default="10.0.0.0/24")

    # ────────────────────────────────────────────────────────────────────────
    # Step 2: Hosts
    # ────────────────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Step 2: Define Hosts[/bold cyan]")
    console.print("[dim]Add the workstations, servers, and domain controllers in your attack path.[/dim]\n")

    console.print("  [yellow]Host Types and Examples:[/yellow]")
    console.print("    Workstation:        WORKSTATION01.corp.local    (WS01)")
    console.print("    Domain Controller:  DC01.corp.local             (DC01)")
    console.print("    File Server:        FILESERVER.corp.local       (FS01)")
    console.print("    Web Server:         WEBSERVER.corp.local        (WEB01)\n")

    console.print("  [yellow]Typical Attack Path:[/yellow]")
    console.print("    1. Workstation (phishing target, initial compromise)")
    console.print("    2. Domain Controller (credential theft, lateral movement)")
    console.print("    3. File Server (data staging, ransomware deployment)\n")

    hosts = []
    host_counter = 1

    while True:
        if not hosts:
            console.print("[bold]Add your first host (usually a workstation):[/bold]")
        else:
            console.print(f"\n[dim]Hosts added: {', '.join(h['short_name'] for h in hosts)}[/dim]")

        hostname = Prompt.ask("Host FQDN (or 'done' to finish)", default="done" if hosts else f"WORKSTATION01.{domain}")

        if hostname.lower() == "done":
            if not hosts:
                console.print("[yellow]At least one host is required.[/yellow]")
                continue
            break

        # Auto-detect role from hostname
        hostname_upper = hostname.upper()
        if "DC" in hostname_upper or "DOMAIN" in hostname_upper:
            default_role = "domain_controller"
        elif "FS" in hostname_upper or "FILE" in hostname_upper or "NAS" in hostname_upper:
            default_role = "file_server"
        elif "WEB" in hostname_upper or "IIS" in hostname_upper:
            default_role = "web_server"
        elif "DB" in hostname_upper or "SQL" in hostname_upper:
            default_role = "database"
        else:
            default_role = "workstation"

        # Generate smart defaults
        short_default = hostname.split(".")[0].upper()
        if len(short_default) > 10:
            # Abbreviate long names
            short_default = short_default[:6] + str(host_counter).zfill(2)

        base_ip = internal_cidr.split("/")[0].rsplit(".", 1)[0]

        short_name = Prompt.ask("  Short name", default=short_default)
        ip = Prompt.ask("  IP address", default=f"{base_ip}.{50 + len(hosts)}")

        console.print("  [dim]Role options: workstation, domain_controller, file_server, web_server, database[/dim]")
        role = Prompt.ask("  Role", default=default_role)

        agent_id = Prompt.ask("  Wazuh Agent ID", default=f"{len(hosts) + 1:03d}")

        hosts.append({
            "hostname": hostname,
            "short_name": short_name,
            "ip": ip,
            "os": "windows",
            "agent_id": agent_id,
            "role": role,
            "users": [],
        })
        console.print(f"  [green]Added: {short_name} ({role})[/green]")
        host_counter += 1

    # ────────────────────────────────────────────────────────────────────────
    # Step 3: Users
    # ────────────────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Step 3: Define Users[/bold cyan]")
    console.print("[dim]Add users that will appear in the attack logs.[/dim]\n")

    console.print("  [yellow]Username Examples:[/yellow]")
    console.print("    Standard user:      jsmith, john.smith, jsmith01")
    console.print("    Admin account:      admin.jsmith, jsmith.admin")
    console.print("    Service account:    svc.backup, sql.service\n")

    console.print("  [yellow]Typical Setup:[/yellow]")
    console.print("    1. Regular user (phishing target)")
    console.print("    2. IT admin (escalation target)")
    console.print("    3. Service account (persistence)\n")

    users = []
    while True:
        if not users:
            console.print("[bold]Add your first user (usually the phishing target):[/bold]")
        else:
            console.print(f"\n[dim]Users added: {', '.join(u['username'] for u in users)}[/dim]")

        username = Prompt.ask("Username (or 'done' to finish)", default="done" if users else "jsmith")

        if username.lower() == "done":
            if not users:
                # Add a default user
                console.print("[dim]Adding default user 'user1'...[/dim]")
                users.append({
                    "username": "user1",
                    "display_name": "User One",
                    "groups": ["Domain Users"],
                })
            break

        # Generate display name from username
        name_parts = username.replace(".", " ").replace("_", " ").split()
        display_default = " ".join(part.title() for part in name_parts if not part.isdigit())
        if not display_default:
            display_default = username.title()

        display_name = Prompt.ask("  Display name", default=display_default)

        # Suggest groups based on username
        if "admin" in username.lower() or "svc" in username.lower():
            default_groups = "Domain Admins, Domain Users"
        else:
            default_groups = "Domain Users"

        console.print("  [dim]Common groups: Domain Users, Domain Admins, IT, Finance, HR[/dim]")
        groups = Prompt.ask("  Groups (comma separated)", default=default_groups)

        users.append({
            "username": username,
            "display_name": display_name,
            "groups": [g.strip() for g in groups.split(",")],
        })
        console.print(f"  [green]Added: {username}[/green]")

    # ────────────────────────────────────────────────────────────────────────
    # Step 4: C2 Infrastructure
    # ────────────────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Step 4: C2 Infrastructure[/bold cyan]")
    console.print("[dim]Define the attacker command and control server (appears in network logs).[/dim]\n")

    console.print("  [yellow]Examples:[/yellow]")
    console.print("    C2 IP:      185.220.101.45 (Tor exit), 203.0.113.50 (test range)")
    console.print("    C2 Domain:  update-service.com, cdn-static.net, legit-looking.com")
    console.print("    C2 Port:    443 (HTTPS), 80 (HTTP), 8080 (alt HTTP)\n")

    c2_ip = Prompt.ask("C2 server IP", default="203.0.113.50")
    c2_domain = Prompt.ask("C2 domain", default="update-cdn.com")
    c2_port = IntPrompt.ask("C2 port", default=443)

    # ────────────────────────────────────────────────────────────────────────
    # Step 5: Attack Path
    # ────────────────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Step 5: Define Attack Path[/bold cyan]")
    console.print("[dim]Define how the attacker moves through your network.[/dim]\n")

    console.print(f"  [yellow]Your hosts:[/yellow] {', '.join(h['short_name'] for h in hosts)}\n")

    console.print("  [yellow]Typical Attack Paths:[/yellow]")
    console.print("    Ransomware:    Workstation > Domain Controller > File Server")
    console.print("    Exfiltration:  Workstation > File Server > (external)")
    console.print("    APT:           Workstation > DC > Multiple Servers\n")

    entry_point = Prompt.ask("Entry point (initial compromise host)", default=hosts[0]["short_name"])

    path_steps = []
    current_host = entry_point
    path_steps.append({
        "host": current_host,
        "role": "initial_compromise",
        "techniques": ["T1566.001", "T1059.001"],
    })

    if len(hosts) > 1:
        console.print(f"\n[dim]Starting from {current_host}. Define lateral movement.[/dim]")
        other_hosts = [h["short_name"] for h in hosts if h["short_name"] != current_host]

        while other_hosts:
            console.print(f"  [dim]Remaining hosts: {', '.join(other_hosts)}[/dim]")
            next_host = Prompt.ask(
                f"Next host to pivot to from {current_host} (or 'done')",
                default="done"
            )

            if next_host.lower() == "done":
                break

            if next_host not in [h["short_name"] for h in hosts]:
                console.print(f"  [red]Host '{next_host}' not found. Choose from: {', '.join(other_hosts)}[/red]")
                continue

            path_steps.append({
                "host": next_host,
                "pivot_from": current_host,
                "role": "pivot",
                "techniques": ["T1021.002"],
            })
            console.print(f"  [green]Added pivot: {current_host} > {next_host}[/green]")
            current_host = next_host
            if next_host in other_hosts:
                other_hosts.remove(next_host)

    # ────────────────────────────────────────────────────────────────────────
    # Step 6: Engagement Type
    # ────────────────────────────────────────────────────────────────────────
    console.print("\n[bold cyan]Step 6: Select Engagement Type[/bold cyan]")
    console.print("[dim]Choose the type of attack to simulate.[/dim]\n")

    console.print("  [yellow]Engagement Types:[/yellow]")
    console.print("    1. ransomware              Full kill chain with encryption and ransom notes")
    console.print("    2. exfiltration            Data theft with staging and cloud upload")
    console.print("    3. persistent_c2           APT style with long dwell time and beaconing")
    console.print("    4. insider_threat          Malicious insider stealing data")
    console.print("    5. business_email_compromise   Cloud email, OAuth phishing, wire fraud\n")

    engagement_choices = ["ransomware", "exfiltration", "persistent_c2", "insider_threat", "business_email_compromise"]
    engagement = Prompt.ask(
        "Engagement type",
        choices=engagement_choices,
        default="ransomware"
    )

    # ────────────────────────────────────────────────────────────────────────
    # Build and Save Configuration
    # ────────────────────────────────────────────────────────────────────────
    config = {
        "environment": {
            "name": env_name,
            "domain": domain,
            "network": {"internal": internal_cidr},
            "hosts": hosts,
            "users": users,
            "c2": {
                "ip": c2_ip,
                "domain": c2_domain,
                "port": c2_port,
            },
        },
        "attack_path": {
            "name": f"{env_name} Attack Path",
            "entry_point": entry_point,
            "path": path_steps,
        },
    }

    # Save configuration
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    env_file = output_path / "environment.yaml"
    with open(env_file, "w") as f:
        yaml.dump(config["environment"], f, default_flow_style=False, sort_keys=False)

    path_file = output_path / "attack_path.yaml"
    with open(path_file, "w") as f:
        yaml.dump(config["attack_path"], f, default_flow_style=False, sort_keys=False)

    timing_file = output_path / "timing.yaml"
    with open(timing_file, "w") as f:
        yaml.dump(get_default_timing("realistic"), f, default_flow_style=False, sort_keys=False)

    # Create engagement files
    engagements_dir = output_path / "engagements"
    engagements_dir.mkdir(exist_ok=True)
    for eng_type in ["ransomware", "exfiltration", "persistent_c2", "insider_threat", "business_email_compromise"]:
        eng_file = engagements_dir / f"{eng_type}.yaml"
        with open(eng_file, "w") as f:
            yaml.dump(get_default_engagement(eng_type), f, default_flow_style=False, sort_keys=False)

    # Display summary and next steps
    path_display = " > ".join(step["host"] for step in path_steps)

    console.print(Panel.fit(
        f"[green]Configuration saved to {output_dir}/[/green]\n\n"
        f"[bold]Summary:[/bold]\n"
        f"  Environment:  {env_name} ({domain})\n"
        f"  Network:      {internal_cidr}\n"
        f"  Hosts:        {len(hosts)} ({', '.join(h['short_name'] for h in hosts)})\n"
        f"  Users:        {len(users)} ({', '.join(u['username'] for u in users)})\n"
        f"  Attack Path:  {path_display}\n"
        f"  Engagement:   {engagement}\n\n"
        f"[bold]Files created:[/bold]\n"
        f"  environment.yaml\n"
        f"  attack_path.yaml\n"
        f"  timing.yaml\n"
        f"  engagements/*.yaml\n\n"
        f"[bold]Next step:[/bold]\n"
        f"  [yellow]fomorian generate --config {output_dir} --engagement {engagement} --output scenario.json[/yellow]\n\n"
        f"[bold]Or inject directly into Wazuh:[/bold]\n"
        f"  [yellow]fomorian generate --config {output_dir} --engagement {engagement} --inject wazuh[/yellow]",
        title="Setup Complete",
    ))


# ============================================================
# GENERATE Command
# ============================================================

@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), required=True, help="Configuration directory")
@click.option(
    "--engagement", "-e",
    type=click.Choice(["ransomware", "exfiltration", "persistent_c2", "insider_threat", "business_email_compromise"]),
    required=True,
    help="Engagement type",
)
@click.option("--output", "-o", type=click.Path(), default="./scenario.json", help="Output file")
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "ndjson", "syslog", "split", "wazuh"]),
    default="json",
    help="Output format (use 'wazuh' for raw Wazuh alerts)",
)
@click.option("--duration", "-d", type=str, default=None, help="Scenario duration (e.g., '4h', '7d')")
@click.option("--seed", type=int, default=None, help="Random seed for reproducibility")
@click.option("--dry-run", "-n", is_flag=True, help="Preview without generating")
@click.option(
    "--inject",
    type=click.Choice(["wazuh"]),
    default=None,
    help="Inject directly into Wazuh Manager",
)
@click.option("--siem-host", type=str, envvar="PURPLE_TEAM_HOST", help="SIEM host (or set PURPLE_TEAM_HOST)")
@click.option("--siem-port", type=int, envvar="PURPLE_TEAM_PORT", help="SIEM port (or set PURPLE_TEAM_PORT)")
@click.option("--siem-token", type=str, envvar="PURPLE_TEAM_TOKEN", help="SIEM API token (or set PURPLE_TEAM_TOKEN)")
@click.option("--siem-user", type=str, envvar="PURPLE_TEAM_USERNAME", help="SIEM username (or set PURPLE_TEAM_USERNAME)")
@click.option("--siem-password", type=str, envvar="PURPLE_TEAM_PASSWORD", help="SIEM password (or set PURPLE_TEAM_PASSWORD)")
@click.option("--realtime", is_flag=True, help="Replay logs with original timing delays")
@click.option(
    "--inject-method",
    type=click.Choice(["auto", "api", "file", "archives", "alerts"]),
    default="auto",
    help="Wazuh injection method: auto (detect best), api, file, archives, alerts",
)
def generate(
    config: str, engagement: str, output: str, format: str, duration: str,
    seed: int, dry_run: bool, inject: str, siem_host: str, siem_port: int,
    siem_token: str, siem_user: str, siem_password: str, realtime: bool,
    inject_method: str
):
    """Generate an attack scenario based on configuration."""
    console.print(f"\n[bold blue]Generating {engagement} scenario...[/bold blue]\n")

    # Load configuration
    try:
        loader = ConfigLoader(config)
        loader.load()
        loader.validate()
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)

    # Load engagement config
    eng_file = Path(config) / "engagements" / f"{engagement}.yaml"
    if eng_file.exists():
        with open(eng_file) as f:
            eng_data = yaml.safe_load(f)
    else:
        eng_data = get_default_engagement(engagement)

    if dry_run:
        _preview_scenario(loader, eng_data, duration)
        return

    # Build engagement config
    from .config.models import EngagementType as EngType
    engagement_type_map = {
        "ransomware": EngType.RANSOMWARE,
        "exfiltration": EngType.EXFILTRATION,
        "persistent_c2": EngType.PERSISTENT_C2,
        "insider_threat": EngType.INSIDER_THREAT,
        "business_email_compromise": EngType.BUSINESS_EMAIL_COMPROMISE,
    }
    eng_config = EngagementConfig(
        type=engagement_type_map[engagement],
        phases=eng_data.get("phases", []),
    )

    # Apply duration to timing if specified
    timing_config = loader.timing or TimingConfig()
    if duration:
        timing_config.duration = duration

    # Generate scenario
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Building scenario...", total=None)

        builder = ScenarioBuilder(
            environment=loader.environment,
            attack_path=loader.attack_path,
            engagement=eng_config,
            timing=timing_config,
            seed=seed,
        )
        scenario = builder.build()

        progress.update(task, description="[green]Scenario generated!")

    # Write output using formatters
    output_path = Path(output)
    formatter = get_formatter(format)
    files_created = formatter.write(scenario, output_path)

    # Build file list for display
    files_display = "\n".join(f"  - {f}" for f in files_created)

    # Handle SIEM injection if requested
    if inject:
        _inject_to_siem(
            scenario, inject, siem_host, siem_port, siem_token,
            siem_user, siem_password, realtime, inject_method
        )

    console.print(Panel.fit(
        f"[green]Scenario generated successfully![/green]\n\n"
        f"[bold]Files created:[/bold]\n{files_display}\n\n"
        f"Format: {format}\n"
        f"Total logs: {scenario.metadata.total_logs}\n"
        f"Duration: {scenario.metadata.duration}\n"
        f"Techniques: {len(scenario.metadata.techniques_used)}\n"
        f"Phases: {', '.join(scenario.metadata.kill_chain_phases)}",
        title="Generation Complete",
    ))


def _inject_to_siem(
    scenario, siem_type: str, host: str, port: int, token: str,
    username: str, password: str, realtime: bool, inject_method: str = "auto"
):
    """Inject scenario into SIEM."""
    from .injectors import get_injector, InjectorConfig

    # Build injector config
    protocol = "https"

    # Build extra config for Wazuh injection method
    extra = {}
    if siem_type == "wazuh":
        extra["method"] = inject_method
        extra["facility"] = "fomorian"

    config = InjectorConfig(
        host=host or "localhost",
        port=port or 0,
        protocol=protocol,
        api_key=token,
        token=token,
        username=username,
        password=password,
        realtime_replay=realtime,
        extra=extra,
    )

    console.print(f"\n[bold blue]Injecting into {siem_type}...[/bold blue]")

    try:
        injector = get_injector(siem_type, config)

        # Test connection
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Detecting Wazuh installation...", total=None)

            if not injector.connect():
                progress.update(task, description="[red]Connection failed!")
                console.print(f"[red]Failed to connect to {siem_type} at {config.host}:{config.port}[/red]")
                console.print("[yellow]Check your credentials and network connectivity.[/yellow]")
                # Show setup instructions for Wazuh
                if siem_type == "wazuh" and hasattr(injector, "get_setup_instructions"):
                    console.print("\n[bold]Setup Instructions:[/bold]")
                    console.print(injector.get_setup_instructions())
                return

            progress.update(task, description="[green]Connected!")

        # Show Wazuh installation details
        if siem_type == "wazuh" and hasattr(injector, "get_installation_info"):
            info = injector.get_installation_info()
            console.print(f"\n[cyan]Installation Type:[/cyan] {info.get('type', 'unknown').upper()}")
            if info.get("container_name"):
                console.print(f"[cyan]Container:[/cyan] {info['container_name']}")
            if info.get("version"):
                console.print(f"[cyan]Version:[/cyan] {info['version']}")
            console.print(f"[cyan]Injection Method:[/cyan] {info.get('effective_method', 'auto')}")

        # Inject logs with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Injecting {len(scenario.logs)} logs...", total=len(scenario.logs))

            def update_progress(current, total):
                progress.update(task, completed=current, description=f"Injecting logs ({current}/{total})...")

            result = injector.inject(scenario, progress_callback=update_progress)

            if result.success:
                progress.update(task, description=f"[green]Injected {result.logs_sent} logs!")
            else:
                progress.update(task, description=f"[yellow]Injected {result.logs_sent}, failed {result.logs_failed}")

        # Show result
        if result.success:
            console.print(Panel.fit(
                f"[green]Successfully injected {result.logs_sent} logs![/green]\n\n"
                f"SIEM: {siem_type}\n"
                f"Host: {config.host}:{config.port}\n"
                f"Duration: {result.duration_seconds:.2f}s",
                title="Injection Complete",
            ))
        else:
            console.print(Panel.fit(
                f"[yellow]Injection completed with errors[/yellow]\n\n"
                f"Sent: {result.logs_sent}\n"
                f"Failed: {result.logs_failed}\n"
                f"Errors: {len(result.errors)}",
                title="Injection Result",
            ))
            if result.errors[:5]:
                for err in result.errors[:5]:
                    console.print(f"  [red]• {err}[/red]")

    except Exception as e:
        console.print(f"[red]Injection error: {e}[/red]")


def _preview_scenario(loader: ConfigLoader, engagement: dict, duration: str):
    """Preview scenario without generating."""
    console.print(Panel.fit(
        f"[bold]Scenario Preview[/bold]\n\n"
        f"Environment: {loader.environment.name}\n"
        f"Domain: {loader.environment.domain}\n"
        f"Engagement: {engagement.get('type', 'unknown')}\n"
        f"Duration: {duration or 'default'}\n\n"
        f"[bold]Hosts in attack path:[/bold]",
        title="Dry Run",
    ))

    if loader.attack_path:
        for step in loader.attack_path.path:
            pivot = f" (from {step.pivot_from})" if step.pivot_from else " (entry point)"
            console.print(f"  → {step.host}{pivot}")
            if step.techniques:
                console.print(f"    Techniques: {', '.join(step.techniques)}")


# ============================================================
# VALIDATE Command
# ============================================================

@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), required=True, help="Configuration to validate")
def validate(config: str):
    """Validate configuration files."""
    console.print(f"\n[bold blue]Validating configuration: {config}[/bold blue]\n")

    try:
        loader = ConfigLoader(config)
        loader.load()
        loader.validate()

        console.print("[green]✓ Configuration is valid![/green]\n")

        # Show summary
        if loader.environment:
            table = Table(title="Configuration Summary")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details", style="white")

            table.add_row(
                "Environment",
                "✓",
                f"{loader.environment.name} ({len(loader.environment.hosts)} hosts)"
            )
            table.add_row(
                "Attack Path",
                "✓" if loader.attack_path else "○",
                f"{len(loader.attack_path.path)} steps" if loader.attack_path else "Not configured"
            )
            table.add_row(
                "Timing",
                "✓" if loader.timing else "○",
                loader.timing.mode if loader.timing else "Using defaults"
            )
            console.print(table)

    except Exception as e:
        console.print(f"[red]✗ Validation failed: {e}[/red]")
        sys.exit(1)


# ============================================================
# INJECT Command
# ============================================================

@cli.command()
@click.argument("scenario_file", type=click.Path(exists=True))
@click.option(
    "--siem", "-s",
    type=click.Choice(["wazuh"]),
    required=True,
    help="Target SIEM for injection",
)
@click.option("--host", "-h", type=str, envvar="PURPLE_TEAM_HOST", help="SIEM host")
@click.option("--port", "-p", type=int, envvar="PURPLE_TEAM_PORT", help="SIEM port")
@click.option("--token", "-t", type=str, envvar="PURPLE_TEAM_TOKEN", help="API token/key")
@click.option("--username", "-u", type=str, envvar="PURPLE_TEAM_USERNAME", help="Username")
@click.option("--password", type=str, envvar="PURPLE_TEAM_PASSWORD", help="Password")
@click.option("--index", type=str, help="Index/sourcetype name")
@click.option("--realtime", is_flag=True, help="Replay with original timing")
@click.option("--batch-size", type=int, default=100, help="Logs per batch (default: 100)")
@click.option("--delay", type=float, default=0, help="Delay between logs in seconds")
@click.option("--no-verify-ssl", is_flag=True, help="Disable SSL verification")
@click.option(
    "--inject-method",
    type=click.Choice(["auto", "api", "file", "archives", "alerts"]),
    default="auto",
    help="Wazuh injection method: auto (detect best), api, file, archives, alerts",
)
def inject(
    scenario_file: str, siem: str, host: str, port: int, token: str,
    username: str, password: str, index: str, realtime: bool,
    batch_size: int, delay: float, no_verify_ssl: bool, inject_method: str
):
    """Inject an existing scenario file into a SIEM."""
    import json
    from .injectors import get_injector, InjectorConfig
    from .builder.scenario_builder import AttackScenario, ScenarioMetadata, LogEntry

    console.print(f"\n[bold blue]Loading scenario from {scenario_file}...[/bold blue]\n")

    # Load scenario file
    try:
        with open(scenario_file) as f:
            data = json.load(f)
    except json.JSONDecodeError:
        # Try NDJSON
        logs_data = []
        metadata_data = None
        with open(scenario_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    obj = json.loads(line)
                    if obj.get("_type") == "metadata":
                        metadata_data = obj
                    else:
                        logs_data.append(obj)
        data = {"_metadata": metadata_data or {}, "logs": logs_data}

    # Reconstruct scenario object
    meta = data.get("_metadata", {})
    metadata = ScenarioMetadata(
        scenario_name=meta.get("scenario_name", "Imported Scenario"),
        engagement_type=meta.get("engagement_type", "unknown"),
        generated_at=meta.get("generated_at", ""),
        duration=meta.get("duration", ""),
        total_logs=meta.get("total_logs", len(data.get("logs", []))),
        hosts_involved=meta.get("hosts_involved", []),
        techniques_used=meta.get("techniques_used", []),
        kill_chain_phases=meta.get("kill_chain_phases", []),
        environment_name=meta.get("environment_name", ""),
    )

    logs = []
    for log_data in data.get("logs", []):
        logs.append(LogEntry(
            sequence=log_data.get("sequence", 0),
            timestamp=log_data.get("timestamp", ""),
            attack_phase=log_data.get("attack_phase", ""),
            technique=log_data.get("technique", ""),
            host=log_data.get("host", ""),
            comment=log_data.get("_comment", ""),
            log=log_data.get("log", log_data),
        ))

    scenario = AttackScenario(metadata=metadata, logs=logs)

    console.print(f"Loaded {len(logs)} logs from scenario")

    # Inject
    _inject_to_siem(scenario, siem, host, port, token, username, password, realtime, inject_method)


# ============================================================
# DETECT-WAZUH Command
# ============================================================

@cli.command("detect-wazuh")
@click.option("--show-instructions", "-i", is_flag=True, help="Show setup instructions")
def detect_wazuh(show_instructions: bool):
    """Detect Wazuh installation and show compatible injection methods."""
    from .injectors import InjectorConfig
    from .injectors.wazuh import WazuhInjector

    console.print("\n[bold blue]Detecting Wazuh Installation...[/bold blue]\n")

    # Create a basic config for detection
    config = InjectorConfig(
        host="localhost",
        port=55000,
        extra={"method": "auto"},
    )

    injector = WazuhInjector(config)
    injector._installation = injector._detect_installation()

    info = injector.get_installation_info()

    # Display detection results
    table = Table(title="Wazuh Installation Detection")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Installation Type", info.get("type", "none").upper())
    table.add_row("Manager Available", "Yes" if info.get("manager_available") else "No")
    table.add_row("Base Path", info.get("base_path") or "N/A")
    table.add_row("Container Name", info.get("container_name") or "N/A")
    table.add_row("Version", info.get("version") or "Unknown")
    table.add_row("API Available", "Yes" if info.get("api_available") else "No")

    console.print(table)

    # Show recommended injection methods
    console.print("\n[bold]Recommended Injection Methods:[/bold]")

    inst_type = info.get("type", "none")
    if inst_type == "docker":
        console.print("  [green]1. archives[/green] - Direct write to archives.json (recommended)")
        console.print("  [yellow]2. alerts[/yellow] - Direct write to alerts.json")
        console.print("  [dim]3. file[/dim] - Monitored log file (requires ossec.conf setup)")
        console.print("  [dim]4. api[/dim] - Wazuh API (requires credentials)")
    elif inst_type == "native" and info.get("manager_available"):
        console.print("  [green]1. archives[/green] - Direct write to archives.json (recommended)")
        console.print("  [yellow]2. alerts[/yellow] - Direct write to alerts.json")
        console.print("  [dim]3. file[/dim] - Monitored log file (requires ossec.conf setup)")
        console.print("  [dim]4. api[/dim] - Wazuh API (requires credentials)")
    elif inst_type == "agent":
        console.print("  [green]1. file[/green] - Monitored log file (requires ossec.conf setup)")
        console.print("  [dim]Note: Agent-only installations require log file monitoring[/dim]")
    else:
        console.print("  [yellow]1. api[/yellow] - Remote Wazuh API (requires host/credentials)")
        console.print("  [dim]2. file[/dim] - Generate and manually copy to Wazuh server")

    # Show usage example
    console.print("\n[bold]Quick Start:[/bold]")
    if inst_type in ("docker", "native") and info.get("manager_available"):
        console.print("  [dim]fomorian generate -c ./config -e ransomware --inject wazuh --inject-method archives[/dim]")
    elif inst_type == "agent":
        console.print("  [dim]fomorian generate -c ./config -e ransomware --inject wazuh --inject-method file[/dim]")
    else:
        console.print("  [dim]fomorian generate -c ./config -e ransomware --inject wazuh --inject-method api \\[/dim]")
        console.print("  [dim]  --siem-host your-wazuh-server --siem-user wazuh-wui --siem-password xxx[/dim]")

    if show_instructions:
        console.print("\n" + injector.get_setup_instructions())


# ============================================================
# LIST SIEMS Command
# ============================================================

@cli.command("list")
@click.argument("resource", type=click.Choice(["techniques", "engagements", "profiles", "templates", "siems"]))
@click.option("--tactic", "-t", type=str, help="Filter techniques by tactic")
def list_resources(resource: str, tactic: str):
    """List available resources (techniques, engagements, profiles, siems)."""
    if resource == "siems":
        # SIEM targets
        table = Table(title="Supported SIEM Targets")
        table.add_column("Target", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Default Port", style="green")

        siems = [
            ("wazuh", "Direct Wazuh Manager (multiple methods)", "55000"),
        ]

        for siem, desc, port in siems:
            table.add_row(siem, desc, port)

        console.print(table)

        # Wazuh injection methods
        console.print("\n")
        methods_table = Table(title="Wazuh Injection Methods (--inject-method)")
        methods_table.add_column("Method", style="cyan")
        methods_table.add_column("Description", style="white")
        methods_table.add_column("Requires", style="yellow")

        methods = [
            ("auto", "Auto-detect best method based on installation", "Auto"),
            ("archives", "Write directly to /var/ossec/logs/archives/archives.json", "Manager access"),
            ("alerts", "Write directly to /var/ossec/logs/alerts/alerts.json", "Manager access"),
            ("file", "Write to monitored log file (most compatible)", "ossec.conf setup"),
            ("api", "Use Wazuh Manager API", "API credentials"),
        ]

        for method, desc, requires in methods:
            methods_table.add_row(method, desc, requires)

        console.print(methods_table)

        console.print("\n[bold]Environment Variables:[/bold]")
        console.print("  PURPLE_TEAM_HOST     - SIEM hostname")
        console.print("  PURPLE_TEAM_PORT     - SIEM port")
        console.print("  PURPLE_TEAM_TOKEN    - API token/key")
        console.print("  PURPLE_TEAM_USERNAME - Username")
        console.print("  PURPLE_TEAM_PASSWORD - Password")

        console.print("\n[bold]Examples:[/bold]")
        console.print("  [dim]# Inject directly into Wazuh archives (recommended for local Wazuh)[/dim]")
        console.print("  fomorian generate -c ./config -e ransomware --inject wazuh --inject-method archives")
        console.print("")
        console.print("  [dim]# Use Wazuh API for remote injection[/dim]")
        console.print("  fomorian generate -c ./config -e ransomware --inject wazuh --inject-method api \\")
        console.print("    --siem-host wazuh-manager --siem-user wazuh-wui --siem-password xxx")
        console.print("")
        console.print("  [dim]# Detect Wazuh installation and show recommended methods[/dim]")
        console.print("  fomorian detect-wazuh")

    elif resource == "engagements":
        table = Table(title="Available Engagement Types")
        table.add_column("Type", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Phases", style="green")

        table.add_row(
            "ransomware",
            "Full kill chain ending with encryption",
            "8 phases"
        )
        table.add_row(
            "exfiltration",
            "Data staging, collection, and exfiltration",
            "6 phases"
        )
        table.add_row(
            "persistent_c2",
            "Long-term APT with multiple persistence",
            "8 phases"
        )
        table.add_row(
            "insider_threat",
            "Authorized user stealing data",
            "3 phases"
        )
        console.print(table)

    elif resource == "profiles":
        table = Table(title="Available Profile Templates")
        table.add_column("Profile", style="cyan")
        table.add_column("Description", style="white")

        for name, profile in PROFILE_TEMPLATES.items():
            table.add_row(name, profile.get("description", ""))
        table.add_row("minimal", "Minimal single-host configuration")
        console.print(table)

    elif resource == "techniques":
        console.print("[yellow]Technique listing requires template library (Phase 2)[/yellow]")
        console.print("Use: purple-team-gen list techniques --tactic lateral-movement")

    elif resource == "templates":
        console.print("[yellow]Template listing requires template library (Phase 2)[/yellow]")


# ============================================================
# WIZARD Command Group
# ============================================================

@cli.group()
def wizard():
    """
    Setup wizard for guided configuration.

    Run 'fomorian wizard full' for complete 10-step setup.
    """
    pass


@wizard.command("full")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./config",
    help="Output directory for configuration files",
)
def wizard_full(output: str):
    """Complete 10-step guided wizard (default)."""
    from .wizard import WizardRunner

    runner = WizardRunner(console=console, output_dir=Path(output))
    success = runner.run(mode="full")

    if success:
        runner.export_config(Path(output))
        sys.exit(0)
    else:
        sys.exit(1)


@wizard.command("quick")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./config",
    help="Output directory for configuration files",
)
def wizard_quick(output: str):
    """Quick setup with sensible defaults."""
    from .wizard import WizardRunner

    runner = WizardRunner(console=console, output_dir=Path(output))
    success = runner.run(mode="quick")

    if success:
        runner.export_config(Path(output))
        sys.exit(0)
    else:
        sys.exit(1)


@wizard.command("random")
@click.option(
    "--complexity",
    "-c",
    type=click.Choice(["simple", "medium", "complex"]),
    default="medium",
    help="Scenario complexity level",
)
@click.option(
    "--engagement",
    "-e",
    type=click.Choice([
        "ransomware", "exfiltration", "persistent_c2", "insider_threat",
        "destructive_attack", "account_takeover", "business_email_compromise", "random"
    ]),
    default="random",
    help="Engagement type (or 'random')",
)
@click.option("--duration", "-d", type=str, help="Duration override (e.g., 4h, 1d)")
@click.option("--seed", "-s", type=int, help="Random seed for reproducibility")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./config",
    help="Output directory for configuration files",
)
def wizard_random(complexity: str, engagement: str, duration: str, seed: int, output: str):
    """Generate a random scenario configuration."""
    from .random import RandomScenarioGenerator

    console.print(f"\n[bold blue]Generating random {complexity} scenario...[/bold blue]\n")

    generator = RandomScenarioGenerator(
        complexity=complexity,
        seed=seed,
    )

    scenario = generator.generate(
        engagement_type=engagement if engagement != "random" else None,
        duration=duration,
    )

    # Save configuration
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    # Write environment.yaml
    env_data = {
        "name": scenario["environment"]["name"],
        "domain": scenario["environment"]["domain"],
        "network": scenario["environment"]["network"],
        "hosts": scenario["hosts"],
        "users": scenario["users"],
    }
    if scenario.get("c2"):
        env_data["c2"] = scenario["c2"]

    with open(output_path / "environment.yaml", "w") as f:
        yaml.dump(env_data, f, default_flow_style=False, sort_keys=False)

    # Write attack_path.yaml
    with open(output_path / "attack_path.yaml", "w") as f:
        yaml.dump(scenario["attack_path"], f, default_flow_style=False, sort_keys=False)

    # Write engagement.yaml
    with open(output_path / "engagement.yaml", "w") as f:
        yaml.dump(scenario["engagement"], f, default_flow_style=False, sort_keys=False)

    # Write timing.yaml
    with open(output_path / "timing.yaml", "w") as f:
        yaml.dump(scenario["params"], f, default_flow_style=False, sort_keys=False)

    # Show summary
    console.print(Panel.fit(
        f"[bold green]Random Scenario Generated![/bold green]\n\n"
        f"Complexity: [cyan]{complexity}[/cyan]\n"
        f"Engagement: [cyan]{scenario['engagement']['type']}[/cyan]\n"
        f"Hosts: [cyan]{len(scenario['hosts'])}[/cyan]\n"
        f"Users: [cyan]{len(scenario['users'])}[/cyan]\n"
        f"Attack Path: [cyan]{len(scenario['attack_path']['path'])} steps[/cyan]\n"
        f"Duration: [cyan]{scenario['params']['total_duration']}[/cyan]\n\n"
        f"Output: [cyan]{output}[/cyan]\n\n"
        f"[bold]Next steps:[/bold]\n"
        f"1. Review: [yellow]cat {output}/environment.yaml[/yellow]\n"
        f"2. Generate: [yellow]fomorian generate -c {output} -e {scenario['engagement']['type']}[/yellow]",
        title="Random Scenario",
        border_style="green"
    ))

    if seed:
        console.print(f"\n[dim]Seed: {seed} (use --seed {seed} to reproduce)[/dim]")
    else:
        console.print(f"\n[dim]Seed: {scenario['metadata']['seed']} (use --seed to reproduce)[/dim]")


@wizard.command("resume")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./config",
    help="Output directory for configuration files",
)
def wizard_resume(output: str):
    """Resume from a saved checkpoint."""
    from .wizard import WizardRunner

    runner = WizardRunner(console=console, output_dir=Path(output))
    success = runner.run(mode="full", resume=True)

    if success:
        runner.export_config(Path(output))
        sys.exit(0)
    else:
        sys.exit(1)


@wizard.command("wazuh")
def wizard_wazuh():
    """Wazuh connection setup only."""
    from .wizard.steps.s02_wazuh import WazuhStep
    from .wizard import WizardState

    console.print("\n[bold blue]Wazuh Connection Setup[/bold blue]\n")

    state = WizardState()
    state.initialize(mode="wazuh", step_names=["Wazuh Connection"])

    step = WazuhStep()
    result = step.execute(state, console)

    if result.success:
        console.print("\n[green]Wazuh configuration complete![/green]")
        console.print(f"Configuration saved to: [cyan]~/.fomorian/wizard_state.json[/cyan]")
    else:
        console.print(f"\n[red]Setup failed: {result.message}[/red]")
        sys.exit(1)


# ============================================================
# PREFLIGHT Command
# ============================================================

@cli.command("preflight")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    required=True,
    help="Configuration directory or file to validate",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def preflight(config: str, verbose: bool):
    """
    Run pre-flight validation checks.

    Validates configuration and tests Wazuh connectivity before
    scenario generation.
    """
    from .preflight import PreflightChecker

    console.print(f"\n[bold blue]Running Pre-flight Checks[/bold blue]\n")
    console.print(f"Configuration: [cyan]{config}[/cyan]\n")

    checker = PreflightChecker(config_path=Path(config))
    result = checker.run_all()

    # Display results
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details")

    for check in result.checks:
        if check.passed:
            status = "[green]PASS[/green]"
        elif check.severity.value == "error":
            status = "[red]FAIL[/red]"
        else:
            status = "[yellow]WARN[/yellow]"

        details = check.message
        if verbose and check.details:
            details += f" ({'; '.join(check.details[:2])})"

        table.add_row(check.name, status, details)

    console.print(table)

    # Summary
    console.print()
    if result.passed:
        console.print(f"[green]{result.summary()}[/green]")
        console.print("\n[bold]Ready to generate scenarios![/bold]")
        console.print(f"  [dim]fomorian generate -c {config} -e ransomware[/dim]")
    else:
        console.print(f"[red]{result.summary()}[/red]")
        console.print("\n[bold]Please fix the errors above before generating.[/bold]")
        sys.exit(1)


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    cli()
