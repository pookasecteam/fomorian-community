"""
Step 8: Engagement Type

Configure the type of attack engagement.
"""

from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .base import WizardStep
from ..state import WizardState, StepResult


class EngagementStep(WizardStep):
    """Engagement step - configure the type of attack scenario."""

    name = "Engagement Type"
    description = "Select the type of attack scenario to simulate"
    required = True
    can_skip = False

    # Engagement types with descriptions
    ENGAGEMENT_TYPES = {
        "ransomware": {
            "name": "Ransomware",
            "description": "Full ransomware kill chain with file encryption",
            "phases": ["Initial Access", "Discovery", "Credential Access", "Lateral Movement", "Encryption", "Ransom Note"],
            "techniques": ["T1566", "T1059", "T1003", "T1021", "T1486", "T1490"],
        },
        "exfiltration": {
            "name": "Data Exfiltration",
            "description": "APT-style data theft with staging and exfil",
            "phases": ["Initial Access", "Discovery", "Collection", "Staging", "Exfiltration"],
            "techniques": ["T1566", "T1083", "T1074", "T1560", "T1567"],
        },
        "persistent_c2": {
            "name": "Persistent C2",
            "description": "Long-term C2 beaconing with persistence",
            "phases": ["Initial Access", "Persistence", "C2", "Discovery", "Credential Access"],
            "techniques": ["T1566", "T1547", "T1071", "T1087", "T1003"],
        },
        "insider_threat": {
            "name": "Insider Threat",
            "description": "Malicious insider data theft",
            "phases": ["Internal Recon", "Data Collection", "Staging", "Exfiltration"],
            "techniques": ["T1087", "T1083", "T1074", "T1567"],
        },
        "business_email_compromise": {
            "name": "Business Email Compromise",
            "description": "OAuth phishing and email-based attack",
            "phases": ["Phishing", "OAuth Consent", "Email Access", "Wire Fraud"],
            "techniques": ["T1566", "T1550", "T1114", "T1534"],
        },
        "destructive_attack": {
            "name": "Destructive Attack",
            "description": "Wiper/destroyer malware simulation",
            "phases": ["Initial Access", "Lateral Movement", "Persistence", "Destruction"],
            "techniques": ["T1566", "T1021", "T1053", "T1485", "T1561"],
        },
        "account_takeover": {
            "name": "Account Takeover",
            "description": "Cloud/Azure AD account compromise",
            "phases": ["Credential Stuffing", "MFA Bypass", "Persistence", "Data Access"],
            "techniques": ["T1110", "T1111", "T1098", "T1114"],
        },
    }

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the engagement type step."""

        existing = state.get_config("engagement") or {}

        console.print(Panel.fit(
            "Select the type of attack scenario to simulate.\n"
            "Each engagement type has different phases and techniques.",
            title="Engagement Selection",
            border_style="blue"
        ))
        console.print()

        # Show current if resuming
        if existing.get("type"):
            console.print(f"[bold]Current selection:[/bold] [cyan]{existing['type']}[/cyan]")
            console.print()

            if self.prompt_confirm(console, "Keep current selection?", default=True):
                return self.success(data=existing)

        # Show engagement options
        console.print("[bold]Available Engagement Types:[/bold]")
        console.print()

        self._show_engagement_table(console)
        console.print()

        # Select type
        type_names = list(self.ENGAGEMENT_TYPES.keys())
        selected = self.prompt_choice(
            console,
            "Select engagement type",
            type_names,
            default="ransomware"
        )

        engagement_info = self.ENGAGEMENT_TYPES[selected]

        # Configure engagement-specific options
        engagement_config = {
            "type": selected,
        }

        if selected == "ransomware":
            engagement_config["ransomware"] = self._configure_ransomware(console)
        elif selected == "exfiltration":
            engagement_config["exfiltration"] = self._configure_exfiltration(console)
        elif selected == "persistent_c2":
            engagement_config["persistent_c2"] = self._configure_c2_engagement(console)
        elif selected == "insider_threat":
            engagement_config["insider_threat"] = self._configure_insider(console)
        elif selected == "destructive_attack":
            engagement_config["destructive"] = self._configure_destructive(console)

        # Show summary
        console.print()
        console.print("[bold]Engagement Configuration:[/bold]")
        console.print(f"  Type: [green]{engagement_info['name']}[/green]")
        console.print(f"  Description: [dim]{engagement_info['description']}[/dim]")
        console.print(f"  Phases: [cyan]{len(engagement_info['phases'])}[/cyan]")

        return self.success(data=engagement_config)

    def validate(self, state: WizardState) -> List[str]:
        """Validate engagement configuration."""
        errors = []
        engagement = state.get_config("engagement")

        if not engagement:
            errors.append("Engagement type is not configured")
            return errors

        if not engagement.get("type"):
            errors.append("Engagement type is required")

        if engagement.get("type") not in self.ENGAGEMENT_TYPES:
            errors.append(f"Unknown engagement type: {engagement.get('type')}")

        return errors

    def _show_engagement_table(self, console: Console) -> None:
        """Display engagement types in a table."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Type", style="cyan")
        table.add_column("Description")
        table.add_column("Phases")
        table.add_column("Key Techniques")

        for type_id, info in self.ENGAGEMENT_TYPES.items():
            table.add_row(
                type_id,
                info["description"],
                str(len(info["phases"])),
                ", ".join(info["techniques"][:3]) + "...",
            )

        console.print(table)

    def _configure_ransomware(self, console: Console) -> Dict[str, Any]:
        """Configure ransomware-specific options."""
        console.print()
        console.print("[bold]Ransomware Configuration:[/bold]")

        extension = self.prompt_text(
            console,
            "Encryption file extension",
            default=".encrypted"
        )

        shadow_delete = self.prompt_confirm(
            console,
            "Include shadow copy deletion?",
            default=True
        )

        target_extensions_str = self.prompt_text(
            console,
            "Target file extensions (comma-separated)",
            default=".docx,.xlsx,.pdf,.pptx,.txt"
        )
        target_extensions = [e.strip() for e in target_extensions_str.split(",")]

        return {
            "encryption_extension": extension,
            "shadow_delete": shadow_delete,
            "target_extensions": target_extensions,
        }

    def _configure_exfiltration(self, console: Console) -> Dict[str, Any]:
        """Configure exfiltration-specific options."""
        console.print()
        console.print("[bold]Exfiltration Configuration:[/bold]")

        staging_path = self.prompt_text(
            console,
            "Staging directory",
            default="C:\\Users\\Public\\Documents"
        )

        exfil_method = self.prompt_choice(
            console,
            "Exfiltration method",
            ["https", "dns", "ftp", "cloud"],
            default="https"
        )

        compress = self.prompt_confirm(
            console,
            "Compress files before exfil?",
            default=True
        )

        return {
            "staging_path": staging_path,
            "method": exfil_method,
            "compress": compress,
        }

    def _configure_c2_engagement(self, console: Console) -> Dict[str, Any]:
        """Configure C2 persistence engagement options."""
        console.print()
        console.print("[bold]Persistent C2 Configuration:[/bold]")

        persistence_method = self.prompt_choice(
            console,
            "Persistence mechanism",
            ["registry_run", "scheduled_task", "service", "startup_folder"],
            default="scheduled_task"
        )

        beacon_type = self.prompt_choice(
            console,
            "Beacon type",
            ["http", "https", "dns"],
            default="https"
        )

        return {
            "persistence_method": persistence_method,
            "beacon_type": beacon_type,
        }

    def _configure_insider(self, console: Console) -> Dict[str, Any]:
        """Configure insider threat options."""
        console.print()
        console.print("[bold]Insider Threat Configuration:[/bold]")

        target_data = self.prompt_choice(
            console,
            "Target data type",
            ["financial", "customer_pii", "intellectual_property", "credentials"],
            default="customer_pii"
        )

        exfil_method = self.prompt_choice(
            console,
            "Exfiltration method",
            ["usb", "email", "cloud_storage", "personal_email"],
            default="cloud_storage"
        )

        return {
            "target_data": target_data,
            "exfil_method": exfil_method,
        }

    def _configure_destructive(self, console: Console) -> Dict[str, Any]:
        """Configure destructive attack options."""
        console.print()
        console.print("[bold]Destructive Attack Configuration:[/bold]")

        console.print("[yellow]Warning: This simulates destructive malware like WhisperGate/HermeticWiper[/yellow]")

        targets = self.prompt_choice(
            console,
            "Primary target",
            ["mbr", "files", "both"],
            default="both"
        )

        trigger = self.prompt_choice(
            console,
            "Trigger mechanism",
            ["immediate", "scheduled", "command"],
            default="scheduled"
        )

        return {
            "targets": targets,
            "trigger": trigger,
        }

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        return {
            "type": "ransomware",
            "ransomware": {
                "encryption_extension": ".encrypted",
                "shadow_delete": True,
                "target_extensions": [".docx", ".xlsx", ".pdf"],
            }
        }
