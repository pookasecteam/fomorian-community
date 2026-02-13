"""
Step 5: Users

Configure user accounts for the scenario.
"""

from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .base import WizardStep
from ..state import WizardState, StepResult


class UsersStep(WizardStep):
    """Users step - configure user accounts for the scenario."""

    name = "Users"
    description = "Define user accounts that will appear in attack logs"
    required = True
    can_skip = True  # Can use defaults

    # Common groups
    COMMON_GROUPS = [
        "Domain Users",
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "IT Support",
        "Helpdesk",
        "Finance",
        "HR",
        "Marketing",
        "Engineering",
    ]

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the users step."""

        # Get existing users and hosts
        existing_users = state.get_config("users") or []
        hosts = state.get_config("hosts") or []

        console.print(Panel.fit(
            "Define user accounts for your environment.\n"
            "These users will appear in attack logs as victims or targets.\n"
            "At minimum, you need one compromised user for the attack.",
            title="User Configuration",
            border_style="blue"
        ))
        console.print()

        # Extract users mentioned in hosts
        host_users = set()
        for host in hosts:
            for user in host.get("users", []):
                host_users.add(user)

        if host_users:
            console.print("[dim]Users referenced in host configurations:[/dim]")
            console.print(f"  {', '.join(sorted(host_users))}")
            console.print()

        # Show existing users
        if existing_users:
            console.print("[bold]Existing users:[/bold]")
            self._show_users_table(existing_users, console)
            console.print()

            if self.prompt_confirm(console, "Keep existing users?", default=True):
                if self.prompt_confirm(console, "Add more users?", default=False):
                    users = list(existing_users)
                else:
                    return self.success(data=existing_users)
            else:
                users = []
        else:
            users = []

        # Quick setup options
        if not users:
            console.print("[bold]Quick Setup Options:[/bold]")
            console.print("  [1] Generate from hosts (users mentioned in host config)")
            console.print("  [2] Standard set (3 users: regular, IT, admin)")
            console.print("  [3] Custom (define each user)")
            console.print()

            choice = self.prompt_choice(
                console,
                "Choose setup",
                ["Generate from hosts", "Standard set", "Custom"],
                default="Standard set"
            )

            if choice == "Generate from hosts" and host_users:
                users = self._generate_from_hosts(host_users, state)
            elif choice == "Standard set":
                users = self._generate_standard_users(state)

            if users and choice != "Custom":
                console.print()
                console.print("[bold]Generated users:[/bold]")
                self._show_users_table(users, console)
                console.print()

                if self.prompt_confirm(console, "Use these users?", default=True):
                    if self.prompt_confirm(console, "Would you like to customize any user?", default=False):
                        users = self._edit_users(users, console)
                    return self.success(data=users)
                else:
                    users = []

        # Manual user entry
        console.print()
        console.print("[bold]Define users manually:[/bold]")
        console.print("[dim](Enter empty username to finish)[/dim]")
        console.print()

        while True:
            user = self._configure_user(console, state)
            if user is None:
                break
            users.append(user)

            console.print()
            self._show_users_table(users, console)
            console.print()

        if not users:
            # Generate default users
            console.print("[yellow]At least one user is required. Generating defaults.[/yellow]")
            users = self._generate_standard_users(state)

        return self.success(data=users)

    def validate(self, state: WizardState) -> List[str]:
        """Validate users configuration."""
        errors = []
        users = state.get_config("users")

        if not users or len(users) == 0:
            errors.append("At least one user is required")
            return errors

        usernames = set()
        for i, user in enumerate(users):
            if not user.get("username"):
                errors.append(f"User {i+1}: username is required")
            else:
                if user["username"] in usernames:
                    errors.append(f"Duplicate username: {user['username']}")
                usernames.add(user["username"])

        return errors

    def _generate_from_hosts(self, host_users: set, state: WizardState) -> List[Dict[str, Any]]:
        """Generate user configs from host user references."""
        users = []
        for username in sorted(host_users):
            users.append(self._create_user_from_name(username))
        return users

    def _generate_standard_users(self, state: WizardState) -> List[Dict[str, Any]]:
        """Generate standard user set."""
        env = state.get_config("environment") or {}
        domain = env.get("domain", "corp.local").split(".")[0].upper()

        return [
            {
                "username": "jsmith",
                "display_name": "John Smith",
                "groups": ["Domain Users", "Finance"],
                "is_admin": False,
                "email": "jsmith@corp.local",
            },
            {
                "username": "mjones",
                "display_name": "Mike Jones",
                "groups": ["Domain Users", "IT Support"],
                "is_admin": False,
                "email": "mjones@corp.local",
            },
            {
                "username": "admin.sarah",
                "display_name": "Sarah Admin",
                "groups": ["Domain Users", "Domain Admins", "Administrators"],
                "is_admin": True,
                "email": "sarah.admin@corp.local",
            },
        ]

    def _create_user_from_name(self, username: str) -> Dict[str, Any]:
        """Create a user config from just a username."""
        # Determine if admin
        is_admin = any(
            keyword in username.lower()
            for keyword in ["admin", "svc_", "service", "root", "administrator"]
        )

        # Generate display name
        if "_" in username:
            parts = username.split("_")
            display_name = " ".join(p.capitalize() for p in parts)
        else:
            # Try to split camelCase or assume first.last
            display_name = username.replace(".", " ").title()

        # Determine groups
        groups = ["Domain Users"]
        if is_admin:
            groups.extend(["Domain Admins", "Administrators"])
        elif "svc" in username.lower() or "service" in username.lower():
            groups.append("Service Accounts")

        return {
            "username": username,
            "display_name": display_name,
            "groups": groups,
            "is_admin": is_admin,
            "email": f"{username}@corp.local",
        }

    def _configure_user(self, console: Console, state: WizardState) -> dict | None:
        """Configure a single user interactively."""
        # Username
        username = self.prompt_text(
            console,
            "Username (e.g., jsmith)",
            required=False
        )

        if not username:
            return None

        # Display name
        default_display = username.replace(".", " ").replace("_", " ").title()
        display_name = self.prompt_text(
            console,
            "Display name",
            default=default_display
        )

        # Groups
        console.print()
        console.print("[dim]Common groups: Domain Users, Domain Admins, IT Support, Finance, etc.[/dim]")
        groups_str = self.prompt_text(
            console,
            "Groups (comma-separated)",
            default="Domain Users"
        )
        groups = [g.strip() for g in groups_str.split(",") if g.strip()]

        # Is admin
        is_admin = any(
            g.lower() in ["domain admins", "administrators", "enterprise admins"]
            for g in groups
        )
        if not is_admin:
            is_admin = self.prompt_confirm(
                console,
                "Is this user an administrator?",
                default=False
            )

        # Email
        env = state.get_config("environment") or {}
        domain = env.get("domain", "corp.local")
        email = self.prompt_text(
            console,
            "Email",
            default=f"{username}@{domain}",
            required=False
        )

        return {
            "username": username,
            "display_name": display_name,
            "groups": groups,
            "is_admin": is_admin,
            "email": email,
        }

    def _edit_users(self, users: List[Dict], console: Console) -> List[Dict]:
        """Allow editing of users."""
        for i, user in enumerate(users):
            console.print(f"\n[bold]User {i+1}: {user['username']}[/bold]")

            if self.prompt_confirm(console, "Edit this user?", default=False):
                user["username"] = self.prompt_text(
                    console, "Username", default=user["username"]
                )
                user["display_name"] = self.prompt_text(
                    console, "Display name", default=user["display_name"]
                )
                groups_str = self.prompt_text(
                    console, "Groups (comma-separated)",
                    default=",".join(user.get("groups", []))
                )
                user["groups"] = [g.strip() for g in groups_str.split(",") if g.strip()]
                user["is_admin"] = self.prompt_confirm(
                    console, "Is admin?", default=user.get("is_admin", False)
                )
                user["email"] = self.prompt_text(
                    console, "Email", default=user.get("email", "")
                )

        return users

    def _show_users_table(self, users: List[Dict], console: Console) -> None:
        """Display users in a table."""
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Username")
        table.add_column("Display Name")
        table.add_column("Groups")
        table.add_column("Admin")

        for user in users:
            table.add_row(
                user.get("username", ""),
                user.get("display_name", ""),
                ", ".join(user.get("groups", [])[:2]) + ("..." if len(user.get("groups", [])) > 2 else ""),
                "Yes" if user.get("is_admin") else "No",
            )

        console.print(table)

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        return self._generate_standard_users(state)
