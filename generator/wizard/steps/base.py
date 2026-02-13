"""
Base Wizard Step

Abstract base class for all wizard steps.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from ..state import WizardState, StepResult


class WizardStep(ABC):
    """
    Abstract base class for wizard steps.

    Each step must implement execute() and validate() methods.
    """

    # Step metadata
    name: str = "Unnamed Step"
    description: str = ""
    required: bool = True
    can_skip: bool = False

    def __init__(self):
        """Initialize the step."""
        pass

    @abstractmethod
    def execute(self, state: WizardState, console: Console) -> StepResult:
        """
        Execute this wizard step.

        Args:
            state: The wizard state object
            console: Rich console for output

        Returns:
            StepResult indicating success/failure and collected data
        """
        pass

    @abstractmethod
    def validate(self, state: WizardState) -> List[str]:
        """
        Validate the data collected by this step.

        Args:
            state: The wizard state object

        Returns:
            List of error messages (empty if valid)
        """
        pass

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """
        Get default values for this step.

        Can be overridden by subclasses to provide smart defaults
        based on current state.

        Args:
            state: The wizard state object

        Returns:
            Dictionary of default values
        """
        return {}

    def show_current_values(self, state: WizardState, console: Console) -> None:
        """
        Display current values for this step (if resuming).

        Args:
            state: The wizard state object
            console: Rich console for output
        """
        step_state = state.get_step_state(state.current_step)
        if step_state and step_state.data:
            console.print("[dim]Current values:[/dim]")
            for key, value in step_state.data.items():
                console.print(f"  [cyan]{key}[/cyan]: {value}")
            console.print()

    # Utility methods for common prompts

    def prompt_text(
        self,
        console: Console,
        prompt: str,
        default: str = "",
        required: bool = True,
        validator: Optional[callable] = None,
    ) -> str:
        """
        Prompt for text input.

        Args:
            console: Rich console
            prompt: Prompt text
            default: Default value
            required: Whether input is required
            validator: Optional validation function

        Returns:
            User input string
        """
        while True:
            value = Prompt.ask(prompt, default=default or "")

            if required and not value:
                console.print("[red]This field is required.[/red]")
                continue

            if validator and value:
                error = validator(value)
                if error:
                    console.print(f"[red]{error}[/red]")
                    continue

            return value

    def prompt_int(
        self,
        console: Console,
        prompt: str,
        default: int = 0,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
    ) -> int:
        """
        Prompt for integer input.

        Args:
            console: Rich console
            prompt: Prompt text
            default: Default value
            min_val: Minimum allowed value
            max_val: Maximum allowed value

        Returns:
            User input integer
        """
        while True:
            try:
                value = IntPrompt.ask(prompt, default=default)

                if min_val is not None and value < min_val:
                    console.print(f"[red]Value must be at least {min_val}.[/red]")
                    continue

                if max_val is not None and value > max_val:
                    console.print(f"[red]Value must be at most {max_val}.[/red]")
                    continue

                return value
            except ValueError:
                console.print("[red]Please enter a valid number.[/red]")

    def prompt_choice(
        self,
        console: Console,
        prompt: str,
        choices: List[str],
        default: Optional[str] = None,
    ) -> str:
        """
        Prompt for a choice from a list.

        Args:
            console: Rich console
            prompt: Prompt text
            choices: List of valid choices
            default: Default choice

        Returns:
            Selected choice
        """
        # Show choices
        console.print()
        for i, choice in enumerate(choices, 1):
            console.print(f"  [{i}] {choice}")
        console.print()

        # Get selection
        while True:
            selection = Prompt.ask(
                prompt,
                default=str(choices.index(default) + 1) if default else "1"
            )

            try:
                # Try as number
                idx = int(selection) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]
            except ValueError:
                # Try as string match
                for choice in choices:
                    if choice.lower() == selection.lower():
                        return choice

            console.print("[red]Invalid selection. Please choose a number from the list.[/red]")

    def prompt_confirm(
        self,
        console: Console,
        prompt: str,
        default: bool = True,
    ) -> bool:
        """
        Prompt for yes/no confirmation.

        Args:
            console: Rich console
            prompt: Prompt text
            default: Default value

        Returns:
            True for yes, False for no
        """
        return Confirm.ask(prompt, default=default)

    def prompt_ip(
        self,
        console: Console,
        prompt: str,
        default: str = "",
    ) -> str:
        """
        Prompt for IP address with validation.

        Args:
            console: Rich console
            prompt: Prompt text
            default: Default value

        Returns:
            Valid IP address
        """
        import ipaddress

        def validate_ip(value: str) -> Optional[str]:
            try:
                ipaddress.ip_address(value)
                return None
            except ValueError:
                return "Invalid IP address format"

        return self.prompt_text(console, prompt, default, validator=validate_ip)

    def prompt_cidr(
        self,
        console: Console,
        prompt: str,
        default: str = "",
    ) -> str:
        """
        Prompt for CIDR notation with validation.

        Args:
            console: Rich console
            prompt: Prompt text
            default: Default value

        Returns:
            Valid CIDR notation
        """
        import ipaddress

        def validate_cidr(value: str) -> Optional[str]:
            try:
                ipaddress.ip_network(value, strict=False)
                return None
            except ValueError:
                return "Invalid CIDR notation (e.g., 10.0.0.0/24)"

        return self.prompt_text(console, prompt, default, validator=validate_cidr)

    def prompt_domain(
        self,
        console: Console,
        prompt: str,
        default: str = "",
    ) -> str:
        """
        Prompt for domain name.

        Args:
            console: Rich console
            prompt: Prompt text
            default: Default value

        Returns:
            Domain name
        """
        import re

        def validate_domain(value: str) -> Optional[str]:
            pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(pattern, value):
                return "Invalid domain format (e.g., corp.local)"
            return None

        return self.prompt_text(console, prompt, default, validator=validate_domain)

    def show_table(
        self,
        console: Console,
        title: str,
        columns: List[str],
        rows: List[List[str]],
    ) -> None:
        """
        Display a table.

        Args:
            console: Rich console
            title: Table title
            columns: Column headers
            rows: Table rows
        """
        table = Table(title=title, show_header=True, header_style="bold cyan")

        for col in columns:
            table.add_column(col)

        for row in rows:
            table.add_row(*row)

        console.print(table)

    def success(self, data: Dict[str, Any] = None, message: str = "") -> StepResult:
        """Create a successful step result."""
        return StepResult(success=True, data=data or {}, message=message)

    def failure(self, message: str, errors: List[str] = None) -> StepResult:
        """Create a failed step result."""
        return StepResult(success=False, message=message, errors=errors or [])
