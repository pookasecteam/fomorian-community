"""
Wizard Navigation

Handles back/skip/resume navigation for the wizard.
"""

from enum import Enum
from typing import Optional, Tuple

from rich.console import Console
from rich.prompt import Prompt

from .state import WizardState, StepStatus


class NavigationAction(str, Enum):
    """Possible navigation actions."""
    CONTINUE = "continue"
    BACK = "back"
    SKIP = "skip"
    QUIT = "quit"
    RESTART = "restart"


class Navigator:
    """
    Handles wizard navigation including back, skip, and resume functionality.
    """

    def __init__(self, state: WizardState, console: Console):
        """
        Initialize navigator.

        Args:
            state: The wizard state object
            console: Rich console for output
        """
        self.state = state
        self.console = console

    def show_navigation_prompt(
        self,
        step_number: int,
        can_skip: bool = False,
        can_go_back: bool = True,
    ) -> NavigationAction:
        """
        Show navigation prompt and get user choice.

        Args:
            step_number: Current step number
            can_skip: Whether this step can be skipped
            can_go_back: Whether user can go back

        Returns:
            The chosen navigation action
        """
        options = ["[Enter] Continue"]

        if can_go_back and step_number > 0:
            options.append("[B] Back")

        if can_skip:
            options.append("[S] Skip")

        options.append("[Q] Quit")

        self.console.print()
        self.console.print("  ".join(options), style="dim")

        while True:
            choice = Prompt.ask("", default="").strip().lower()

            if choice == "" or choice == "c":
                return NavigationAction.CONTINUE
            elif choice == "b" and can_go_back and step_number > 0:
                return NavigationAction.BACK
            elif choice == "s" and can_skip:
                return NavigationAction.SKIP
            elif choice == "q":
                return NavigationAction.QUIT
            else:
                self.console.print("[yellow]Invalid choice. Please try again.[/yellow]")

    def get_next_step(
        self,
        current_step: int,
        action: NavigationAction,
        total_steps: int,
    ) -> Tuple[int, bool]:
        """
        Calculate the next step based on the action.

        Args:
            current_step: Current step number
            action: The navigation action taken
            total_steps: Total number of steps

        Returns:
            Tuple of (next_step_number, should_continue)
        """
        if action == NavigationAction.QUIT:
            return current_step, False

        if action == NavigationAction.BACK:
            # Go back to previous step
            new_step = max(0, current_step - 1)
            return new_step, True

        if action == NavigationAction.SKIP:
            # Mark current as skipped and move forward
            self.state.mark_step_skipped(current_step)
            new_step = min(total_steps - 1, current_step + 1)
            return new_step, True

        # Continue - move to next step
        new_step = current_step + 1
        if new_step >= total_steps:
            return current_step, False  # Wizard complete
        return new_step, True

    def handle_resume(self) -> Optional[int]:
        """
        Handle resuming from a checkpoint.

        Returns:
            Step number to resume from, or None to start fresh
        """
        if not self.state.has_checkpoint():
            return None

        checkpoint_info = self.state.get_checkpoint_info()
        if not checkpoint_info:
            return None

        self.console.print()
        self.console.print("[bold yellow]Existing wizard session found![/bold yellow]")
        self.console.print()
        self.console.print(f"  Mode: [cyan]{checkpoint_info['mode']}[/cyan]")
        self.console.print(
            f"  Progress: Step [cyan]{checkpoint_info['current_step'] + 1}[/cyan] "
            f"of [cyan]{checkpoint_info['total_steps']}[/cyan]"
        )
        self.console.print(f"  Started: [cyan]{checkpoint_info['started_at']}[/cyan]")
        self.console.print(f"  Last Updated: [cyan]{checkpoint_info['last_updated']}[/cyan]")
        self.console.print()

        choice = Prompt.ask(
            "Would you like to [bold]R[/bold]esume, start [bold]F[/bold]resh, or [bold]Q[/bold]uit?",
            choices=["r", "f", "q"],
            default="r",
        ).lower()

        if choice == "q":
            return -1  # Signal to quit

        if choice == "r":
            if self.state.load():
                return self.state.current_step
            else:
                self.console.print("[red]Failed to load checkpoint. Starting fresh.[/red]")
                return None

        # Start fresh
        self.state.clear()
        return None

    def confirm_quit(self) -> bool:
        """
        Confirm the user wants to quit.

        Returns:
            True if user confirms quit
        """
        self.console.print()
        self.console.print("[yellow]Your progress will be saved and can be resumed later.[/yellow]")

        choice = Prompt.ask(
            "Are you sure you want to quit?",
            choices=["y", "n"],
            default="n",
        ).lower()

        return choice == "y"

    def show_progress(self, current_step: int, total_steps: int) -> None:
        """
        Show wizard progress bar.

        Args:
            current_step: Current step number (0-indexed)
            total_steps: Total number of steps
        """
        completed = current_step
        remaining = total_steps - current_step - 1

        # Build progress bar
        bar_length = 30
        completed_length = int((completed / total_steps) * bar_length)
        current_length = 1
        remaining_length = bar_length - completed_length - current_length

        bar = (
            "[green]" + "=" * completed_length + "[/green]"
            + "[cyan]>[/cyan]"
            + "[dim]" + "-" * remaining_length + "[/dim]"
        )

        percentage = int((current_step / total_steps) * 100)

        self.console.print()
        self.console.print(f"Progress: [{bar}] {percentage}%")

    def get_step_summary(self) -> str:
        """
        Get a summary of completed steps.

        Returns:
            Formatted summary string
        """
        lines = []
        for step_num in sorted(self.state.steps.keys()):
            step = self.state.steps[step_num]

            if step.status == StepStatus.COMPLETED:
                icon = "[green]✓[/green]"
            elif step.status == StepStatus.SKIPPED:
                icon = "[yellow]○[/yellow]"
            elif step.status == StepStatus.IN_PROGRESS:
                icon = "[cyan]→[/cyan]"
            elif step.status == StepStatus.FAILED:
                icon = "[red]✗[/red]"
            else:
                icon = "[dim]○[/dim]"

            lines.append(f"  {icon} Step {step_num + 1}: {step.name}")

        return "\n".join(lines)
