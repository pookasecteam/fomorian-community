"""
Step 9: Scenario Parameters

Configure timing, duration, and other scenario parameters.
"""

import re
from typing import Any, Dict, List

from rich.console import Console
from rich.panel import Panel

from .base import WizardStep
from ..state import WizardState, StepResult


class ParamsStep(WizardStep):
    """Parameters step - configure timing and scenario parameters."""

    name = "Scenario Parameters"
    description = "Configure timing, duration, and simulation speed"
    required = True
    can_skip = True  # Can use defaults

    # Timing modes
    TIMING_MODES = {
        "realistic": {
            "name": "Realistic",
            "description": "Realistic timing with natural dwell times",
            "duration_multiplier": 1.0,
        },
        "compressed": {
            "name": "Compressed",
            "description": "Faster timing for quick testing",
            "duration_multiplier": 0.1,
        },
        "custom": {
            "name": "Custom",
            "description": "Define your own timing parameters",
            "duration_multiplier": 1.0,
        },
    }

    def execute(self, state: WizardState, console: Console) -> StepResult:
        """Execute the parameters step."""

        existing = state.get_config("params") or {}

        console.print(Panel.fit(
            "Configure timing and simulation parameters.\n"
            "These settings control how the scenario unfolds.",
            title="Scenario Parameters",
            border_style="blue"
        ))
        console.print()

        # Show current values if resuming
        if existing:
            console.print("[bold]Current parameters:[/bold]")
            console.print(f"  Mode: [cyan]{existing.get('mode', 'N/A')}[/cyan]")
            console.print(f"  Duration: [cyan]{existing.get('total_duration', 'N/A')}[/cyan]")
            console.print()

            if self.prompt_confirm(console, "Keep current parameters?", default=True):
                return self.success(data=existing)

        # Select timing mode
        console.print("[bold]Timing Mode:[/bold]")
        for mode_id, mode_info in self.TIMING_MODES.items():
            console.print(f"  [cyan]{mode_id}[/cyan]: {mode_info['description']}")
        console.print()

        mode = self.prompt_choice(
            console,
            "Select timing mode",
            list(self.TIMING_MODES.keys()),
            default="realistic"
        )

        params: Dict[str, Any] = {"mode": mode}

        if mode == "custom":
            params.update(self._configure_custom_timing(console))
        else:
            params.update(self._get_preset_timing(mode))

        # Additional options
        console.print()
        console.print("[bold]Additional Options:[/bold]")

        # Total duration
        duration = self.prompt_text(
            console,
            "Total scenario duration (e.g., 4h, 1d, 30m)",
            default=existing.get("total_duration", "4h")
        )
        params["total_duration"] = duration

        # Start time
        console.print()
        console.print("[dim]Start time: When the attack begins in the scenario timeline[/dim]")
        start_time = self.prompt_text(
            console,
            "Start time (ISO format or 'now')",
            default="now"
        )
        params["start_time"] = start_time

        # Noise ratio
        console.print()
        console.print("[dim]Noise ratio: Percentage of benign logs mixed with attack logs[/dim]")
        noise = self.prompt_int(
            console,
            "Noise ratio percentage (0-100)",
            default=0,
            min_val=0,
            max_val=100
        )
        params["noise_ratio"] = noise / 100.0

        # Business hours only
        business_hours = self.prompt_confirm(
            console,
            "Restrict to business hours (9-5)?",
            default=False
        )
        params["business_hours_only"] = business_hours

        # Show summary
        console.print()
        console.print("[bold]Parameter Summary:[/bold]")
        console.print(f"  Mode: [green]{mode}[/green]")
        console.print(f"  Duration: [green]{duration}[/green]")
        console.print(f"  Start: [green]{start_time}[/green]")
        console.print(f"  Noise: [green]{noise}%[/green]")
        console.print(f"  Business Hours: [green]{'Yes' if business_hours else 'No'}[/green]")

        return self.success(data=params)

    def validate(self, state: WizardState) -> List[str]:
        """Validate parameters configuration."""
        errors = []
        params = state.get_config("params")

        if not params:
            # Params are optional, will use defaults
            return []

        if params.get("mode") not in self.TIMING_MODES:
            errors.append(f"Unknown timing mode: {params.get('mode')}")

        # Validate duration format
        duration = params.get("total_duration", "")
        if duration and not self._parse_duration(duration):
            errors.append(f"Invalid duration format: {duration}")

        # Validate noise ratio
        noise = params.get("noise_ratio", 0)
        if not isinstance(noise, (int, float)) or noise < 0 or noise > 1:
            errors.append("Noise ratio must be between 0 and 1")

        return errors

    def _get_preset_timing(self, mode: str) -> Dict[str, Any]:
        """Get preset timing parameters."""
        if mode == "realistic":
            return {
                "default_interval": "30s",
                "discovery_phase_duration": "15m",
                "attack_phase_duration": "2h",
                "exfil_phase_duration": "1h",
                "jitter": 0.3,
            }
        elif mode == "compressed":
            return {
                "default_interval": "5s",
                "discovery_phase_duration": "2m",
                "attack_phase_duration": "15m",
                "exfil_phase_duration": "5m",
                "jitter": 0.1,
            }
        return {}

    def _configure_custom_timing(self, console: Console) -> Dict[str, Any]:
        """Configure custom timing parameters."""
        console.print()
        console.print("[bold]Custom Timing Configuration:[/bold]")

        default_interval = self.prompt_text(
            console,
            "Default interval between logs (e.g., 30s, 1m)",
            default="30s"
        )

        discovery_duration = self.prompt_text(
            console,
            "Discovery phase duration",
            default="15m"
        )

        attack_duration = self.prompt_text(
            console,
            "Attack phase duration",
            default="2h"
        )

        jitter_pct = self.prompt_int(
            console,
            "Timing jitter percentage (0-100)",
            default=30,
            min_val=0,
            max_val=100
        )

        return {
            "default_interval": default_interval,
            "discovery_phase_duration": discovery_duration,
            "attack_phase_duration": attack_duration,
            "jitter": jitter_pct / 100.0,
        }

    def _parse_duration(self, duration: str) -> int | None:
        """
        Parse duration string to seconds.

        Supports: 30s, 5m, 2h, 1d
        Returns None if invalid.
        """
        pattern = r'^(\d+)(s|m|h|d)$'
        match = re.match(pattern, duration.lower())

        if not match:
            return None

        value = int(match.group(1))
        unit = match.group(2)

        multipliers = {
            's': 1,
            'm': 60,
            'h': 3600,
            'd': 86400,
        }

        return value * multipliers.get(unit, 1)

    def get_default(self, state: WizardState) -> Dict[str, Any]:
        """Get default values."""
        defaults = self._get_preset_timing("realistic")
        defaults["mode"] = "realistic"
        defaults["total_duration"] = "4h"
        defaults["start_time"] = "now"
        defaults["noise_ratio"] = 0
        defaults["business_hours_only"] = False
        return defaults
