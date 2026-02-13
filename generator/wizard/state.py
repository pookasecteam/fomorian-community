"""
Wizard State Management

Handles checkpoint persistence and state tracking for the wizard.
Allows resuming from any step.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class StepStatus(str, Enum):
    """Status of a wizard step."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class StepResult:
    """Result of executing a wizard step."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    message: str = ""
    errors: List[str] = field(default_factory=list)
    next_step: Optional[int] = None  # Override for navigation

    @property
    def should_continue(self) -> bool:
        """Whether the wizard should continue to the next step."""
        return self.success


@dataclass
class StepState:
    """State for a single step."""
    step_number: int
    name: str
    status: StepStatus = StepStatus.PENDING
    data: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "name": self.name,
            "status": self.status.value,
            "data": self.data,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StepState":
        return cls(
            step_number=data["step_number"],
            name=data["name"],
            status=StepStatus(data.get("status", "pending")),
            data=data.get("data", {}),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
        )


class WizardState:
    """
    Manages wizard state with checkpoint persistence.

    State is saved to ~/.fomorian/wizard_state.json for resume capability.
    """

    DEFAULT_STATE_DIR = Path.home() / ".fomorian"
    STATE_FILENAME = "wizard_state.json"

    def __init__(self, state_dir: Optional[Path] = None):
        """
        Initialize wizard state.

        Args:
            state_dir: Directory for state files. Defaults to ~/.fomorian/
        """
        self.state_dir = state_dir or self._get_state_dir()
        self.state_file = self.state_dir / self.STATE_FILENAME

        # Initialize state
        self.wizard_id: str = ""
        self.wizard_mode: str = "full"  # full, quick, random
        self.current_step: int = 0
        self.total_steps: int = 10
        self.started_at: str = ""
        self.last_updated: str = ""
        self.steps: Dict[int, StepState] = {}

        # Collected configuration data
        self.config_data: Dict[str, Any] = {
            "wazuh": {},
            "environment": {},
            "hosts": [],
            "users": [],
            "c2": {},
            "attack_path": {},
            "engagement": {},
            "params": {},
        }

        # Ensure state directory exists
        self.state_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _get_state_dir(cls) -> Path:
        """Get state directory from environment or default."""
        env_dir = os.environ.get("FOMORIAN_STATE_DIR")
        if env_dir:
            return Path(env_dir)
        return cls.DEFAULT_STATE_DIR

    def initialize(self, mode: str = "full", step_names: Optional[List[str]] = None) -> None:
        """
        Initialize a new wizard session.

        Args:
            mode: Wizard mode (full, quick, random)
            step_names: List of step names
        """
        self.wizard_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.wizard_mode = mode
        self.current_step = 0
        self.started_at = datetime.now().isoformat()
        self.last_updated = self.started_at

        # Initialize step states
        if step_names:
            self.total_steps = len(step_names)
            for i, name in enumerate(step_names):
                self.steps[i] = StepState(step_number=i, name=name)

    def mark_step_started(self, step_number: int) -> None:
        """Mark a step as started."""
        if step_number in self.steps:
            self.steps[step_number].status = StepStatus.IN_PROGRESS
            self.steps[step_number].started_at = datetime.now().isoformat()
        self.current_step = step_number
        self.last_updated = datetime.now().isoformat()
        self.save()

    def mark_step_completed(self, step_number: int, data: Dict[str, Any] = None) -> None:
        """Mark a step as completed with its data."""
        if step_number in self.steps:
            self.steps[step_number].status = StepStatus.COMPLETED
            self.steps[step_number].completed_at = datetime.now().isoformat()
            if data:
                self.steps[step_number].data = data
        self.last_updated = datetime.now().isoformat()
        self.save()

    def mark_step_skipped(self, step_number: int) -> None:
        """Mark a step as skipped."""
        if step_number in self.steps:
            self.steps[step_number].status = StepStatus.SKIPPED
            self.steps[step_number].completed_at = datetime.now().isoformat()
        self.last_updated = datetime.now().isoformat()
        self.save()

    def mark_step_failed(self, step_number: int, errors: List[str] = None) -> None:
        """Mark a step as failed."""
        if step_number in self.steps:
            self.steps[step_number].status = StepStatus.FAILED
            if errors:
                self.steps[step_number].data["errors"] = errors
        self.last_updated = datetime.now().isoformat()
        self.save()

    def update_config(self, section: str, data: Dict[str, Any]) -> None:
        """Update a section of the configuration data."""
        if section in self.config_data:
            if isinstance(self.config_data[section], list):
                self.config_data[section] = data
            else:
                self.config_data[section].update(data)
        else:
            self.config_data[section] = data
        self.last_updated = datetime.now().isoformat()

    def get_config(self, section: str) -> Any:
        """Get configuration data for a section."""
        return self.config_data.get(section, {})

    def get_step_state(self, step_number: int) -> Optional[StepState]:
        """Get state for a specific step."""
        return self.steps.get(step_number)

    def get_last_completed_step(self) -> int:
        """Get the last completed step number."""
        completed = [
            num for num, state in self.steps.items()
            if state.status in (StepStatus.COMPLETED, StepStatus.SKIPPED)
        ]
        return max(completed) if completed else -1

    def can_skip_step(self, step_number: int) -> bool:
        """Check if a step can be skipped (has defaults)."""
        # Steps that can be skipped: Users (4), C2 (5), Attack Path (6), Params (8)
        skippable = {4, 5, 6, 8}
        return step_number in skippable

    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary for serialization."""
        return {
            "wizard_id": self.wizard_id,
            "wizard_mode": self.wizard_mode,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "started_at": self.started_at,
            "last_updated": self.last_updated,
            "steps": {str(k): v.to_dict() for k, v in self.steps.items()},
            "config_data": self.config_data,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], state_dir: Optional[Path] = None) -> "WizardState":
        """Create state from dictionary."""
        state = cls(state_dir=state_dir)
        state.wizard_id = data.get("wizard_id", "")
        state.wizard_mode = data.get("wizard_mode", "full")
        state.current_step = data.get("current_step", 0)
        state.total_steps = data.get("total_steps", 10)
        state.started_at = data.get("started_at", "")
        state.last_updated = data.get("last_updated", "")
        state.steps = {
            int(k): StepState.from_dict(v)
            for k, v in data.get("steps", {}).items()
        }
        state.config_data = data.get("config_data", state.config_data)
        return state

    def save(self) -> None:
        """Save state to disk."""
        with open(self.state_file, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    def load(self) -> bool:
        """
        Load state from disk.

        Returns:
            True if state was loaded successfully, False otherwise.
        """
        if not self.state_file.exists():
            return False

        try:
            with open(self.state_file, "r") as f:
                data = json.load(f)

            self.wizard_id = data.get("wizard_id", "")
            self.wizard_mode = data.get("wizard_mode", "full")
            self.current_step = data.get("current_step", 0)
            self.total_steps = data.get("total_steps", 10)
            self.started_at = data.get("started_at", "")
            self.last_updated = data.get("last_updated", "")
            self.steps = {
                int(k): StepState.from_dict(v)
                for k, v in data.get("steps", {}).items()
            }
            self.config_data = data.get("config_data", self.config_data)
            return True
        except (json.JSONDecodeError, KeyError):
            return False

    def clear(self) -> None:
        """Clear the saved state file."""
        if self.state_file.exists():
            self.state_file.unlink()

    def has_checkpoint(self) -> bool:
        """Check if there's a saved checkpoint."""
        return self.state_file.exists()

    def get_checkpoint_info(self) -> Optional[Dict[str, Any]]:
        """Get summary info about saved checkpoint."""
        if not self.has_checkpoint():
            return None

        try:
            with open(self.state_file, "r") as f:
                data = json.load(f)

            return {
                "wizard_id": data.get("wizard_id", ""),
                "mode": data.get("wizard_mode", "full"),
                "current_step": data.get("current_step", 0),
                "total_steps": data.get("total_steps", 10),
                "started_at": data.get("started_at", ""),
                "last_updated": data.get("last_updated", ""),
            }
        except (json.JSONDecodeError, KeyError):
            return None
