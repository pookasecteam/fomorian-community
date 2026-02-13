"""
Pre-flight Check Models

Shared data types for pre-flight validation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class CheckSeverity(str, Enum):
    """Severity levels for check results."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class CheckResult:
    """Result of a single pre-flight check."""
    name: str
    passed: bool
    severity: CheckSeverity
    message: str
    details: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.name}: {self.message}"
