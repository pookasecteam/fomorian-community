"""
Pre-flight Checker

Main orchestrator for pre-flight validation checks.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .models import CheckResult, CheckSeverity
from .checks.config import validate_config
from .checks.wazuh import validate_wazuh
from .checks.templates import validate_templates


@dataclass
class PreflightResult:
    """Complete pre-flight check results."""
    checks: List[CheckResult]
    config_path: Optional[Path] = None

    @property
    def passed(self) -> bool:
        """Check if all critical checks passed."""
        return not any(
            c for c in self.checks
            if not c.passed and c.severity == CheckSeverity.ERROR
        )

    @property
    def errors(self) -> List[CheckResult]:
        """Get all error-level failures."""
        return [c for c in self.checks if not c.passed and c.severity == CheckSeverity.ERROR]

    @property
    def warnings(self) -> List[CheckResult]:
        """Get all warning-level issues."""
        return [c for c in self.checks if not c.passed and c.severity == CheckSeverity.WARNING]

    def summary(self) -> str:
        """Get summary string."""
        total = len(self.checks)
        passed = len([c for c in self.checks if c.passed])
        errors = len(self.errors)
        warnings = len(self.warnings)

        if errors > 0:
            status = "FAILED"
        elif warnings > 0:
            status = "PASSED with warnings"
        else:
            status = "PASSED"

        return f"{status}: {passed}/{total} checks passed ({errors} errors, {warnings} warnings)"


class PreflightChecker:
    """
    Orchestrates pre-flight validation checks.

    Runs a series of checks to validate:
    - Configuration files are valid
    - Host references are consistent
    - Wazuh connectivity works
    - Write permissions are available
    - Templates exist for techniques
    - Disk space is sufficient
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        config_data: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the checker.

        Args:
            config_path: Path to configuration directory/file
            config_data: Pre-loaded configuration data
        """
        self.config_path = config_path
        self.config_data = config_data or {}

    def run_all(self) -> PreflightResult:
        """
        Run all pre-flight checks.

        Returns:
            PreflightResult with all check results
        """
        checks = []

        # Load config if path provided
        if self.config_path and not self.config_data:
            self.config_data = self._load_config()

        # Run each check category
        checks.extend(validate_config(self.config_data))
        checks.extend(validate_wazuh(self.config_data.get("wazuh", {})))
        checks.extend(validate_templates(
            self.config_data.get("attack_path", {}),
            self.config_path
        ))

        # Additional checks
        checks.append(self._check_disk_space())
        checks.append(self._check_python_dependencies())

        return PreflightResult(checks=checks, config_path=self.config_path)

    def run_check(self, check_name: str) -> Optional[CheckResult]:
        """
        Run a specific check by name.

        Args:
            check_name: Name of the check to run

        Returns:
            CheckResult or None if check not found
        """
        check_map: Dict[str, Callable[[], CheckResult]] = {
            "config": lambda: validate_config(self.config_data)[0],
            "wazuh": lambda: validate_wazuh(self.config_data.get("wazuh", {}))[0],
            "disk_space": self._check_disk_space,
            "dependencies": self._check_python_dependencies,
        }

        if check_name in check_map:
            return check_map[check_name]()
        return None

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from path."""
        import yaml

        config = {}

        if not self.config_path:
            return config

        path = Path(self.config_path)

        if path.is_file():
            # Single file config
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}

        if path.is_dir():
            # Directory with multiple config files
            config_files = {
                "environment": ["environment.yaml", "environment.yml"],
                "attack_path": ["attack_path.yaml", "attack_path.yml"],
                "engagement": ["engagement.yaml", "engagement.yml"],
                "timing": ["timing.yaml", "timing.yml"],
            }

            for section, filenames in config_files.items():
                for filename in filenames:
                    filepath = path / filename
                    if filepath.exists():
                        with open(filepath, "r") as f:
                            data = yaml.safe_load(f)
                            if data:
                                if section == "environment":
                                    config.update(data)
                                else:
                                    config[section] = data
                        break

        return config

    def _check_disk_space(self) -> CheckResult:
        """Check available disk space."""
        import shutil

        try:
            total, used, free = shutil.disk_usage(".")
            free_mb = free // (1024 * 1024)
            free_gb = free_mb / 1024

            if free_mb < 100:
                return CheckResult(
                    name="Disk Space",
                    passed=False,
                    severity=CheckSeverity.WARNING,
                    message=f"Low disk space: {free_mb}MB available",
                    details=["Recommend at least 100MB free"]
                )

            return CheckResult(
                name="Disk Space",
                passed=True,
                severity=CheckSeverity.INFO,
                message=f"{free_gb:.1f}GB available"
            )

        except Exception as e:
            return CheckResult(
                name="Disk Space",
                passed=True,
                severity=CheckSeverity.INFO,
                message=f"Could not check disk space: {e}"
            )

    def _check_python_dependencies(self) -> CheckResult:
        """Check required Python packages are installed."""
        required = ["click", "rich", "pydantic", "yaml", "jinja2"]
        missing = []

        for package in required:
            try:
                __import__(package)
            except ImportError:
                missing.append(package)

        if missing:
            return CheckResult(
                name="Python Dependencies",
                passed=False,
                severity=CheckSeverity.ERROR,
                message=f"Missing packages: {', '.join(missing)}",
                details=["Run: pip install " + " ".join(missing)]
            )

        return CheckResult(
            name="Python Dependencies",
            passed=True,
            severity=CheckSeverity.INFO,
            message="All required packages installed"
        )
