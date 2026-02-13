"""
Wazuh Validation

Pre-flight checks for Wazuh connectivity and permissions.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from .detector import WazuhDetector, WazuhInstallation, InstallationType
from .connector import WazuhConnector, ConnectionConfig, InjectionMethod


class CheckSeverity(str, Enum):
    """Severity level for validation checks."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationCheck:
    """Result of a single validation check."""
    name: str
    passed: bool
    severity: CheckSeverity
    message: str
    details: Optional[str] = None


@dataclass
class ValidationResult:
    """Complete validation result."""
    checks: List[ValidationCheck]

    @property
    def passed(self) -> bool:
        """Check if all critical checks passed."""
        return not any(
            c for c in self.checks
            if not c.passed and c.severity == CheckSeverity.ERROR
        )

    @property
    def errors(self) -> List[ValidationCheck]:
        """Get all failed error checks."""
        return [c for c in self.checks if not c.passed and c.severity == CheckSeverity.ERROR]

    @property
    def warnings(self) -> List[ValidationCheck]:
        """Get all warning checks."""
        return [c for c in self.checks if not c.passed and c.severity == CheckSeverity.WARNING]

    def summary(self) -> str:
        """Get summary string."""
        total = len(self.checks)
        passed = len([c for c in self.checks if c.passed])
        errors = len(self.errors)
        warnings = len(self.warnings)

        return f"{passed}/{total} checks passed ({errors} errors, {warnings} warnings)"


class WazuhValidator:
    """
    Validates Wazuh connectivity and configuration.

    Performs comprehensive pre-flight checks before scenario injection.
    """

    def __init__(self, installation: Optional[WazuhInstallation] = None):
        """
        Initialize validator.

        Args:
            installation: Pre-detected installation, or None to auto-detect
        """
        self.installation = installation
        self._detector = WazuhDetector()

    def validate(self, method: InjectionMethod = InjectionMethod.ALERTS) -> ValidationResult:
        """
        Run all validation checks.

        Args:
            method: Injection method to validate

        Returns:
            ValidationResult with all check results
        """
        checks = []

        # Check 1: Installation detection
        checks.append(self._check_installation())

        if not self.installation:
            return ValidationResult(checks=checks)

        # Check 2: Installation type
        checks.append(self._check_installation_type())

        # Check 3: Connectivity
        checks.append(self._check_connectivity())

        # Check 4: Write permission (if using file-based injection)
        if method in (InjectionMethod.ALERTS, InjectionMethod.ARCHIVES):
            checks.append(self._check_write_permission(method))

        # Check 5: Wazuh version
        checks.append(self._check_version())

        # Check 6: Wazuh service status
        checks.append(self._check_service_status())

        return ValidationResult(checks=checks)

    def _check_installation(self) -> ValidationCheck:
        """Check if Wazuh installation is detected."""
        if self.installation:
            return ValidationCheck(
                name="Installation Detection",
                passed=True,
                severity=CheckSeverity.INFO,
                message=f"Wazuh detected at {self.installation.location}"
            )

        # Try to auto-detect
        self.installation = self._detector.detect()

        if self.installation:
            return ValidationCheck(
                name="Installation Detection",
                passed=True,
                severity=CheckSeverity.INFO,
                message=f"Auto-detected Wazuh at {self.installation.location}"
            )

        return ValidationCheck(
            name="Installation Detection",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="No Wazuh installation detected",
            details="Run 'fomorian detect-wazuh' for detection options"
        )

    def _check_installation_type(self) -> ValidationCheck:
        """Check installation type is suitable for injection."""
        if self.installation.install_type == InstallationType.AGENT_ONLY:
            return ValidationCheck(
                name="Installation Type",
                passed=False,
                severity=CheckSeverity.ERROR,
                message="Agent-only installation cannot receive injected logs",
                details="Logs must be injected on the Wazuh Manager"
            )

        if self.installation.install_type == InstallationType.NONE:
            return ValidationCheck(
                name="Installation Type",
                passed=False,
                severity=CheckSeverity.WARNING,
                message="No Wazuh connection (generate-only mode)"
            )

        return ValidationCheck(
            name="Installation Type",
            passed=True,
            severity=CheckSeverity.INFO,
            message=f"Installation type: {self.installation.install_type.value}"
        )

    def _check_connectivity(self) -> ValidationCheck:
        """Check connectivity to Wazuh."""
        if not self.installation or self.installation.install_type == InstallationType.NONE:
            return ValidationCheck(
                name="Connectivity",
                passed=True,
                severity=CheckSeverity.INFO,
                message="Skipped (no connection configured)"
            )

        # Create connector and test
        config = ConnectionConfig(
            connection_type=self.installation.install_type.value,
            container_name=self.installation.container_name,
            ssh_host=self.installation.ssh_host,
            ssh_user=self.installation.ssh_user or "root",
            api_url=self.installation.api_url,
            alerts_path=self.installation.alerts_path or "/var/ossec/logs/alerts/alerts.json",
        )

        connector = WazuhConnector(config)
        result = connector.test_connection()

        return ValidationCheck(
            name="Connectivity",
            passed=result.success,
            severity=CheckSeverity.ERROR if not result.success else CheckSeverity.INFO,
            message=result.message,
            details=str(result.details) if result.details else None
        )

    def _check_write_permission(self, method: InjectionMethod) -> ValidationCheck:
        """Check write permission for target file."""
        if not self.installation:
            return ValidationCheck(
                name="Write Permission",
                passed=False,
                severity=CheckSeverity.WARNING,
                message="Cannot check (no installation)"
            )

        file_path = (
            self.installation.alerts_path
            if method == InjectionMethod.ALERTS
            else self.installation.archives_path
        )

        if not file_path:
            return ValidationCheck(
                name="Write Permission",
                passed=False,
                severity=CheckSeverity.WARNING,
                message=f"Path not configured for {method.value}"
            )

        # Create connector and check
        config = ConnectionConfig(
            connection_type=self.installation.install_type.value,
            container_name=self.installation.container_name,
            ssh_host=self.installation.ssh_host,
            alerts_path=file_path,
        )

        connector = WazuhConnector(config)
        result = connector.test_connection()

        if result.success and result.details.get("write_access"):
            return ValidationCheck(
                name="Write Permission",
                passed=True,
                severity=CheckSeverity.INFO,
                message=f"Write access confirmed for {file_path}"
            )

        return ValidationCheck(
            name="Write Permission",
            passed=False,
            severity=CheckSeverity.WARNING,
            message=f"No write access to {file_path}",
            details="May need elevated permissions (sudo/root)"
        )

    def _check_version(self) -> ValidationCheck:
        """Check Wazuh version."""
        if not self.installation or not self.installation.version:
            return ValidationCheck(
                name="Version Check",
                passed=True,
                severity=CheckSeverity.INFO,
                message="Version unknown"
            )

        version = self.installation.version

        # Parse version
        try:
            # Version format: "Wazuh v4.7.0" or "4.7.0"
            version_str = version.replace("Wazuh ", "").replace("v", "").strip()
            parts = version_str.split(".")
            major = int(parts[0])

            if major < 4:
                return ValidationCheck(
                    name="Version Check",
                    passed=False,
                    severity=CheckSeverity.WARNING,
                    message=f"Wazuh {version} may have compatibility issues",
                    details="Fomorian is tested with Wazuh 4.x+"
                )

            return ValidationCheck(
                name="Version Check",
                passed=True,
                severity=CheckSeverity.INFO,
                message=f"Wazuh version: {version}"
            )

        except (ValueError, IndexError):
            return ValidationCheck(
                name="Version Check",
                passed=True,
                severity=CheckSeverity.INFO,
                message=f"Version: {version}"
            )

    def _check_service_status(self) -> ValidationCheck:
        """Check if Wazuh service is running."""
        if not self.installation:
            return ValidationCheck(
                name="Service Status",
                passed=True,
                severity=CheckSeverity.INFO,
                message="Skipped (no installation)"
            )

        # For Docker, the container running means service is running
        if self.installation.install_type == InstallationType.DOCKER:
            return ValidationCheck(
                name="Service Status",
                passed=True,
                severity=CheckSeverity.INFO,
                message="Container is running"
            )

        # For native, we'd need to check service status
        # This is a simplified check
        return ValidationCheck(
            name="Service Status",
            passed=True,
            severity=CheckSeverity.INFO,
            message="Service status not verified"
        )
