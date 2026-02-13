"""
Template library for indexing and accessing attack log templates.

Indexes the existing 96+ attack log templates and provides
methods for retrieving templates by technique, phase, or criteria.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import re


@dataclass
class AttackTemplate:
    """Represents a single attack log template."""

    file_path: Path
    attack_id: str
    variation: str
    name: str
    description: str
    expected_detection: str
    expected_soar: Optional[str]
    kill_chain_phase: str
    notes: Optional[str]
    logs: List[Dict[str, Any]]
    os_type: str = "windows"  # Inferred from log structure

    @classmethod
    def from_file(cls, file_path: Path) -> "AttackTemplate":
        """Load template from JSON file."""
        with open(file_path, "r") as f:
            data = json.load(f)

        metadata = data.get("_metadata", {})

        # Infer OS type from log structure
        os_type = "windows"
        logs = data.get("logs", [])
        if logs:
            first_log = logs[0].get("log", {})
            if "syslog" in first_log or "tetragon" in first_log:
                os_type = "linux"
            elif "azure" in first_log or "o365" in first_log:
                os_type = "cloud"

        return cls(
            file_path=file_path,
            attack_id=metadata.get("attack_id", "UNKNOWN"),
            variation=metadata.get("variation", "001"),
            name=metadata.get("name", file_path.stem),
            description=metadata.get("description", ""),
            expected_detection=metadata.get("expected_detection", "MEDIUM"),
            expected_soar=metadata.get("expected_soar"),
            kill_chain_phase=metadata.get("kill_chain_phase", "unknown"),
            notes=metadata.get("notes"),
            logs=logs,
            os_type=os_type,
        )

    def get_raw_logs(self) -> List[Dict[str, Any]]:
        """Get raw log entries from template."""
        return self.logs

    def get_log_count(self) -> int:
        """Get number of logs in template."""
        return len(self.logs)


class TemplateLibrary:
    """
    Library for managing and accessing attack log templates.

    Indexes templates by technique ID, kill chain phase, and other criteria
    to enable efficient template selection during scenario generation.
    """

    def __init__(self, templates_dir: Optional[Path] = None):
        """
        Initialize the template library.

        Args:
            templates_dir: Path to attacks directory. Defaults to ../attacks
        """
        if templates_dir is None:
            # Default to attacks directory relative to generator
            templates_dir = Path(__file__).parent.parent.parent / "attacks"

        self.templates_dir = templates_dir
        self._templates: List[AttackTemplate] = []
        self._by_technique: Dict[str, List[AttackTemplate]] = {}
        self._by_phase: Dict[str, List[AttackTemplate]] = {}
        self._by_os: Dict[str, List[AttackTemplate]] = {}
        self._indexed = False

    def index(self) -> "TemplateLibrary":
        """
        Index all templates in the attacks directory.

        Returns:
            Self for method chaining
        """
        self._templates = []
        self._by_technique = {}
        self._by_phase = {}
        self._by_os = {}

        if not self.templates_dir.exists():
            raise FileNotFoundError(f"Templates directory not found: {self.templates_dir}")

        # Find all JSON files in attacks directory
        for json_file in self.templates_dir.rglob("*.json"):
            # Skip non-log files
            if "README" in json_file.name or "validation" in str(json_file):
                continue

            try:
                template = AttackTemplate.from_file(json_file)
                self._templates.append(template)

                # Index by technique ID
                tech_id = template.attack_id
                if tech_id not in self._by_technique:
                    self._by_technique[tech_id] = []
                self._by_technique[tech_id].append(template)

                # Index by phase
                phase = template.kill_chain_phase
                if phase not in self._by_phase:
                    self._by_phase[phase] = []
                self._by_phase[phase].append(template)

                # Index by OS
                os_type = template.os_type
                if os_type not in self._by_os:
                    self._by_os[os_type] = []
                self._by_os[os_type].append(template)

            except (json.JSONDecodeError, KeyError) as e:
                # Skip invalid files
                continue

        self._indexed = True
        return self

    def _ensure_indexed(self) -> None:
        """Ensure templates are indexed."""
        if not self._indexed:
            self.index()

    def get_all_templates(self) -> List[AttackTemplate]:
        """Get all indexed templates."""
        self._ensure_indexed()
        return self._templates

    def get_by_technique(self, technique_id: str) -> List[AttackTemplate]:
        """
        Get all templates for a MITRE ATT&CK technique.

        Args:
            technique_id: MITRE technique ID (e.g., "T1059.001")

        Returns:
            List of matching templates
        """
        self._ensure_indexed()
        return self._by_technique.get(technique_id, [])

    def get_by_phase(self, phase: str) -> List[AttackTemplate]:
        """
        Get all templates for a kill chain phase.

        Args:
            phase: Kill chain phase (e.g., "initial-access", "lateral-movement")

        Returns:
            List of matching templates
        """
        self._ensure_indexed()
        return self._by_phase.get(phase, [])

    def get_by_os(self, os_type: str) -> List[AttackTemplate]:
        """
        Get all templates for an operating system.

        Args:
            os_type: OS type ("windows", "linux", "cloud")

        Returns:
            List of matching templates
        """
        self._ensure_indexed()
        return self._by_os.get(os_type, [])

    def get_techniques(self) -> List[str]:
        """Get list of all technique IDs in library."""
        self._ensure_indexed()
        return sorted(self._by_technique.keys())

    def get_phases(self) -> List[str]:
        """Get list of all kill chain phases in library."""
        self._ensure_indexed()
        return sorted(self._by_phase.keys())

    def get_statistics(self) -> Dict[str, Any]:
        """Get library statistics."""
        self._ensure_indexed()
        return {
            "total_templates": len(self._templates),
            "techniques": len(self._by_technique),
            "phases": len(self._by_phase),
            "by_phase": {phase: len(templates) for phase, templates in self._by_phase.items()},
            "by_os": {os: len(templates) for os, templates in self._by_os.items()},
        }

    def search(
        self,
        technique: Optional[str] = None,
        phase: Optional[str] = None,
        os_type: Optional[str] = None,
        detection_level: Optional[str] = None,
    ) -> List[AttackTemplate]:
        """
        Search templates with multiple criteria.

        Args:
            technique: MITRE technique ID (or prefix like "T1059")
            phase: Kill chain phase
            os_type: Operating system type
            detection_level: Expected detection level (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            List of matching templates
        """
        self._ensure_indexed()
        results = self._templates.copy()

        if technique:
            if "." in technique:
                # Exact match
                results = [t for t in results if t.attack_id == technique]
            else:
                # Prefix match
                results = [t for t in results if t.attack_id.startswith(technique)]

        if phase:
            results = [t for t in results if t.kill_chain_phase == phase]

        if os_type:
            results = [t for t in results if t.os_type == os_type]

        if detection_level:
            results = [t for t in results if t.expected_detection == detection_level]

        return results

    def get_template_for_engagement(
        self,
        phase: str,
        os_type: str = "windows",
        prefer_critical: bool = True,
    ) -> Optional[AttackTemplate]:
        """
        Get a suitable template for an engagement phase.

        Args:
            phase: Kill chain phase
            os_type: Target OS type
            prefer_critical: Prefer templates with higher detection expectation

        Returns:
            Selected template or None
        """
        candidates = self.search(phase=phase, os_type=os_type)

        if not candidates:
            # Fall back to any OS
            candidates = self.search(phase=phase)

        if not candidates:
            return None

        if prefer_critical:
            # Sort by detection level (CRITICAL > HIGH > MEDIUM > LOW)
            priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
            candidates.sort(key=lambda t: priority.get(t.expected_detection, 5))

        return candidates[0]
