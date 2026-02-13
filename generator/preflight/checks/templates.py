"""
Template Availability Validation

Checks that attack templates exist for specified techniques.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..models import CheckResult, CheckSeverity


def validate_templates(
    attack_path: Dict[str, Any],
    config_path: Optional[Path] = None,
) -> List[CheckResult]:
    """
    Validate template availability for attack techniques.

    Args:
        attack_path: Attack path configuration
        config_path: Path to configuration directory

    Returns:
        List of check results
    """
    results = []

    # Collect all techniques from attack path
    techniques = _collect_techniques(attack_path)

    if not techniques:
        results.append(CheckResult(
            name="Templates",
            passed=True,
            severity=CheckSeverity.INFO,
            message="No specific techniques to check"
        ))
        return results

    # Find template directories
    template_dirs = _find_template_dirs(config_path)

    if not template_dirs:
        results.append(CheckResult(
            name="Templates",
            passed=True,
            severity=CheckSeverity.WARNING,
            message="No template directories found",
            details=["Templates will be generated dynamically"]
        ))
        return results

    # Check each technique
    found, missing = _check_technique_coverage(techniques, template_dirs)

    if missing:
        results.append(CheckResult(
            name="Template Coverage",
            passed=True,  # Missing templates is a warning, not error
            severity=CheckSeverity.WARNING,
            message=f"Missing templates for {len(missing)} techniques",
            details=[f"Not found: {', '.join(sorted(missing)[:5])}"]
        ))
    else:
        results.append(CheckResult(
            name="Template Coverage",
            passed=True,
            severity=CheckSeverity.INFO,
            message=f"Found templates for all {len(found)} techniques"
        ))

    return results


def _collect_techniques(attack_path: Dict[str, Any]) -> Set[str]:
    """Collect all technique IDs from attack path."""
    techniques = set()

    for step in attack_path.get("path", []):
        for tech in step.get("techniques", []):
            techniques.add(tech)

    return techniques


def _find_template_dirs(config_path: Optional[Path] = None) -> List[Path]:
    """Find directories containing attack templates."""
    search_paths = []

    # Check relative to config
    if config_path:
        if config_path.is_file():
            config_path = config_path.parent
        search_paths.append(config_path / "attacks")
        search_paths.append(config_path.parent / "attacks")

    # Check current directory
    search_paths.append(Path.cwd() / "attacks")

    # Check module location
    module_path = Path(__file__).parent.parent.parent.parent / "attacks"
    search_paths.append(module_path)

    return [p for p in search_paths if p.exists() and p.is_dir()]


def _check_technique_coverage(
    techniques: Set[str],
    template_dirs: List[Path],
) -> tuple[Set[str], Set[str]]:
    """
    Check which techniques have templates.

    Returns:
        Tuple of (found_techniques, missing_techniques)
    """
    found = set()
    missing = set()

    # Build index of available templates
    available_techniques = set()
    for template_dir in template_dirs:
        for json_file in template_dir.rglob("*.json"):
            # Extract technique ID from path or filename
            for part in str(json_file).split("/"):
                if part.startswith("T") and len(part) >= 5:
                    # Looks like a technique ID (T1234 or T1234.001)
                    tech_id = part.split("-")[0]  # Handle T1234-name format
                    available_techniques.add(tech_id)

    # Check each required technique
    for tech in techniques:
        if tech in available_techniques:
            found.add(tech)
        else:
            # Check for parent technique (T1234.001 -> T1234)
            parent = tech.split(".")[0] if "." in tech else None
            if parent and parent in available_techniques:
                found.add(tech)
            else:
                missing.add(tech)

    return found, missing
