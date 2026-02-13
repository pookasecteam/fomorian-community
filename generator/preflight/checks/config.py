"""
Configuration Validation

Validates configuration structure and required fields.
"""

from typing import Any, Dict, List

from ..models import CheckResult, CheckSeverity


def validate_config(config: Dict[str, Any]) -> List[CheckResult]:
    """
    Validate configuration structure.

    Args:
        config: Configuration dictionary

    Returns:
        List of check results
    """
    results = []

    # Check required sections
    results.append(_check_required_sections(config))

    # Check hosts
    if "hosts" in config:
        results.append(_check_hosts(config["hosts"]))

    # Check users
    if "users" in config:
        results.append(_check_users(config["users"]))

    # Check attack path
    if "attack_path" in config:
        results.append(_check_attack_path(config["attack_path"], config.get("hosts", [])))

    # Check engagement
    if "engagement" in config:
        results.append(_check_engagement(config["engagement"]))

    return results


def _check_required_sections(config: Dict[str, Any]) -> CheckResult:
    """Check that required configuration sections exist."""
    required = ["name", "domain"]
    missing = [r for r in required if r not in config]

    # Check for hosts (required)
    if "hosts" not in config or not config["hosts"]:
        missing.append("hosts")

    if missing:
        return CheckResult(
            name="Required Sections",
            passed=False,
            severity=CheckSeverity.ERROR,
            message=f"Missing required configuration: {', '.join(missing)}",
            details=[f"Add '{m}' to your configuration" for m in missing]
        )

    return CheckResult(
        name="Required Sections",
        passed=True,
        severity=CheckSeverity.INFO,
        message="All required sections present"
    )


def _check_hosts(hosts: List[Dict]) -> CheckResult:
    """Validate hosts configuration."""
    if not hosts:
        return CheckResult(
            name="Hosts Configuration",
            passed=False,
            severity=CheckSeverity.ERROR,
            message="No hosts configured",
            details=["At least one host is required"]
        )

    errors = []
    hostnames = set()
    ips = set()
    agent_ids = set()

    for i, host in enumerate(hosts):
        # Check required fields
        if not host.get("hostname"):
            errors.append(f"Host {i+1}: missing hostname")

        if not host.get("ip"):
            errors.append(f"Host {i+1}: missing IP address")

        if not host.get("agent_id"):
            errors.append(f"Host {i+1}: missing agent_id")

        # Check for duplicates
        hostname = host.get("hostname", "")
        if hostname in hostnames:
            errors.append(f"Duplicate hostname: {hostname}")
        hostnames.add(hostname)

        ip = host.get("ip", "")
        if ip in ips:
            errors.append(f"Duplicate IP: {ip}")
        ips.add(ip)

        agent_id = host.get("agent_id", "")
        if agent_id in agent_ids:
            errors.append(f"Duplicate agent_id: {agent_id}")
        agent_ids.add(agent_id)

    if errors:
        return CheckResult(
            name="Hosts Configuration",
            passed=False,
            severity=CheckSeverity.ERROR,
            message=f"Found {len(errors)} host configuration error(s)",
            details=errors[:5]  # Limit to first 5
        )

    return CheckResult(
        name="Hosts Configuration",
        passed=True,
        severity=CheckSeverity.INFO,
        message=f"{len(hosts)} hosts configured correctly"
    )


def _check_users(users: List[Dict]) -> CheckResult:
    """Validate users configuration."""
    if not users:
        return CheckResult(
            name="Users Configuration",
            passed=True,
            severity=CheckSeverity.INFO,
            message="No users configured (will use defaults)"
        )

    errors = []
    usernames = set()

    for i, user in enumerate(users):
        if not user.get("username"):
            errors.append(f"User {i+1}: missing username")

        username = user.get("username", "")
        if username in usernames:
            errors.append(f"Duplicate username: {username}")
        usernames.add(username)

    if errors:
        return CheckResult(
            name="Users Configuration",
            passed=False,
            severity=CheckSeverity.ERROR,
            message=f"Found {len(errors)} user configuration error(s)",
            details=errors[:5]
        )

    return CheckResult(
        name="Users Configuration",
        passed=True,
        severity=CheckSeverity.INFO,
        message=f"{len(users)} users configured correctly"
    )


def _check_attack_path(
    attack_path: Dict[str, Any],
    hosts: List[Dict]
) -> CheckResult:
    """Validate attack path configuration."""
    if not attack_path:
        return CheckResult(
            name="Attack Path",
            passed=False,
            severity=CheckSeverity.WARNING,
            message="No attack path configured",
            details=["Attack path will be auto-generated"]
        )

    errors = []

    # Check entry point
    entry = attack_path.get("entry_point")
    if not entry:
        errors.append("Missing entry_point")

    # Check path steps
    path = attack_path.get("path", [])
    if not path:
        errors.append("Attack path is empty")

    # Build set of valid host names
    valid_hosts = set()
    for host in hosts:
        valid_hosts.add(host.get("short_name", ""))
        valid_hosts.add(host.get("hostname", ""))

    # Validate host references
    for i, step in enumerate(path):
        host = step.get("host", "")
        if host and host not in valid_hosts and valid_hosts:
            errors.append(f"Step {i+1}: unknown host '{host}'")

        pivot = step.get("pivot_from", "")
        if pivot and pivot not in valid_hosts and valid_hosts:
            errors.append(f"Step {i+1}: unknown pivot host '{pivot}'")

    if errors:
        return CheckResult(
            name="Attack Path",
            passed=False,
            severity=CheckSeverity.ERROR,
            message=f"Found {len(errors)} attack path error(s)",
            details=errors[:5]
        )

    return CheckResult(
        name="Attack Path",
        passed=True,
        severity=CheckSeverity.INFO,
        message=f"Attack path with {len(path)} steps validated"
    )


def _check_engagement(engagement: Dict[str, Any]) -> CheckResult:
    """Validate engagement configuration."""
    valid_types = [
        "ransomware",
        "exfiltration",
        "persistent_c2",
        "insider_threat",
        "destructive_attack",
        "account_takeover",
        "business_email_compromise",
    ]

    eng_type = engagement.get("type")
    if not eng_type:
        return CheckResult(
            name="Engagement Type",
            passed=False,
            severity=CheckSeverity.WARNING,
            message="No engagement type specified",
            details=["Will default to 'ransomware'"]
        )

    if eng_type not in valid_types:
        return CheckResult(
            name="Engagement Type",
            passed=False,
            severity=CheckSeverity.WARNING,
            message=f"Unknown engagement type: {eng_type}",
            details=[f"Valid types: {', '.join(valid_types)}"]
        )

    return CheckResult(
        name="Engagement Type",
        passed=True,
        severity=CheckSeverity.INFO,
        message=f"Engagement type: {eng_type}"
    )
