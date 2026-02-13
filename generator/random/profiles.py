"""
Complexity Profiles

Defines simple, medium, and complex scenario profiles.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple, Union


class Complexity(str, Enum):
    """Complexity levels for random scenarios."""
    SIMPLE = "simple"
    MEDIUM = "medium"
    COMPLEX = "complex"


@dataclass
class ComplexityProfile:
    """Defines parameters for a complexity level."""
    name: str
    description: str

    # Host counts
    min_hosts: int
    max_hosts: int
    require_dc: bool

    # User counts
    min_users: int
    max_users: int
    min_admins: int

    # Attack path
    min_phases: int
    max_phases: int
    min_techniques: int
    max_techniques: int

    # Timing
    min_duration_hours: float
    max_duration_hours: float
    dwell_time_minutes: Tuple[int, int]  # min, max

    # Engagement types available
    engagement_types: List[str]


# Pre-defined profiles
PROFILES: Dict[Complexity, ComplexityProfile] = {
    Complexity.SIMPLE: ComplexityProfile(
        name="Simple",
        description="Quick test scenario with minimal configuration",
        min_hosts=1,
        max_hosts=2,
        require_dc=False,
        min_users=1,
        max_users=2,
        min_admins=0,
        min_phases=2,
        max_phases=3,
        min_techniques=2,
        max_techniques=5,
        min_duration_hours=0.5,
        max_duration_hours=2.0,
        dwell_time_minutes=(5, 15),
        engagement_types=["ransomware", "insider_threat"],
    ),

    Complexity.MEDIUM: ComplexityProfile(
        name="Medium",
        description="Realistic scenario with standard kill chain",
        min_hosts=2,
        max_hosts=4,
        require_dc=True,
        min_users=2,
        max_users=4,
        min_admins=1,
        min_phases=4,
        max_phases=6,
        min_techniques=5,
        max_techniques=15,
        min_duration_hours=2.0,
        max_duration_hours=8.0,
        dwell_time_minutes=(10, 60),
        engagement_types=["ransomware", "exfiltration", "persistent_c2", "insider_threat"],
    ),

    Complexity.COMPLEX: ComplexityProfile(
        name="Complex",
        description="Full enterprise attack with complete kill chain",
        min_hosts=4,
        max_hosts=8,
        require_dc=True,
        min_users=4,
        max_users=8,
        min_admins=2,
        min_phases=6,
        max_phases=10,
        min_techniques=15,
        max_techniques=30,
        min_duration_hours=8.0,
        max_duration_hours=48.0,
        dwell_time_minutes=(30, 240),
        engagement_types=[
            "ransomware",
            "exfiltration",
            "persistent_c2",
            "insider_threat",
            "destructive_attack",
            "account_takeover",
            "business_email_compromise",
        ],
    ),
}


def get_profile(complexity: Union[Complexity, str]) -> ComplexityProfile:
    """
    Get complexity profile by name or enum.

    Args:
        complexity: Complexity level

    Returns:
        ComplexityProfile for the specified level
    """
    if isinstance(complexity, str):
        complexity = Complexity(complexity.lower())

    return PROFILES[complexity]


# Kill chain phases with associated techniques
KILL_CHAIN_PHASES = {
    "initial_access": {
        "name": "Initial Access",
        "techniques": [
            "T1566.001",  # Spearphishing Attachment
            "T1566.002",  # Spearphishing Link
            "T1078",      # Valid Accounts
            "T1190",      # Exploit Public-Facing App
            "T1133",      # External Remote Services
        ],
    },
    "execution": {
        "name": "Execution",
        "techniques": [
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1059.005",  # VBScript
            "T1204.002",  # User Execution: Malicious File
            "T1047",      # WMI
            "T1053.005",  # Scheduled Task
        ],
    },
    "persistence": {
        "name": "Persistence",
        "techniques": [
            "T1547.001",  # Registry Run Keys
            "T1053.005",  # Scheduled Task
            "T1543.003",  # Windows Service
            "T1546.001",  # Change Default File Association
            "T1136.001",  # Create Account: Local Account
        ],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "techniques": [
            "T1548.002",  # UAC Bypass
            "T1134.001",  # Token Impersonation
            "T1055",      # Process Injection
            "T1068",      # Exploitation for Privilege Escalation
        ],
    },
    "defense_evasion": {
        "name": "Defense Evasion",
        "techniques": [
            "T1562.001",  # Disable or Modify Tools
            "T1070.001",  # Clear Windows Event Logs
            "T1027",      # Obfuscated Files
            "T1036",      # Masquerading
            "T1140",      # Deobfuscate/Decode Files
        ],
    },
    "credential_access": {
        "name": "Credential Access",
        "techniques": [
            "T1003.001",  # LSASS Memory
            "T1003.006",  # DCSync
            "T1558.003",  # Kerberoasting
            "T1552.001",  # Credentials in Files
            "T1110.003",  # Password Spraying
        ],
    },
    "discovery": {
        "name": "Discovery",
        "techniques": [
            "T1087.001",  # Local Account Discovery
            "T1087.002",  # Domain Account Discovery
            "T1082",      # System Information Discovery
            "T1083",      # File and Directory Discovery
            "T1018",      # Remote System Discovery
            "T1016",      # System Network Configuration
        ],
    },
    "lateral_movement": {
        "name": "Lateral Movement",
        "techniques": [
            "T1021.002",  # SMB/Windows Admin Shares
            "T1021.001",  # Remote Desktop Protocol
            "T1021.006",  # Windows Remote Management
            "T1570",      # Lateral Tool Transfer
        ],
    },
    "collection": {
        "name": "Collection",
        "techniques": [
            "T1074.001",  # Local Data Staging
            "T1560.001",  # Archive via Utility
            "T1005",      # Data from Local System
            "T1114",      # Email Collection
        ],
    },
    "exfiltration": {
        "name": "Exfiltration",
        "techniques": [
            "T1567",      # Exfiltration Over Web Service
            "T1048",      # Exfiltration Over Alternative Protocol
            "T1041",      # Exfiltration Over C2 Channel
        ],
    },
    "impact": {
        "name": "Impact",
        "techniques": [
            "T1486",      # Data Encrypted for Impact
            "T1490",      # Inhibit System Recovery
            "T1489",      # Service Stop
            "T1485",      # Data Destruction
            "T1561.002",  # Disk Structure Wipe
        ],
    },
}


# Standard attack paths by engagement type
STANDARD_PATHS = {
    "ransomware": [
        "initial_access",
        "execution",
        "discovery",
        "credential_access",
        "lateral_movement",
        "defense_evasion",
        "impact",
    ],
    "exfiltration": [
        "initial_access",
        "execution",
        "discovery",
        "credential_access",
        "lateral_movement",
        "collection",
        "exfiltration",
    ],
    "persistent_c2": [
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "discovery",
        "credential_access",
    ],
    "insider_threat": [
        "discovery",
        "collection",
        "exfiltration",
    ],
    "destructive_attack": [
        "initial_access",
        "execution",
        "discovery",
        "lateral_movement",
        "persistence",
        "defense_evasion",
        "impact",
    ],
    "account_takeover": [
        "initial_access",
        "credential_access",
        "persistence",
        "discovery",
        "collection",
        "exfiltration",
    ],
    "business_email_compromise": [
        "initial_access",
        "credential_access",
        "collection",
        "exfiltration",
    ],
}
