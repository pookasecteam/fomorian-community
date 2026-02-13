"""
Pydantic models for configuration validation.

These models define the schema for environment, attack path,
engagement, and timing configurations.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, field_validator, model_validator
import ipaddress
import re


class OSType(str, Enum):
    """Supported operating system types."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class HostRole(str, Enum):
    """Common host roles in an enterprise environment."""
    WORKSTATION = "workstation"
    DOMAIN_CONTROLLER = "domain_controller"
    FILE_SERVER = "file_server"
    WEB_SERVER = "web_server"
    DATABASE_SERVER = "database_server"
    MAIL_SERVER = "mail_server"
    BACKUP_SERVER = "backup_server"
    GENERIC = "generic"


class EngagementType(str, Enum):
    """Supported engagement types (attack objectives)."""
    RANSOMWARE = "ransomware"
    EXFILTRATION = "exfiltration"
    PERSISTENT_C2 = "persistent_c2"
    INSIDER_THREAT = "insider_threat"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"


class TimingMode(str, Enum):
    """Timing modes for scenario generation."""
    REALISTIC = "realistic"
    COMPRESSED = "compressed"
    CUSTOM = "custom"


class KillChainPhase(str, Enum):
    """MITRE ATT&CK kill chain phases."""
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


# ============================================================
# Host and User Configuration
# ============================================================

class HostConfig(BaseModel):
    """Configuration for a single host in the environment."""

    hostname: str = Field(..., description="Fully qualified domain name")
    short_name: str = Field(..., description="Short hostname for references")
    ip: str = Field(..., description="IP address")
    os: OSType = Field(default=OSType.WINDOWS, description="Operating system")
    agent_id: Optional[str] = Field(None, description="SIEM agent ID if applicable")
    agent_name: Optional[str] = Field(None, description="SIEM agent name")
    role: HostRole = Field(default=HostRole.WORKSTATION, description="Host role")
    users: List[str] = Field(default_factory=list, description="Users on this host")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @model_validator(mode="after")
    def set_agent_name(self):
        """Default agent_name to short_name if not set."""
        if self.agent_name is None:
            self.agent_name = self.short_name
        return self


class UserConfig(BaseModel):
    """Configuration for a user account."""

    username: str = Field(..., description="Username (sAMAccountName)")
    display_name: Optional[str] = Field(None, description="Display name")
    groups: List[str] = Field(default_factory=list, description="Group memberships")
    is_admin: bool = Field(default=False, description="Has admin privileges")
    email: Optional[str] = Field(None, description="Email address")

    @model_validator(mode="after")
    def check_admin_status(self):
        """Auto-detect admin status from groups."""
        admin_groups = ["Domain Admins", "Administrators", "Enterprise Admins", "root", "sudo", "wheel"]
        if any(g in self.groups for g in admin_groups):
            self.is_admin = True
        return self


class NetworkConfig(BaseModel):
    """Network configuration for the environment."""

    internal: str = Field(..., description="Internal network CIDR")
    dmz: Optional[str] = Field(None, description="DMZ network CIDR")
    management: Optional[str] = Field(None, description="Management network CIDR")

    @field_validator("internal", "dmz", "management", mode="before")
    @classmethod
    def validate_cidr(cls, v: Optional[str]) -> Optional[str]:
        """Validate CIDR notation."""
        if v is None:
            return v
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR notation: {v}")
        return v


class C2Config(BaseModel):
    """Command and Control infrastructure configuration."""

    ip: str = Field(..., description="C2 server IP address")
    domain: Optional[str] = Field(None, description="C2 domain name")
    port: int = Field(default=443, description="C2 port")
    protocol: str = Field(default="https", description="C2 protocol")
    beacon_interval: int = Field(default=60, description="Beacon interval in seconds")
    jitter: float = Field(default=0.2, description="Beacon jitter (0.0-1.0)")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid C2 IP address: {v}")
        return v

    @field_validator("jitter")
    @classmethod
    def validate_jitter(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("Jitter must be between 0.0 and 1.0")
        return v


# ============================================================
# Environment Configuration (Main)
# ============================================================

class EnvironmentConfig(BaseModel):
    """
    Complete environment configuration.

    This is the main configuration that defines the target environment
    including hosts, users, network topology, and C2 infrastructure.
    """

    name: str = Field(..., description="Environment name (e.g., 'acme-corp')")
    domain: str = Field(..., description="Active Directory domain name")
    network: NetworkConfig = Field(..., description="Network configuration")
    hosts: List[HostConfig] = Field(..., description="Host definitions")
    users: List[UserConfig] = Field(default_factory=list, description="User accounts")
    c2: Optional[C2Config] = Field(None, description="C2 infrastructure")

    def get_host(self, short_name: str) -> Optional[HostConfig]:
        """Get host by short name."""
        for host in self.hosts:
            if host.short_name == short_name:
                return host
        return None

    def get_user(self, username: str) -> Optional[UserConfig]:
        """Get user by username."""
        for user in self.users:
            if user.username == username:
                return user
        return None

    def get_hosts_by_role(self, role: HostRole) -> List[HostConfig]:
        """Get all hosts with a specific role."""
        return [h for h in self.hosts if h.role == role]

    def get_admin_users(self) -> List[UserConfig]:
        """Get all admin users."""
        return [u for u in self.users if u.is_admin]


# ============================================================
# Attack Path Configuration
# ============================================================

class PathStep(BaseModel):
    """A single step in the attack path."""

    host: str = Field(..., description="Target host short name")
    pivot_from: Optional[str] = Field(None, description="Source host for lateral movement")
    role: str = Field(default="target", description="Role in attack (initial_compromise, pivot, target)")
    techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    dwell_time: Optional[str] = Field(None, description="Time to spend on this host (e.g., '2h', '1d')")

    @field_validator("techniques")
    @classmethod
    def validate_techniques(cls, v: List[str]) -> List[str]:
        """Validate MITRE ATT&CK technique ID format."""
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tech in v:
            if not pattern.match(tech):
                raise ValueError(f"Invalid MITRE ATT&CK technique ID: {tech}")
        return v


class AttackPathConfig(BaseModel):
    """
    Attack path configuration defining lateral movement sequence.

    The attack path defines the order of hosts the attacker will
    compromise and the techniques used at each step.
    """

    name: str = Field(..., description="Attack path name")
    description: Optional[str] = Field(None, description="Attack path description")
    entry_point: str = Field(..., description="Initial compromise host")
    path: List[PathStep] = Field(..., description="Ordered attack steps")

    @model_validator(mode="after")
    def validate_path_consistency(self):
        """Ensure entry point matches first path step."""
        if self.path and self.path[0].host != self.entry_point:
            raise ValueError(
                f"Entry point '{self.entry_point}' does not match first path step '{self.path[0].host}'"
            )
        return self

    def get_hosts_in_order(self) -> List[str]:
        """Get list of hosts in attack order."""
        return [step.host for step in self.path]


# ============================================================
# Engagement Configuration
# ============================================================

class RansomwareConfig(BaseModel):
    """Ransomware-specific engagement configuration."""

    encryption_extension: str = Field(default=".encrypted", description="File extension for encrypted files")
    ransom_note: str = Field(default="README_RESTORE.txt", description="Ransom note filename")
    shadow_delete: bool = Field(default=True, description="Delete shadow copies")
    recovery_disable: bool = Field(default=True, description="Disable recovery options")
    target_extensions: List[str] = Field(
        default=[".docx", ".xlsx", ".pdf", ".jpg", ".png", ".sql", ".mdb"],
        description="File extensions to encrypt"
    )


class ExfiltrationConfig(BaseModel):
    """Data exfiltration engagement configuration."""

    staging_directory: str = Field(
        default="C:\\Users\\Public\\staging",
        description="Directory for staging data"
    )
    archive_password: Optional[str] = Field(None, description="Password for archive")
    exfil_method: str = Field(default="https", description="Exfiltration method")
    target_paths: List[str] = Field(
        default_factory=list,
        description="Paths to target for exfiltration"
    )
    max_file_size_mb: int = Field(default=100, description="Max file size to exfil")


class PersistentC2Config(BaseModel):
    """Persistent C2/APT engagement configuration."""

    beacon_interval_min: int = Field(default=60, description="Min beacon interval (seconds)")
    beacon_interval_max: int = Field(default=300, description="Max beacon interval (seconds)")
    persistence_methods: List[str] = Field(
        default=["registry_run_key", "scheduled_task"],
        description="Persistence mechanisms to use"
    )
    check_in_schedule: str = Field(
        default="working_hours",
        description="When to check in (working_hours, always, random)"
    )


class InsiderThreatConfig(BaseModel):
    """Insider threat engagement configuration."""

    actor_username: str = Field(..., description="Insider's username")
    after_hours: bool = Field(default=True, description="Activity occurs after hours")
    target_shares: List[str] = Field(
        default_factory=list,
        description="Network shares to target"
    )
    exfil_method: str = Field(default="usb", description="Exfiltration method (usb, email, cloud)")


class BECConfig(BaseModel):
    """Business Email Compromise engagement configuration."""

    target_email: str = Field(default="cfo@company.com", description="Target executive email")
    impersonated_email: str = Field(default="ceo@company.com", description="Email to impersonate")
    oauth_app_name: str = Field(default="Microsoft Security", description="Malicious OAuth app name")
    forwarding_address: str = Field(default="attacker@external.com", description="Email forward destination")
    target_mailboxes: List[str] = Field(
        default_factory=list,
        description="Mailboxes to access"
    )
    search_keywords: List[str] = Field(
        default=["wire transfer", "payment", "invoice", "bank account", "routing number"],
        description="Keywords to search in emails"
    )


class EngagementConfig(BaseModel):
    """
    Engagement configuration defining attack objectives.

    The engagement type determines the overall goal of the attack
    and which kill chain phases will be included.
    """

    type: EngagementType = Field(..., description="Engagement type")
    name: Optional[str] = Field(None, description="Custom engagement name")
    phases: List[KillChainPhase] = Field(default_factory=list, description="Kill chain phases to include")

    # Type-specific configurations
    ransomware: Optional[RansomwareConfig] = Field(None)
    exfiltration: Optional[ExfiltrationConfig] = Field(None)
    persistent_c2: Optional[PersistentC2Config] = Field(None)
    insider_threat: Optional[InsiderThreatConfig] = Field(None)
    bec: Optional[BECConfig] = Field(None)

    @model_validator(mode="after")
    def set_default_phases(self):
        """Set default phases based on engagement type if not specified."""
        if not self.phases:
            phase_map = {
                EngagementType.RANSOMWARE: [
                    KillChainPhase.INITIAL_ACCESS,
                    KillChainPhase.EXECUTION,
                    KillChainPhase.PERSISTENCE,
                    KillChainPhase.PRIVILEGE_ESCALATION,
                    KillChainPhase.DEFENSE_EVASION,
                    KillChainPhase.CREDENTIAL_ACCESS,
                    KillChainPhase.LATERAL_MOVEMENT,
                    KillChainPhase.IMPACT,
                ],
                EngagementType.EXFILTRATION: [
                    KillChainPhase.INITIAL_ACCESS,
                    KillChainPhase.EXECUTION,
                    KillChainPhase.DISCOVERY,
                    KillChainPhase.COLLECTION,
                    KillChainPhase.COMMAND_AND_CONTROL,
                    KillChainPhase.EXFILTRATION,
                ],
                EngagementType.PERSISTENT_C2: [
                    KillChainPhase.INITIAL_ACCESS,
                    KillChainPhase.EXECUTION,
                    KillChainPhase.PERSISTENCE,
                    KillChainPhase.DEFENSE_EVASION,
                    KillChainPhase.DISCOVERY,
                    KillChainPhase.CREDENTIAL_ACCESS,
                    KillChainPhase.LATERAL_MOVEMENT,
                    KillChainPhase.COMMAND_AND_CONTROL,
                ],
                EngagementType.INSIDER_THREAT: [
                    KillChainPhase.DISCOVERY,
                    KillChainPhase.COLLECTION,
                    KillChainPhase.EXFILTRATION,
                ],
                EngagementType.BUSINESS_EMAIL_COMPROMISE: [
                    KillChainPhase.INITIAL_ACCESS,
                    KillChainPhase.PERSISTENCE,
                    KillChainPhase.DISCOVERY,
                    KillChainPhase.COLLECTION,
                    KillChainPhase.DEFENSE_EVASION,
                    KillChainPhase.EXFILTRATION,
                ],
            }
            self.phases = phase_map.get(self.type, [])
        return self


# ============================================================
# Timing Configuration
# ============================================================

class PhaseDelays(BaseModel):
    """Delays between attack phases (for realistic timing)."""

    initial_to_execution: str = Field(default="5s-30s")
    execution_to_persistence: str = Field(default="1m-5m")
    persistence_to_discovery: str = Field(default="5m-30m")
    discovery_to_lateral: str = Field(default="30m-2h")
    lateral_to_collection: str = Field(default="1h-4h")
    collection_to_exfil: str = Field(default="30m-2h")

    def get_delay(self, from_phase: str, to_phase: str) -> str:
        """Get delay between two phases."""
        key = f"{from_phase}_to_{to_phase}".replace("-", "_")
        return getattr(self, key, "1m-5m")


class TimingConfig(BaseModel):
    """
    Timing configuration for scenario generation.

    Controls how timestamps are generated, including support
    for multi-day scenarios with realistic dwell times.
    """

    mode: TimingMode = Field(default=TimingMode.REALISTIC, description="Timing mode")
    base_timestamp: Optional[datetime] = Field(None, description="Starting timestamp")
    duration: Optional[str] = Field(None, description="Total duration (e.g., '4h', '7d')")
    working_hours_start: str = Field(default="08:00", description="Working hours start")
    working_hours_end: str = Field(default="18:00", description="Working hours end")
    timezone: str = Field(default="UTC", description="Timezone")
    phase_delays: PhaseDelays = Field(default_factory=PhaseDelays)
    inter_event_delay: str = Field(default="1s-10s", description="Delay between events")

    def parse_duration(self, duration_str: str) -> timedelta:
        """Parse duration string to timedelta."""
        pattern = re.compile(r"(\d+)(s|m|h|d|w)")
        match = pattern.match(duration_str)
        if not match:
            raise ValueError(f"Invalid duration format: {duration_str}")

        value = int(match.group(1))
        unit = match.group(2)

        unit_map = {
            "s": timedelta(seconds=value),
            "m": timedelta(minutes=value),
            "h": timedelta(hours=value),
            "d": timedelta(days=value),
            "w": timedelta(weeks=value),
        }
        return unit_map[unit]
