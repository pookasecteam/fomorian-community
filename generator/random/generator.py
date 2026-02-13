"""
Random Scenario Generator

Generates complete random attack scenarios.
"""

import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

from .profiles import (
    Complexity,
    ComplexityProfile,
    get_profile,
    KILL_CHAIN_PHASES,
    STANDARD_PATHS,
)
from .names import NameGenerator


class RandomScenarioGenerator:
    """
    Generates randomized attack scenarios.

    Creates complete scenarios with environment, hosts, users,
    attack path, and engagement configuration.
    """

    def __init__(
        self,
        complexity: Union[Complexity, str] = Complexity.MEDIUM,
        seed: Optional[int] = None,
    ):
        """
        Initialize the generator.

        Args:
            complexity: Scenario complexity level
            seed: Random seed for reproducibility
        """
        if isinstance(complexity, str):
            complexity = Complexity(complexity.lower())

        self.complexity = complexity
        self.profile = get_profile(complexity)
        self.seed = seed
        self.rng = random.Random(seed)
        self.names = NameGenerator(seed)

    def generate(
        self,
        engagement_type: Optional[str] = None,
        duration: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a complete random scenario.

        Args:
            engagement_type: Specific engagement type, or None for random
            duration: Duration override (e.g., "4h", "1d")

        Returns:
            Complete scenario configuration dictionary
        """
        # Select engagement type
        if engagement_type and engagement_type != "random":
            eng_type = engagement_type
        else:
            eng_type = self.rng.choice(self.profile.engagement_types)

        # Generate environment
        environment = self._generate_environment()

        # Generate hosts
        num_hosts = self.rng.randint(self.profile.min_hosts, self.profile.max_hosts)
        hosts = self.names.generate_hosts(
            count=num_hosts,
            include_dc=self.profile.require_dc
        )

        # Generate users
        num_users = self.rng.randint(self.profile.min_users, self.profile.max_users)
        num_admins = max(self.profile.min_admins, num_users // 4)
        users = self.names.generate_users(
            count=num_users,
            include_admins=num_admins
        )

        # Assign users to hosts
        self._assign_users_to_hosts(hosts, users)

        # Generate C2
        c2 = self._generate_c2()

        # Generate attack path
        attack_path = self._generate_attack_path(hosts, eng_type)

        # Generate engagement config
        engagement = self._generate_engagement(eng_type)

        # Generate timing
        timing = self._generate_timing(duration)

        return {
            "environment": environment,
            "hosts": hosts,
            "users": users,
            "c2": c2,
            "attack_path": attack_path,
            "engagement": engagement,
            "params": timing,
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "complexity": self.complexity.value,
                "seed": self.seed,
                "engagement_type": eng_type,
            },
        }

    def _generate_environment(self) -> Dict[str, Any]:
        """Generate environment configuration."""
        domain = self.names.generate_domain()
        org_name = self.names.generate_organization()

        return {
            "name": f"{org_name.lower().replace(' ', '-')}-lab",
            "domain": domain,
            "network": {
                "internal": "10.0.0.0/24",
            },
        }

    def _generate_c2(self) -> Dict[str, Any]:
        """Generate C2 configuration."""
        return {
            "ip": self.names.generate_c2_ip(),
            "domain": self.names.generate_c2_domain(),
            "port": self.rng.choice([80, 443, 8080, 8443]),
            "protocol": self.rng.choice(["http", "https"]),
            "beacon_interval": self.rng.choice([30, 60, 120, 300]),
            "jitter": round(self.rng.uniform(0.1, 0.3), 2),
        }

    def _assign_users_to_hosts(self, hosts: List[Dict], users: List[Dict]) -> None:
        """Assign users to hosts."""
        # First host (workstation) gets the first regular user
        regular_users = [u for u in users if not u.get("is_admin")]
        admin_users = [u for u in users if u.get("is_admin")]

        if regular_users and hosts:
            hosts[0]["users"] = [regular_users[0]["username"]]

        # DC gets admin users
        for host in hosts:
            if host.get("role") == "domain_controller" and admin_users:
                host["users"] = [admin_users[0]["username"]]

        # Distribute remaining users
        remaining_users = regular_users[1:] if len(regular_users) > 1 else []
        for i, user in enumerate(remaining_users):
            host_idx = (i + 1) % len(hosts)
            if user["username"] not in hosts[host_idx].get("users", []):
                hosts[host_idx]["users"] = hosts[host_idx].get("users", []) + [user["username"]]

    def _generate_attack_path(
        self,
        hosts: List[Dict],
        engagement_type: str
    ) -> Dict[str, Any]:
        """Generate attack path configuration."""
        # Get standard path for engagement type
        standard_phases = STANDARD_PATHS.get(
            engagement_type,
            STANDARD_PATHS["ransomware"]
        )

        # Limit phases based on profile
        num_phases = self.rng.randint(
            self.profile.min_phases,
            min(self.profile.max_phases, len(standard_phases))
        )
        phases = standard_phases[:num_phases]

        # Find entry point (first workstation)
        workstations = [h for h in hosts if h.get("role") == "workstation"]
        entry_point = workstations[0]["short_name"] if workstations else hosts[0]["short_name"]

        # Build path steps
        path = []
        current_host = entry_point
        hosts_by_role = self._group_hosts_by_role(hosts)

        for i, phase in enumerate(phases):
            phase_info = KILL_CHAIN_PHASES.get(phase, {})

            # Select techniques
            available_techniques = phase_info.get("techniques", ["T1059.001"])
            num_techniques = self.rng.randint(
                1,
                min(self.profile.max_techniques // num_phases, len(available_techniques))
            )
            techniques = self.rng.sample(
                available_techniques,
                min(num_techniques, len(available_techniques))
            )

            # Determine host for this phase
            if phase == "initial_access":
                host = entry_point
            elif phase == "lateral_movement" and "domain_controller" in hosts_by_role:
                # Pivot to DC
                host = hosts_by_role["domain_controller"][0]["short_name"]
            elif phase in ("collection", "exfiltration", "impact") and "file_server" in hosts_by_role:
                # Target file server for data
                host = hosts_by_role["file_server"][0]["short_name"]
            else:
                host = current_host

            # Dwell time
            dwell_min, dwell_max = self.profile.dwell_time_minutes
            dwell_time = self.rng.randint(dwell_min, dwell_max)

            step = {
                "host": host,
                "role": phase,
                "techniques": techniques,
                "dwell_time": f"{dwell_time}m",
            }

            # Add pivot if host changed
            if host != current_host:
                step["pivot_from"] = current_host

            path.append(step)
            current_host = host

        return {
            "name": f"Random {engagement_type.replace('_', ' ').title()} Path",
            "description": f"Auto-generated {self.complexity.value} complexity path",
            "entry_point": entry_point,
            "path": path,
        }

    def _group_hosts_by_role(self, hosts: List[Dict]) -> Dict[str, List[Dict]]:
        """Group hosts by their role."""
        groups: Dict[str, List[Dict]] = {}
        for host in hosts:
            role = host.get("role", "generic")
            if role not in groups:
                groups[role] = []
            groups[role].append(host)
        return groups

    def _generate_engagement(self, engagement_type: str) -> Dict[str, Any]:
        """Generate engagement configuration."""
        config: Dict[str, Any] = {"type": engagement_type}

        if engagement_type == "ransomware":
            config["ransomware"] = {
                "encryption_extension": self.rng.choice([".encrypted", ".locked", ".crypt"]),
                "shadow_delete": True,
                "target_extensions": [".docx", ".xlsx", ".pdf", ".pptx", ".txt"],
            }
        elif engagement_type == "exfiltration":
            config["exfiltration"] = {
                "staging_path": "C:\\Users\\Public\\Documents",
                "method": self.rng.choice(["https", "dns", "cloud"]),
                "compress": True,
            }
        elif engagement_type == "persistent_c2":
            config["persistent_c2"] = {
                "persistence_method": self.rng.choice([
                    "registry_run", "scheduled_task", "service"
                ]),
                "beacon_type": "https",
            }
        elif engagement_type == "destructive_attack":
            config["destructive"] = {
                "targets": "both",
                "trigger": "scheduled",
            }

        return config

    def _generate_timing(self, duration: Optional[str] = None) -> Dict[str, Any]:
        """Generate timing configuration."""
        if duration:
            total_duration = duration
        else:
            hours = self.rng.uniform(
                self.profile.min_duration_hours,
                self.profile.max_duration_hours
            )
            if hours >= 24:
                total_duration = f"{int(hours // 24)}d"
            else:
                total_duration = f"{int(hours)}h"

        return {
            "mode": "realistic",
            "total_duration": total_duration,
            "start_time": "now",
            "noise_ratio": 0,
            "business_hours_only": False,
            "default_interval": "30s",
            "jitter": 0.3,
        }

    @staticmethod
    def get_available_complexities() -> List[str]:
        """Get list of available complexity levels."""
        return [c.value for c in Complexity]

    @staticmethod
    def get_available_engagements() -> List[str]:
        """Get list of available engagement types."""
        return list(STANDARD_PATHS.keys())
