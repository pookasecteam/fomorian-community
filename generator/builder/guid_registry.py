"""
GUID Registry for process correlation across attack scenarios.

Manages ProcessGUID generation and parent-child relationships
to ensure proper process tree correlation across multi-host attacks.
"""

import secrets
from typing import Dict, Optional, List
from dataclasses import dataclass, field


@dataclass
class ProcessInfo:
    """Information about a process in the scenario."""

    guid: str
    host: str
    image: str
    pid: int
    parent_guid: Optional[str] = None
    parent_pid: Optional[int] = None
    user: Optional[str] = None


class GuidRegistry:
    """
    Manages ProcessGUID generation and correlation.

    Ensures consistent GUID patterns across the scenario and maintains
    parent-child process relationships for realistic log generation.
    """

    def __init__(self, scenario_id: Optional[str] = None):
        """
        Initialize the GUID registry.

        Args:
            scenario_id: Optional scenario identifier for GUID prefix
        """
        self.scenario_id = scenario_id or self._generate_scenario_id()
        self._counter = 0
        self._processes: Dict[str, ProcessInfo] = {}
        self._host_processes: Dict[str, List[str]] = {}
        self._current_process: Dict[str, str] = {}  # host -> current process guid

    def _generate_scenario_id(self) -> str:
        """Generate a unique scenario identifier."""
        return secrets.token_hex(4).upper()

    def generate_guid(
        self,
        host: str,
        image: str = "unknown",
        parent_guid: Optional[str] = None,
        user: Optional[str] = None,
    ) -> str:
        """
        Generate a new ProcessGUID for a host.

        Args:
            host: Host short name (e.g., "WS01")
            image: Process image path
            parent_guid: Parent process GUID (if known)
            user: User running the process

        Returns:
            Generated ProcessGUID in Windows format
        """
        self._counter += 1

        # Generate GUID in Windows format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
        # We embed scenario ID and sequence for correlation
        guid = f"{{{self.scenario_id}-{host[:4].upper()}-{self._counter:04d}-{secrets.token_hex(6).upper()}}}"

        # Generate a realistic PID
        pid = 1000 + (self._counter * 100) + secrets.randbelow(99)

        # Get parent PID if parent exists
        parent_pid = None
        if parent_guid and parent_guid in self._processes:
            parent_pid = self._processes[parent_guid].pid

        # Store process info
        process_info = ProcessInfo(
            guid=guid,
            host=host,
            image=image,
            pid=pid,
            parent_guid=parent_guid,
            parent_pid=parent_pid,
            user=user,
        )
        self._processes[guid] = process_info

        # Track processes by host
        if host not in self._host_processes:
            self._host_processes[host] = []
        self._host_processes[host].append(guid)

        # Update current process for host
        self._current_process[host] = guid

        return guid

    def get_process(self, guid: str) -> Optional[ProcessInfo]:
        """Get process information by GUID."""
        return self._processes.get(guid)

    def get_parent_guid(self, guid: str) -> Optional[str]:
        """Get parent GUID for a process."""
        process = self._processes.get(guid)
        return process.parent_guid if process else None

    def get_pid(self, guid: str) -> Optional[int]:
        """Get PID for a process GUID."""
        process = self._processes.get(guid)
        return process.pid if process else None

    def get_parent_pid(self, guid: str) -> Optional[int]:
        """Get parent PID for a process GUID."""
        process = self._processes.get(guid)
        return process.parent_pid if process else None

    def get_current_process(self, host: str) -> Optional[str]:
        """Get the current (most recent) process GUID for a host."""
        return self._current_process.get(host)

    def get_host_processes(self, host: str) -> List[str]:
        """Get all process GUIDs for a host."""
        return self._host_processes.get(host, [])

    def create_child_process(
        self,
        host: str,
        image: str,
        parent_guid: Optional[str] = None,
        user: Optional[str] = None,
    ) -> str:
        """
        Create a child process of the current process on a host.

        Args:
            host: Host short name
            image: Child process image path
            parent_guid: Explicit parent GUID (defaults to current process)
            user: User running the process

        Returns:
            Generated child ProcessGUID
        """
        if parent_guid is None:
            parent_guid = self.get_current_process(host)

        return self.generate_guid(
            host=host,
            image=image,
            parent_guid=parent_guid,
            user=user,
        )

    def get_system_process_guid(self, host: str) -> str:
        """
        Get or create a system-level process GUID (e.g., services.exe parent).

        These are the root processes that spawn services on Windows.
        """
        system_key = f"_SYSTEM_{host}"
        if system_key not in self._processes:
            # Create a synthetic system process
            guid = f"{{SYSTEM-{host[:4].upper()}-0000-000000000000}}"
            self._processes[system_key] = ProcessInfo(
                guid=guid,
                host=host,
                image="System",
                pid=4,
                parent_guid=None,
                parent_pid=0,
                user="NT AUTHORITY\\SYSTEM",
            )
            self._processes[guid] = self._processes[system_key]
        return self._processes[system_key].guid

    def get_services_guid(self, host: str) -> str:
        """Get or create a services.exe GUID for a host."""
        services_key = f"_SERVICES_{host}"
        if services_key not in self._processes:
            system_guid = self.get_system_process_guid(host)
            guid = f"{{SERVICES-{host[:4].upper()}-0001-000000000000}}"
            self._processes[services_key] = ProcessInfo(
                guid=guid,
                host=host,
                image="C:\\Windows\\System32\\services.exe",
                pid=704,
                parent_guid=system_guid,
                parent_pid=4,
                user="NT AUTHORITY\\SYSTEM",
            )
            self._processes[guid] = self._processes[services_key]
        return self._processes[services_key].guid

    def get_statistics(self) -> Dict:
        """Get registry statistics."""
        return {
            "scenario_id": self.scenario_id,
            "total_processes": len(self._processes),
            "hosts": list(self._host_processes.keys()),
            "processes_by_host": {
                host: len(guids) for host, guids in self._host_processes.items()
            },
        }

    def get_process_tree(self, host: str) -> List[Dict]:
        """
        Get the process tree for a host.

        Returns:
            List of process dictionaries with parent relationships
        """
        tree = []
        for guid in self._host_processes.get(host, []):
            process = self._processes[guid]
            tree.append({
                "guid": process.guid,
                "pid": process.pid,
                "image": process.image,
                "parent_guid": process.parent_guid,
                "parent_pid": process.parent_pid,
                "user": process.user,
            })
        return tree
