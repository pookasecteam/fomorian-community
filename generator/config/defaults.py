"""
Default configuration values and templates.

Provides sensible defaults for quick setup and template generation.
"""

from typing import Dict, Any


def get_default_environment() -> Dict[str, Any]:
    """Get default environment configuration template."""
    return {
        "name": "example-corp",
        "domain": "example.local",
        "network": {
            "internal": "10.1.1.0/24",
            "dmz": "10.2.1.0/24",
        },
        "hosts": [
            {
                "hostname": "WORKSTATION01.example.local",
                "short_name": "WS01",
                "ip": "10.1.1.50",
                "os": "windows",
                "agent_id": "007",
                "role": "workstation",
                "users": ["jsmith", "mjones"],
            },
            {
                "hostname": "DC01.example.local",
                "short_name": "DC01",
                "ip": "10.1.1.10",
                "os": "windows",
                "agent_id": "003",
                "role": "domain_controller",
                "users": [],
            },
            {
                "hostname": "FILESERVER01.example.local",
                "short_name": "FS01",
                "ip": "10.1.1.20",
                "os": "windows",
                "agent_id": "004",
                "role": "file_server",
                "users": [],
            },
        ],
        "users": [
            {
                "username": "jsmith",
                "display_name": "John Smith",
                "groups": ["Domain Users", "IT Support"],
                "email": "jsmith@example.local",
            },
            {
                "username": "mjones",
                "display_name": "Mary Jones",
                "groups": ["Domain Users", "Finance"],
                "email": "mjones@example.local",
            },
            {
                "username": "admin.svc",
                "display_name": "Admin Service Account",
                "groups": ["Domain Admins"],
            },
        ],
        "c2": {
            "ip": "203.0.113.50",
            "domain": "update-cdn.example.com",
            "port": 443,
            "protocol": "https",
            "beacon_interval": 60,
            "jitter": 0.2,
        },
    }


def get_default_attack_path() -> Dict[str, Any]:
    """Get default attack path configuration template."""
    return {
        "name": "Workstation to Domain Controller",
        "description": "Classic lateral movement from initial workstation compromise to DC",
        "entry_point": "WS01",
        "path": [
            {
                "host": "WS01",
                "role": "initial_compromise",
                "techniques": ["T1566.001", "T1059.001"],
                "dwell_time": "30m",
            },
            {
                "host": "DC01",
                "pivot_from": "WS01",
                "role": "pivot",
                "techniques": ["T1021.002", "T1003.006"],
                "dwell_time": "2h",
            },
            {
                "host": "FS01",
                "pivot_from": "DC01",
                "role": "target",
                "techniques": ["T1039", "T1560.001"],
                "dwell_time": "1h",
            },
        ],
    }


def get_default_engagement(engagement_type: str) -> Dict[str, Any]:
    """Get default engagement configuration for a specific type."""
    engagements = {
        "ransomware": {
            "type": "ransomware",
            "name": "Ransomware Attack Simulation",
            "ransomware": {
                "encryption_extension": ".encrypted",
                "ransom_note": "README_RESTORE.txt",
                "shadow_delete": True,
                "recovery_disable": True,
                "target_extensions": [".docx", ".xlsx", ".pdf", ".jpg", ".png", ".sql"],
            },
        },
        "exfiltration": {
            "type": "exfiltration",
            "name": "Data Exfiltration Simulation",
            "exfiltration": {
                "staging_directory": "C:\\Users\\Public\\staging",
                "archive_password": "exfil2026",
                "exfil_method": "https",
                "target_paths": [
                    "\\\\FILESERVER01\\Confidential",
                    "C:\\Users\\*\\Documents\\*",
                ],
                "max_file_size_mb": 100,
            },
        },
        "persistent_c2": {
            "type": "persistent_c2",
            "name": "APT Persistent Access Simulation",
            "persistent_c2": {
                "beacon_interval_min": 60,
                "beacon_interval_max": 300,
                "persistence_methods": ["registry_run_key", "scheduled_task", "wmi_subscription"],
                "check_in_schedule": "working_hours",
            },
        },
        "insider_threat": {
            "type": "insider_threat",
            "name": "Insider Threat Simulation",
            "insider_threat": {
                "actor_username": "departing_employee",
                "after_hours": True,
                "target_shares": ["HR", "Finance", "Confidential"],
                "exfil_method": "usb",
            },
        },
    }
    return engagements.get(engagement_type, engagements["ransomware"])


def get_default_timing(mode: str = "realistic") -> Dict[str, Any]:
    """Get default timing configuration."""
    timing_configs = {
        "realistic": {
            "mode": "realistic",
            "working_hours_start": "08:00",
            "working_hours_end": "18:00",
            "timezone": "America/New_York",
            "phase_delays": {
                "initial_to_execution": "5s-30s",
                "execution_to_persistence": "1m-5m",
                "persistence_to_discovery": "5m-30m",
                "discovery_to_lateral": "30m-2h",
                "lateral_to_collection": "1h-4h",
                "collection_to_exfil": "30m-2h",
            },
            "inter_event_delay": "1s-10s",
        },
        "compressed": {
            "mode": "compressed",
            "duration": "10m",
            "inter_event_delay": "500ms-2s",
        },
        "custom": {
            "mode": "custom",
            "base_timestamp": None,  # Will be set at runtime
            "inter_event_delay": "1s-5s",
        },
    }
    return timing_configs.get(mode, timing_configs["realistic"])


# Profile templates for different environments
PROFILE_TEMPLATES = {
    "enterprise": {
        "description": "Large enterprise with AD, multiple workstations, servers",
        "environment": get_default_environment(),
        "attack_path": get_default_attack_path(),
        "timing": get_default_timing("realistic"),
    },
    "small_business": {
        "description": "Small business with limited infrastructure",
        "environment": {
            "name": "smallbiz",
            "domain": "smallbiz.local",
            "network": {"internal": "192.168.1.0/24"},
            "hosts": [
                {
                    "hostname": "PC01.smallbiz.local",
                    "short_name": "PC01",
                    "ip": "192.168.1.10",
                    "os": "windows",
                    "agent_id": "001",
                    "role": "workstation",
                    "users": ["owner", "employee1"],
                },
                {
                    "hostname": "SERVER01.smallbiz.local",
                    "short_name": "SRV01",
                    "ip": "192.168.1.5",
                    "os": "windows",
                    "agent_id": "002",
                    "role": "file_server",
                },
            ],
            "users": [
                {"username": "owner", "display_name": "Business Owner", "groups": ["Administrators"]},
                {"username": "employee1", "display_name": "Employee One", "groups": ["Users"]},
            ],
            "c2": {"ip": "198.51.100.50", "domain": "cdn-updates.com", "port": 443},
        },
    },
    "cloud_hybrid": {
        "description": "Hybrid environment with Azure AD and on-prem",
        "environment": {
            "name": "hybrid-corp",
            "domain": "hybrid.onmicrosoft.com",
            "network": {"internal": "10.0.0.0/16", "dmz": "172.16.0.0/24"},
            "hosts": [
                {
                    "hostname": "AADCONNECT01.hybrid.local",
                    "short_name": "AADCONNECT",
                    "ip": "10.0.1.10",
                    "os": "windows",
                    "role": "generic",
                },
                {
                    "hostname": "WS-AZURE01",
                    "short_name": "WS-AZURE01",
                    "ip": "10.0.2.50",
                    "os": "windows",
                    "role": "workstation",
                    "users": ["clouduser@hybrid.onmicrosoft.com"],
                },
            ],
            "users": [
                {
                    "username": "clouduser@hybrid.onmicrosoft.com",
                    "display_name": "Cloud User",
                    "groups": ["Azure AD Users"],
                },
                {
                    "username": "admin@hybrid.onmicrosoft.com",
                    "display_name": "Global Admin",
                    "groups": ["Global Administrators"],
                },
            ],
        },
    },
}
