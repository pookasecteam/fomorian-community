"""Wazuh-compatible injectors for automatic log ingestion.

This module provides injectors for Wazuh:
- wazuh: For direct injection into Wazuh Manager (alerts.json, archives.json, or API)
"""

from .base import SIEMInjector, InjectorConfig, LogEntry, InjectionResult
from .wazuh import WazuhInjector

INJECTORS = {
    "wazuh": WazuhInjector,
}


def get_injector(siem_type: str, config: InjectorConfig) -> SIEMInjector:
    """Get the appropriate injector for a SIEM type."""
    injector_class = INJECTORS.get(siem_type.lower())
    if not injector_class:
        supported = ", ".join(sorted(INJECTORS.keys()))
        raise ValueError(f"Unknown SIEM type: {siem_type}. Supported: {supported}")
    return injector_class(config)


def list_supported_siems() -> list:
    """List all supported SIEM types."""
    return sorted(set(INJECTORS.keys()))


__all__ = [
    "SIEMInjector",
    "InjectorConfig",
    "LogEntry",
    "InjectionResult",
    "WazuhInjector",
    "get_injector",
    "list_supported_siems",
]
