"""
Wazuh Integration Module

Provides auto-detection, connection management, and validation
for Wazuh Manager integration.
"""

from .detector import WazuhDetector, WazuhInstallation
from .connector import WazuhConnector
from .validator import WazuhValidator

__all__ = [
    "WazuhDetector",
    "WazuhInstallation",
    "WazuhConnector",
    "WazuhValidator",
]
