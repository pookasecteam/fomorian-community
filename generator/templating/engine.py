"""
Template rendering engine using Jinja2.

Renders attack log templates with environment-specific values,
handling placeholder substitution and log customization.
"""

import copy
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class RenderContext:
    """Context for rendering a template."""

    # Environment context
    hostname: str
    short_name: str
    domain: str
    agent_name: str
    agent_id: str
    ip: str

    # User context
    username: str
    user_domain: str

    # Process context
    guid: str
    parent_guid: Optional[str]
    pid: int
    parent_pid: Optional[int]

    # Timing
    timestamp: datetime

    # Network context (for lateral movement / C2)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_hostname: Optional[str] = None
    dest_port: Optional[int] = None

    # C2 context
    c2_ip: Optional[str] = None
    c2_domain: Optional[str] = None
    c2_port: Optional[int] = None


class TemplateEngine:
    """
    Renders attack log templates with environment-specific values.

    Uses simple string substitution with {{placeholder}} syntax
    to replace template placeholders with actual values.
    """

    # Pattern for matching {{placeholder}} syntax
    PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*(\w+)\s*\}\}")

    def __init__(self):
        """Initialize the template engine."""
        self._custom_filters: Dict[str, callable] = {}
        self._register_default_filters()

    def _register_default_filters(self) -> None:
        """Register default transformation filters."""
        import base64
        import hashlib
        import secrets

        self._custom_filters["upper"] = str.upper
        self._custom_filters["lower"] = str.lower
        self._custom_filters["base64"] = lambda s: base64.b64encode(s.encode()).decode()
        self._custom_filters["sha256"] = lambda s: hashlib.sha256(s.encode()).hexdigest().upper()
        self._custom_filters["random_hex"] = lambda n: secrets.token_hex(int(n))

    def render(self, template: Dict[str, Any], context: RenderContext) -> Dict[str, Any]:
        """
        Render a template with the given context.

        Args:
            template: Log template dictionary
            context: Render context with values

        Returns:
            Rendered log dictionary
        """
        # Build substitution map from context
        substitutions = self._build_substitutions(context)

        # Deep copy template to avoid mutation
        rendered = copy.deepcopy(template)

        # Recursively substitute placeholders
        rendered = self._substitute_recursive(rendered, substitutions)

        return rendered

    def render_logs(
        self,
        logs: List[Dict[str, Any]],
        context: RenderContext,
    ) -> List[Dict[str, Any]]:
        """
        Render a list of log templates.

        Args:
            logs: List of log template dictionaries
            context: Render context

        Returns:
            List of rendered log dictionaries
        """
        return [self.render(log, context) for log in logs]

    def _build_substitutions(self, context: RenderContext) -> Dict[str, str]:
        """Build substitution dictionary from context."""
        subs = {
            # Host
            "hostname": context.hostname,
            "short_name": context.short_name,
            "computer_name": context.hostname,
            "agent_name": context.agent_name,
            "agent_id": context.agent_id,
            "host_ip": context.ip,

            # Domain
            "domain": context.domain,
            "domain_upper": context.domain.upper().split(".")[0],

            # User
            "username": context.username,
            "user": f"{context.user_domain}\\{context.username}",
            "user_domain": context.user_domain,

            # Process
            "guid": context.guid,
            "process_guid": context.guid,
            "parent_guid": context.parent_guid or "",
            "parent_process_guid": context.parent_guid or "",
            "pid": str(context.pid),
            "process_id": str(context.pid),
            "pid_hex": format(context.pid, 'x').upper(),
            "parent_pid": str(context.parent_pid) if context.parent_pid else "",
            "parent_process_id": str(context.parent_pid) if context.parent_pid else "",
            "parent_pid_hex": format(context.parent_pid, 'x').upper() if context.parent_pid else "0",

            # Timing
            "timestamp": context.timestamp.isoformat() + "Z",
            "utc_time": context.timestamp.strftime("%Y-%m-%d %H:%M:%S.") + f"{context.timestamp.microsecond // 1000:03d}",
            "date": context.timestamp.strftime("%Y-%m-%d"),
            "time": context.timestamp.strftime("%H:%M:%S"),

            # Network
            "source_ip": context.source_ip or context.ip,
            "src_ip": context.source_ip or context.ip,
            "dest_ip": context.dest_ip or "",
            "dst_ip": context.dest_ip or "",
            "destination_ip": context.dest_ip or "",
            "dest_hostname": context.dest_hostname or "",
            "destination_hostname": context.dest_hostname or "",
            "dest_port": str(context.dest_port) if context.dest_port else "",
            "destination_port": str(context.dest_port) if context.dest_port else "",

            # C2
            "c2_ip": context.c2_ip or "",
            "c2_domain": context.c2_domain or "",
            "c2_port": str(context.c2_port) if context.c2_port else "443",
        }

        return subs

    def _substitute_recursive(
        self,
        obj: Any,
        substitutions: Dict[str, str],
    ) -> Any:
        """Recursively substitute placeholders in nested structure."""
        if isinstance(obj, str):
            return self._substitute_string(obj, substitutions)
        elif isinstance(obj, dict):
            return {k: self._substitute_recursive(v, substitutions) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_recursive(item, substitutions) for item in obj]
        return obj

    def _substitute_string(self, text: str, substitutions: Dict[str, str]) -> str:
        """Substitute placeholders in a string."""
        def replace_match(match):
            key = match.group(1)

            # Check for filter syntax: {{key|filter}}
            if "|" in key:
                key, filter_name = key.split("|", 1)
                key = key.strip()
                filter_name = filter_name.strip()

                value = substitutions.get(key, match.group(0))
                if filter_name in self._custom_filters:
                    try:
                        value = self._custom_filters[filter_name](value)
                    except Exception:
                        pass
                return str(value)

            return substitutions.get(key, match.group(0))

        return self.PLACEHOLDER_PATTERN.sub(replace_match, text)

    def register_filter(self, name: str, func: callable) -> None:
        """Register a custom filter function."""
        self._custom_filters[name] = func


def create_parameterized_template(raw_template: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a raw template with hardcoded values to a parameterized template.

    This function identifies common fields and replaces them with placeholders.
    """
    template = copy.deepcopy(raw_template)

    # Common field mappings for parameterization
    field_mappings = {
        # Sysmon fields
        "computer_name": "{{hostname}}",
        "ComputerName": "{{hostname}}",
        "User": "{{user}}",
        "ProcessGuid": "{{guid}}",
        "ParentProcessGuid": "{{parent_guid}}",
        "ProcessId": "{{pid}}",
        "ParentProcessId": "{{parent_pid}}",
        "UtcTime": "{{utc_time}}",
        "SourceIp": "{{source_ip}}",
        "DestinationIp": "{{dest_ip}}",
        "DestinationHostname": "{{dest_hostname}}",
        "DestinationPort": "{{dest_port}}",
    }

    def replace_fields(obj: Any) -> Any:
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if k in field_mappings and isinstance(v, str):
                    result[k] = field_mappings[k]
                else:
                    result[k] = replace_fields(v)
            return result
        elif isinstance(obj, list):
            return [replace_fields(item) for item in obj]
        return obj

    return replace_fields(template)
