"""
Configuration loader for YAML files.

Handles loading, validation, and merging of configuration files.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any, Union
import yaml
from pydantic import ValidationError

from .models import (
    EnvironmentConfig,
    AttackPathConfig,
    EngagementConfig,
    TimingConfig,
)


class ConfigError(Exception):
    """Configuration loading or validation error."""
    pass


class ConfigLoader:
    """
    Loads and validates configuration from YAML files.

    Supports loading individual config files or a complete
    configuration directory with multiple files.
    """

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        """
        Initialize the config loader.

        Args:
            config_path: Path to config file or directory
        """
        self.config_path = Path(config_path) if config_path else None
        self._environment: Optional[EnvironmentConfig] = None
        self._attack_path: Optional[AttackPathConfig] = None
        self._engagement: Optional[EngagementConfig] = None
        self._timing: Optional[TimingConfig] = None

    def load(self) -> "ConfigLoader":
        """
        Load all configuration files from the config path.

        Returns:
            Self for method chaining
        """
        if self.config_path is None:
            raise ConfigError("No configuration path specified")

        if self.config_path.is_file():
            self._load_single_file(self.config_path)
        elif self.config_path.is_dir():
            self._load_directory(self.config_path)
        else:
            raise ConfigError(f"Configuration path does not exist: {self.config_path}")

        return self

    def _load_single_file(self, file_path: Path) -> None:
        """Load a single YAML file containing all configurations."""
        data = self._read_yaml(file_path)

        if "environment" in data:
            self._environment = self._parse_environment(data["environment"])
        if "attack_path" in data:
            self._attack_path = self._parse_attack_path(data["attack_path"])
        if "engagement" in data:
            self._engagement = self._parse_engagement(data["engagement"])
        if "timing" in data:
            self._timing = self._parse_timing(data["timing"])

    def _load_directory(self, dir_path: Path) -> None:
        """Load configuration from a directory with multiple YAML files."""
        # Standard file names to look for
        file_mapping = {
            "environment.yaml": ("environment", self._parse_environment),
            "environment.yml": ("environment", self._parse_environment),
            "attack_path.yaml": ("attack_path", self._parse_attack_path),
            "attack_path.yml": ("attack_path", self._parse_attack_path),
            "engagement.yaml": ("engagement", self._parse_engagement),
            "engagement.yml": ("engagement", self._parse_engagement),
            "timing.yaml": ("timing", self._parse_timing),
            "timing.yml": ("timing", self._parse_timing),
        }

        for filename, (attr, parser) in file_mapping.items():
            file_path = dir_path / filename
            if file_path.exists():
                data = self._read_yaml(file_path)
                parsed = parser(data)
                setattr(self, f"_{attr}", parsed)

    def _read_yaml(self, file_path: Path) -> Dict[str, Any]:
        """Read and parse a YAML file."""
        try:
            with open(file_path, "r") as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in {file_path}: {e}")
        except IOError as e:
            raise ConfigError(f"Cannot read {file_path}: {e}")

    def _parse_environment(self, data: Dict[str, Any]) -> EnvironmentConfig:
        """Parse environment configuration."""
        try:
            return EnvironmentConfig(**data)
        except ValidationError as e:
            raise ConfigError(f"Invalid environment configuration: {e}")

    def _parse_attack_path(self, data: Dict[str, Any]) -> AttackPathConfig:
        """Parse attack path configuration."""
        try:
            return AttackPathConfig(**data)
        except ValidationError as e:
            raise ConfigError(f"Invalid attack path configuration: {e}")

    def _parse_engagement(self, data: Dict[str, Any]) -> EngagementConfig:
        """Parse engagement configuration."""
        try:
            return EngagementConfig(**data)
        except ValidationError as e:
            raise ConfigError(f"Invalid engagement configuration: {e}")

    def _parse_timing(self, data: Dict[str, Any]) -> TimingConfig:
        """Parse timing configuration."""
        try:
            return TimingConfig(**data)
        except ValidationError as e:
            raise ConfigError(f"Invalid timing configuration: {e}")

    @property
    def environment(self) -> Optional[EnvironmentConfig]:
        """Get loaded environment configuration."""
        return self._environment

    @property
    def attack_path(self) -> Optional[AttackPathConfig]:
        """Get loaded attack path configuration."""
        return self._attack_path

    @property
    def engagement(self) -> Optional[EngagementConfig]:
        """Get loaded engagement configuration."""
        return self._engagement

    @property
    def timing(self) -> Optional[TimingConfig]:
        """Get loaded timing configuration."""
        return self._timing

    def validate(self) -> bool:
        """
        Validate that all required configurations are loaded and consistent.

        Returns:
            True if valid

        Raises:
            ConfigError: If configuration is invalid or incomplete
        """
        if self._environment is None:
            raise ConfigError("Environment configuration is required")

        # Validate attack path references valid hosts
        if self._attack_path:
            valid_hosts = {h.short_name for h in self._environment.hosts}
            for step in self._attack_path.path:
                if step.host not in valid_hosts:
                    raise ConfigError(
                        f"Attack path references unknown host: {step.host}. "
                        f"Valid hosts: {valid_hosts}"
                    )
                if step.pivot_from and step.pivot_from not in valid_hosts:
                    raise ConfigError(
                        f"Attack path pivot_from references unknown host: {step.pivot_from}"
                    )

        return True

    def save(self, output_path: Union[str, Path]) -> None:
        """
        Save current configuration to YAML files.

        Args:
            output_path: Directory to save configuration files
        """
        output_path = Path(output_path)
        output_path.mkdir(parents=True, exist_ok=True)

        configs = [
            ("environment.yaml", self._environment),
            ("attack_path.yaml", self._attack_path),
            ("engagement.yaml", self._engagement),
            ("timing.yaml", self._timing),
        ]

        for filename, config in configs:
            if config is not None:
                file_path = output_path / filename
                with open(file_path, "w") as f:
                    yaml.dump(
                        config.model_dump(exclude_none=True),
                        f,
                        default_flow_style=False,
                        sort_keys=False,
                    )

    @classmethod
    def from_dict(
        cls,
        environment: Optional[Dict] = None,
        attack_path: Optional[Dict] = None,
        engagement: Optional[Dict] = None,
        timing: Optional[Dict] = None,
    ) -> "ConfigLoader":
        """
        Create a ConfigLoader from dictionaries.

        Useful for programmatic configuration.
        """
        loader = cls()
        if environment:
            loader._environment = loader._parse_environment(environment)
        if attack_path:
            loader._attack_path = loader._parse_attack_path(attack_path)
        if engagement:
            loader._engagement = loader._parse_engagement(engagement)
        if timing:
            loader._timing = loader._parse_timing(timing)
        return loader
