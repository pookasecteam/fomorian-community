"""Base SIEM injector class and configuration."""

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime

from ..builder.scenario_builder import AttackScenario, LogEntry


@dataclass
class InjectorConfig:
    """Configuration for SIEM injectors."""

    # Connection settings
    host: str = "localhost"
    port: int = 0  # Default port varies by SIEM
    protocol: str = "https"  # http or https
    verify_ssl: bool = True

    # Authentication
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None

    # Injection settings
    batch_size: int = 100  # Logs per batch
    delay_between_logs: float = 0.0  # Seconds between logs (0 = no delay)
    realtime_replay: bool = False  # Replay with original timing
    index: Optional[str] = None  # Index/sourcetype name
    source: str = "purple-team-generator"

    # Extra SIEM-specific settings
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, prefix: str = "PURPLE_TEAM") -> "InjectorConfig":
        """Load configuration from environment variables."""
        import os

        return cls(
            host=os.environ.get(f"{prefix}_HOST", "localhost"),
            port=int(os.environ.get(f"{prefix}_PORT", "0")),
            protocol=os.environ.get(f"{prefix}_PROTOCOL", "https"),
            api_key=os.environ.get(f"{prefix}_API_KEY"),
            username=os.environ.get(f"{prefix}_USERNAME"),
            password=os.environ.get(f"{prefix}_PASSWORD"),
            token=os.environ.get(f"{prefix}_TOKEN"),
            index=os.environ.get(f"{prefix}_INDEX"),
        )


@dataclass
class InjectionResult:
    """Result of an injection operation."""

    success: bool
    logs_sent: int
    logs_failed: int
    duration_seconds: float
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


class SIEMInjector(ABC):
    """Base class for SIEM injectors."""

    # Override in subclasses
    name: str = "base"
    default_port: int = 0
    supports_batch: bool = True

    def __init__(self, config: InjectorConfig):
        """Initialize the injector with configuration."""
        self.config = config
        if self.config.port == 0:
            self.config.port = self.default_port

    @abstractmethod
    def connect(self) -> bool:
        """Test connection to the SIEM."""
        pass

    @abstractmethod
    def send_log(self, log: Dict[str, Any]) -> bool:
        """Send a single log entry."""
        pass

    def send_batch(self, logs: List[Dict[str, Any]]) -> int:
        """
        Send a batch of logs. Returns count of successful sends.
        Override for SIEMs that support native batching.
        """
        success_count = 0
        for log in logs:
            if self.send_log(log):
                success_count += 1
        return success_count

    def inject(
        self,
        scenario: AttackScenario,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> InjectionResult:
        """
        Inject a complete scenario into the SIEM.

        Args:
            scenario: The attack scenario to inject
            progress_callback: Optional callback(current, total) for progress updates

        Returns:
            InjectionResult with injection statistics
        """
        start_time = time.time()
        logs_sent = 0
        logs_failed = 0
        errors = []

        total_logs = len(scenario.logs)

        # Prepare logs for injection
        prepared_logs = [self.prepare_log(log) for log in scenario.logs]

        # Track timing for realtime replay
        last_timestamp = None

        if self.supports_batch and self.config.batch_size > 1 and not self.config.realtime_replay:
            # Batch mode
            for i in range(0, len(prepared_logs), self.config.batch_size):
                batch = prepared_logs[i : i + self.config.batch_size]
                try:
                    sent = self.send_batch(batch)
                    logs_sent += sent
                    logs_failed += len(batch) - sent
                except Exception as e:
                    errors.append(f"Batch {i // self.config.batch_size}: {str(e)}")
                    logs_failed += len(batch)

                if progress_callback:
                    progress_callback(min(i + len(batch), total_logs), total_logs)

                if self.config.delay_between_logs > 0:
                    time.sleep(self.config.delay_between_logs)
        else:
            # Single log mode (or realtime replay)
            for i, (log_entry, prepared) in enumerate(zip(scenario.logs, prepared_logs)):
                # Handle realtime replay timing
                if self.config.realtime_replay and last_timestamp:
                    current_ts = datetime.fromisoformat(log_entry.timestamp.rstrip("Z"))
                    delay = (current_ts - last_timestamp).total_seconds()
                    if delay > 0:
                        time.sleep(min(delay, 60))  # Cap at 60 seconds max delay
                    last_timestamp = current_ts
                elif self.config.realtime_replay:
                    last_timestamp = datetime.fromisoformat(log_entry.timestamp.rstrip("Z"))

                try:
                    if self.send_log(prepared):
                        logs_sent += 1
                    else:
                        logs_failed += 1
                except Exception as e:
                    errors.append(f"Log {i + 1}: {str(e)}")
                    logs_failed += 1

                if progress_callback:
                    progress_callback(i + 1, total_logs)

                if self.config.delay_between_logs > 0 and not self.config.realtime_replay:
                    time.sleep(self.config.delay_between_logs)

        duration = time.time() - start_time

        return InjectionResult(
            success=logs_failed == 0,
            logs_sent=logs_sent,
            logs_failed=logs_failed,
            duration_seconds=duration,
            errors=errors,
            details={
                "siem": self.name,
                "host": self.config.host,
                "port": self.config.port,
                "scenario_name": scenario.metadata.scenario_name,
            },
        )

    def prepare_log(self, log_entry: LogEntry) -> Dict[str, Any]:
        """
        Prepare a log entry for injection.
        Override in subclasses for SIEM-specific formatting.
        """
        return {
            "_purple_team": {
                "sequence": log_entry.sequence,
                "attack_phase": log_entry.attack_phase,
                "technique": log_entry.technique,
                "comment": log_entry.comment,
            },
            "timestamp": log_entry.timestamp,
            "host": log_entry.host,
            **log_entry.log,
        }

    def get_base_url(self) -> str:
        """Get the base URL for the SIEM."""
        return f"{self.config.protocol}://{self.config.host}:{self.config.port}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(host={self.config.host}, port={self.config.port})"
