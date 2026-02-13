"""
Timestamp generator for realistic attack timing.

Generates timestamps with configurable delays, jitter, and
support for multi-day scenarios with working hours awareness.
"""

import random
import re
from datetime import datetime, timedelta, time
from typing import Optional, Tuple
from dataclasses import dataclass

from ..config.models import TimingConfig, TimingMode


@dataclass
class TimeRange:
    """Represents a time range (min, max) in seconds."""

    min_seconds: float
    max_seconds: float

    @classmethod
    def from_string(cls, range_str: str) -> "TimeRange":
        """
        Parse a time range string.

        Supports formats like:
        - "5s" (5 seconds)
        - "1m-5m" (1 to 5 minutes)
        - "30m-2h" (30 minutes to 2 hours)
        - "1d" (1 day)
        """
        pattern = re.compile(r"(\d+)(ms|s|m|h|d|w)")

        # Check for range format
        if "-" in range_str:
            min_str, max_str = range_str.split("-", 1)
            min_match = pattern.match(min_str.strip())
            max_match = pattern.match(max_str.strip())

            if not min_match or not max_match:
                raise ValueError(f"Invalid time range format: {range_str}")

            min_seconds = cls._to_seconds(int(min_match.group(1)), min_match.group(2))
            max_seconds = cls._to_seconds(int(max_match.group(1)), max_match.group(2))
        else:
            match = pattern.match(range_str.strip())
            if not match:
                raise ValueError(f"Invalid time format: {range_str}")
            seconds = cls._to_seconds(int(match.group(1)), match.group(2))
            min_seconds = seconds
            max_seconds = seconds

        return cls(min_seconds=min_seconds, max_seconds=max_seconds)

    @staticmethod
    def _to_seconds(value: int, unit: str) -> float:
        """Convert value and unit to seconds."""
        multipliers = {
            "ms": 0.001,
            "s": 1,
            "m": 60,
            "h": 3600,
            "d": 86400,
            "w": 604800,
        }
        return value * multipliers.get(unit, 1)

    def random_seconds(self) -> float:
        """Get a random value within the range."""
        return random.uniform(self.min_seconds, self.max_seconds)


class TimestampGenerator:
    """
    Generates realistic timestamps for attack scenarios.

    Features:
    - Configurable delays between events
    - Support for multi-day scenarios
    - Working hours awareness
    - Phase transition delays
    - Jitter for randomization
    """

    def __init__(self, config: Optional[TimingConfig] = None, seed: Optional[int] = None):
        """
        Initialize the timestamp generator.

        Args:
            config: Timing configuration
            seed: Random seed for reproducibility
        """
        self.config = config or TimingConfig()
        self._current: Optional[datetime] = None
        self._start: Optional[datetime] = None
        self._end: Optional[datetime] = None

        if seed is not None:
            random.seed(seed)

    def start(self, base_time: Optional[datetime] = None) -> datetime:
        """
        Start the timestamp sequence.

        Args:
            base_time: Starting timestamp (defaults to config or now)

        Returns:
            The starting timestamp
        """
        if base_time:
            self._current = base_time
        elif self.config.base_timestamp:
            self._current = self.config.base_timestamp
        elif self.config.mode == TimingMode.REALISTIC:
            self._current = self._next_working_hours()
        else:
            self._current = datetime.utcnow()

        self._start = self._current

        # Calculate end time if duration specified
        if self.config.duration:
            duration = self.config.parse_duration(self.config.duration)
            self._end = self._start + duration

        return self._current

    def next(
        self,
        delay: Optional[str] = None,
        phase_transition: Optional[Tuple[str, str]] = None,
    ) -> datetime:
        """
        Get the next timestamp.

        Args:
            delay: Explicit delay string (e.g., "5s", "1m-5m")
            phase_transition: Tuple of (from_phase, to_phase) for phase delays

        Returns:
            Next timestamp
        """
        if self._current is None:
            return self.start()

        # Determine delay
        if delay:
            time_range = TimeRange.from_string(delay)
            delay_seconds = time_range.random_seconds()
        elif phase_transition:
            delay_seconds = self._get_phase_delay(*phase_transition)
        else:
            time_range = TimeRange.from_string(self.config.inter_event_delay)
            delay_seconds = time_range.random_seconds()

        # Apply delay
        self._current = self._current + timedelta(seconds=delay_seconds)

        # Handle working hours if in realistic mode
        if self.config.mode == TimingMode.REALISTIC:
            self._current = self._adjust_for_working_hours(self._current)

        return self._current

    def current(self) -> Optional[datetime]:
        """Get the current timestamp without advancing."""
        return self._current

    def elapsed(self) -> Optional[timedelta]:
        """Get elapsed time since start."""
        if self._start and self._current:
            return self._current - self._start
        return None

    def _next_working_hours(self) -> datetime:
        """Get next timestamp within working hours."""
        now = datetime.utcnow()

        # Parse working hours
        start_hour, start_min = map(int, self.config.working_hours_start.split(":"))
        end_hour, end_min = map(int, self.config.working_hours_end.split(":"))

        work_start = time(start_hour, start_min)
        work_end = time(end_hour, end_min)

        current_time = now.time()

        # If current time is within working hours, use it
        if work_start <= current_time <= work_end:
            return now

        # If before working hours, use start of working hours today
        if current_time < work_start:
            return now.replace(hour=start_hour, minute=start_min, second=0, microsecond=0)

        # If after working hours, use start of working hours tomorrow
        tomorrow = now + timedelta(days=1)
        return tomorrow.replace(hour=start_hour, minute=start_min, second=0, microsecond=0)

    def _adjust_for_working_hours(self, dt: datetime) -> datetime:
        """Adjust timestamp to be within working hours if needed."""
        start_hour, start_min = map(int, self.config.working_hours_start.split(":"))
        end_hour, end_min = map(int, self.config.working_hours_end.split(":"))

        work_start = time(start_hour, start_min)
        work_end = time(end_hour, end_min)

        current_time = dt.time()

        # If within working hours, return as-is
        if work_start <= current_time <= work_end:
            return dt

        # If after working hours, move to next day's working hours
        if current_time > work_end:
            next_day = dt + timedelta(days=1)
            return next_day.replace(hour=start_hour, minute=start_min, second=0, microsecond=0)

        # If before working hours, move to today's working hours start
        return dt.replace(hour=start_hour, minute=start_min, second=0, microsecond=0)

    def _get_phase_delay(self, from_phase: str, to_phase: str) -> float:
        """Get delay between two phases."""
        # Normalize phase names for lookup
        from_key = from_phase.replace("-", "_").replace("access", "").strip("_")
        to_key = to_phase.replace("-", "_").replace("access", "").strip("_")

        # Try to find matching delay in config
        delay_str = None

        # Common phase transition mappings
        transitions = {
            ("initial", "execution"): "initial_to_execution",
            ("execution", "persistence"): "execution_to_persistence",
            ("persistence", "discovery"): "persistence_to_discovery",
            ("discovery", "lateral"): "discovery_to_lateral",
            ("lateral", "collection"): "lateral_to_collection",
            ("collection", "exfil"): "collection_to_exfil",
        }

        for (f, t), attr in transitions.items():
            if f in from_key and t in to_key:
                delay_str = getattr(self.config.phase_delays, attr, None)
                break

        if delay_str is None:
            # Default delay between phases
            delay_str = "1m-5m"

        time_range = TimeRange.from_string(delay_str)
        return time_range.random_seconds()

    def skip_to_next_day(self) -> datetime:
        """Skip to the start of working hours on the next day."""
        if self._current is None:
            return self.start()

        start_hour, start_min = map(int, self.config.working_hours_start.split(":"))

        next_day = self._current + timedelta(days=1)
        self._current = next_day.replace(
            hour=start_hour,
            minute=start_min,
            second=0,
            microsecond=0
        )

        return self._current

    def add_random_jitter(self, max_seconds: float = 5.0) -> datetime:
        """Add random jitter to current timestamp."""
        if self._current is None:
            return self.start()

        jitter = random.uniform(0, max_seconds)
        self._current = self._current + timedelta(seconds=jitter)
        return self._current
