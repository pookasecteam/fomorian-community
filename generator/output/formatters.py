"""Output formatters for generated attack scenarios.

Each formatter takes an AttackScenario and writes it to disk in the
requested format. All formatters expose a `write(scenario, output_path)`
method that returns a list of created file paths (strings).
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List


class Formatter(ABC):
    """Base class for output formatters."""

    @abstractmethod
    def write(self, scenario: Any, output_path: Path) -> List[str]:
        """Write the scenario to disk and return list of created files."""
        ...


class JsonFormatter(Formatter):
    """Write the entire scenario as a single JSON file."""

    def write(self, scenario: Any, output_path: Path) -> List[str]:
        output_path = Path(output_path)
        if output_path.suffix != ".json":
            output_path = output_path.with_suffix(".json")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(scenario.to_dict(), f, indent=2)

        return [str(output_path)]


class NdjsonFormatter(Formatter):
    """Write logs as newline-delimited JSON (one log per line)."""

    def write(self, scenario: Any, output_path: Path) -> List[str]:
        output_path = Path(output_path)
        if output_path.suffix not in (".ndjson", ".jsonl"):
            output_path = output_path.with_suffix(".ndjson")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for entry in scenario.logs:
                log_data = entry.log if isinstance(entry.log, dict) else entry.log
                f.write(json.dumps(log_data) + "\n")

        return [str(output_path)]


class SyslogFormatter(Formatter):
    """Write logs in syslog-compatible format."""

    def write(self, scenario: Any, output_path: Path) -> List[str]:
        output_path = Path(output_path)
        if output_path.suffix != ".log":
            output_path = output_path.with_suffix(".log")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for entry in scenario.logs:
                ts = entry.timestamp
                host = entry.host
                msg = json.dumps(entry.log)
                f.write(f"{ts} {host} fomorian: {msg}\n")

        return [str(output_path)]


class SplitFormatter(Formatter):
    """Write each phase/technique as a separate JSON file."""

    def write(self, scenario: Any, output_path: Path) -> List[str]:
        output_dir = Path(output_path)
        if output_dir.suffix:
            output_dir = output_dir.parent / output_dir.stem

        output_dir.mkdir(parents=True, exist_ok=True)
        created = []

        # Group logs by attack phase
        phases: Dict[str, list] = {}
        for entry in scenario.logs:
            phase = entry.attack_phase or "unknown"
            phases.setdefault(phase, []).append(entry)

        # Write metadata
        meta_path = output_dir / "_metadata.json"
        with open(meta_path, "w") as f:
            json.dump(scenario.to_dict()["_metadata"], f, indent=2)
        created.append(str(meta_path))

        # Write per-phase files
        for phase_name, entries in phases.items():
            safe_name = phase_name.replace(" ", "_").replace("/", "_").lower()
            phase_path = output_dir / f"{safe_name}.json"
            logs = [e.log for e in entries]
            with open(phase_path, "w") as f:
                json.dump(logs, f, indent=2)
            created.append(str(phase_path))

        return created


class WazuhFormatter(Formatter):
    """Write logs in native Wazuh alerts.json format (JSONL).

    Each line is a complete Wazuh alert object ready for injection
    into /var/ossec/logs/alerts/alerts.json.
    """

    def write(self, scenario: Any, output_path: Path) -> List[str]:
        output_path = Path(output_path)
        if output_path.suffix not in (".jsonl", ".json"):
            output_path = output_path.with_suffix(".jsonl")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for entry in scenario.logs:
                f.write(json.dumps(entry.log) + "\n")

        return [str(output_path)]


_FORMATTERS = {
    "json": JsonFormatter,
    "ndjson": NdjsonFormatter,
    "syslog": SyslogFormatter,
    "split": SplitFormatter,
    "wazuh": WazuhFormatter,
}


def get_formatter(name: str) -> Formatter:
    """Return a formatter instance by name.

    Args:
        name: One of json, ndjson, syslog, split, wazuh.

    Raises:
        ValueError: If the formatter name is not recognised.
    """
    cls = _FORMATTERS.get(name)
    if cls is None:
        valid = ", ".join(sorted(_FORMATTERS))
        raise ValueError(f"Unknown format '{name}'. Valid formats: {valid}")
    return cls()
