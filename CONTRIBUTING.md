# Contributing to Fomorian

Fomorian is an open source project and we welcome contributions from the Wazuh community.

## Ways to Contribute

### Add Attack Templates

We need more MITRE ATT&CK coverage. Each technique needs realistic log examples.

```
attacks/
├── execution/
│   └── T1059.001-powershell/
│       └── logs/
│           └── 001-encoded-command.json
```

Template format:
```json
{
  "winlog": {
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "event_id": 1,
    "provider_name": "Microsoft-Windows-Sysmon",
    "computer_name": "{{ hostname }}",
    "event_data": {
      "CommandLine": "powershell.exe -enc ...",
      "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "User": "{{ domain }}\\{{ username }}"
    }
  }
}
```

### Add Engagement Types

Create new attack scenarios in `generator/builder/scenario_builder.py`:

- Supply chain attacks
- Cloud infrastructure attacks
- IoT/OT attacks
- Zero-day simulation

### Improve SIEM Integrations

Current integrations:
- Wazuh (archives, alerts, file, API)

Wanted:
- Graylog (GELF)
- Splunk HEC
- Elastic/OpenSearch direct
- QRadar
- Sentinel

### Fix Bugs

Check the issues tab for open bugs. Common areas:
- Shell escaping in injection methods
- Field mapping issues
- Timestamp handling

## Development Setup

```bash
git clone https://github.com/pookasecteam/fomorian-community.git
cd fomorian
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python3 -m generator detect-wazuh
python3 -m generator generate --config profiles/test-config --engagement ransomware --dry-run
```

## Pull Request Process

1. Fork the repo
2. Create a feature branch (`git checkout -b add-new-technique`)
3. Make your changes
4. Test locally with `--dry-run` and actual injection if possible
5. Submit a PR with a clear description

## Code Style

- Keep it simple
- No unnecessary abstractions
- Comments only where logic is not obvious
- Follow existing patterns in the codebase

## Adding a New Technique

1. Create the directory structure under `attacks/`
2. Add realistic log examples (use real Sysmon/Windows Security event formats)
3. Include MITRE ATT&CK technique ID in the filename
4. Test that it generates valid JSON

## Adding a New Engagement

1. Add the engagement type to `generator/config/models.py`
2. Create the scenario builder method in `generator/builder/scenario_builder.py`
3. Add a default engagement YAML in `profiles/test-config/engagements/`
4. Update the CLI choices in `generator/cli.py`
5. Document in README.md

## Questions?

Open an issue or reach out to the PookaSec team.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
