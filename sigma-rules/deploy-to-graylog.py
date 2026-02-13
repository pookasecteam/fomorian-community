#!/usr/bin/env python3
"""
Convert Sigma rules to Graylog pipeline rules and output for deployment.
"""

import yaml
import os
import uuid
from pathlib import Path

# Level to severity mapping
LEVEL_SEVERITY = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'informational': 1
}

# Field mappings from Sigma to Graylog (filebeat prefix)
FIELD_MAP = {
    'Image': 'filebeat_data_win_eventdata_image',
    'CommandLine': 'filebeat_data_win_eventdata_commandLine',
    'OriginalFileName': 'filebeat_data_win_eventdata_originalFileName',
    'User': 'filebeat_data_win_eventdata_user',
    'ParentImage': 'filebeat_data_win_eventdata_parentImage',
    'ParentCommandLine': 'filebeat_data_win_eventdata_parentCommandLine',
    'DestinationPort': 'filebeat_data_win_eventdata_destinationPort',
    'DestinationHostname': 'filebeat_data_win_eventdata_destinationHostname',
    'DestinationIp': 'filebeat_data_win_eventdata_destinationIp',
    'SourceIp': 'filebeat_data_win_eventdata_sourceIp',
    'Initiated': 'filebeat_data_win_eventdata_initiated',
    'TargetFilename': 'filebeat_data_win_eventdata_targetFilename',
    'QueryName': 'filebeat_data_win_eventdata_queryName',
}


def parse_sigma_rule(filepath):
    """Parse a Sigma YAML rule file."""
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)


def generate_condition(selection, field_prefix=''):
    """Generate Graylog condition from Sigma selection."""
    conditions = []

    for field, values in selection.items():
        # Handle field modifiers
        modifier = None
        base_field = field
        if '|' in field:
            parts = field.split('|')
            base_field = parts[0]
            modifier = parts[1] if len(parts) > 1 else None

        # Map to Graylog field
        graylog_field = FIELD_MAP.get(base_field, f'filebeat_data_win_eventdata_{base_field.lower()}')

        # Handle list of values
        if not isinstance(values, list):
            values = [values]

        value_conditions = []
        for value in values:
            value_str = str(value).replace('"', '\\"')

            if modifier == 'endswith':
                # Use regex for endswith
                value_conditions.append(
                    f'regex(".*{value_str.replace(chr(92), chr(92)+chr(92))}$", to_string($message.{graylog_field})).matches == true'
                )
            elif modifier == 'startswith':
                value_conditions.append(
                    f'regex("^{value_str.replace(chr(92), chr(92)+chr(92))}.*", to_string($message.{graylog_field})).matches == true'
                )
            elif modifier == 'contains':
                value_conditions.append(
                    f'contains(to_string($message.{graylog_field}), "{value_str}", true)'
                )
            else:
                # Exact match or contains for partial
                if '*' in value_str:
                    # Wildcard - convert to contains
                    clean_value = value_str.replace('*', '')
                    value_conditions.append(
                        f'contains(to_string($message.{graylog_field}), "{clean_value}", true)'
                    )
                else:
                    value_conditions.append(
                        f'to_string($message.{graylog_field}) == "{value_str}"'
                    )

        if value_conditions:
            if len(value_conditions) == 1:
                conditions.append(value_conditions[0])
            else:
                conditions.append(f'({" OR ".join(value_conditions)})')

    return ' AND '.join(conditions) if conditions else 'true'


def sigma_to_graylog_rule(sigma_rule, rule_id_prefix='SIGMA'):
    """Convert a Sigma rule to Graylog pipeline rule format."""
    title = sigma_rule.get('title', 'Unknown Rule')
    description = sigma_rule.get('description', '')
    level = sigma_rule.get('level', 'medium')
    tags = sigma_rule.get('tags', [])
    rule_id = sigma_rule.get('id', str(uuid.uuid4()))

    # Extract MITRE ATT&CK IDs from tags
    mitre_ids = [t.split('.')[-1].upper() for t in tags if t.startswith('attack.t')]
    mitre_str = ','.join(mitre_ids) if mitre_ids else ''

    detection = sigma_rule.get('detection', {})
    condition = detection.get('condition', '')

    # Build the when clause
    selections = {k: v for k, v in detection.items() if k.startswith('selection')}
    filters = {k: v for k, v in detection.items() if k.startswith('filter')}

    # Parse condition to understand logic
    when_parts = []

    for sel_name, sel_value in selections.items():
        sel_condition = generate_condition(sel_value)
        when_parts.append((sel_name, sel_condition))

    filter_parts = []
    for flt_name, flt_value in filters.items():
        flt_condition = generate_condition(flt_value)
        filter_parts.append((flt_name, flt_condition))

    # Build the full when clause based on condition
    if 'or' in condition.lower():
        # OR logic between selections
        selection_conditions = [f'({cond})' for _, cond in when_parts]
        when_clause = ' OR '.join(selection_conditions)
    else:
        # AND logic between selections
        selection_conditions = [f'({cond})' for _, cond in when_parts]
        when_clause = ' AND '.join(selection_conditions)

    # Add filter exclusions
    if filter_parts:
        filter_conditions = [f'({cond})' for _, cond in filter_parts]
        filter_clause = ' OR '.join(filter_conditions)
        when_clause = f'({when_clause}) AND NOT ({filter_clause})'

    # Ensure we have a has_field check
    primary_field = 'filebeat_data_win_eventdata_image'
    if 'network_connection' in str(sigma_rule.get('logsource', {})):
        primary_field = 'filebeat_data_win_eventdata_destinationPort'

    severity = LEVEL_SEVERITY.get(level, 3)
    tags_str = ','.join(tags)

    rule_source = f'''rule "Sigma: {title}"
when
    has_field("{primary_field}") AND
    ({when_clause})
then
    set_field("sigma_rule_id", "{rule_id}");
    set_field("sigma_rule_title", "{title}");
    set_field("sigma_level", "{level}");
    set_field("mitre_attack_ids", "{mitre_str}");
    set_field("alert", true);
    set_field("alert_severity", {severity});
    set_field("sigma_tags", "{tags_str}");
end'''

    return {
        'title': f'Sigma: {title}',
        'description': f'Sigma rule ({level.upper()}): {description}',
        'source': rule_source
    }


def process_all_rules(rules_dir):
    """Process all Sigma rules in directory."""
    rules = []

    for root, dirs, files in os.walk(rules_dir):
        # Skip office365 directory (different format)
        if 'office365' in root:
            continue

        for file in files:
            if file.endswith('.yml') and not file.startswith('deploy'):
                filepath = os.path.join(root, file)
                try:
                    sigma_rule = parse_sigma_rule(filepath)
                    graylog_rule = sigma_to_graylog_rule(sigma_rule)
                    rules.append(graylog_rule)
                    print(f"Converted: {sigma_rule.get('title', file)}")
                except Exception as e:
                    print(f"Error processing {filepath}: {e}")

    return rules


def generate_mongo_commands(rules):
    """Generate MongoDB commands to insert rules."""
    commands = []

    for rule in rules:
        title = rule['title'].replace('"', '\\"')
        description = rule['description'].replace('"', '\\"')
        source = rule['source'].replace('"', '\\"').replace('\n', '\\n')

        cmd = f'''db.pipeline_processor_rules.updateOne(
  {{ title: "{title}" }},
  {{
    \\$set: {{
      title: "{title}",
      description: "{description}",
      source: "{source}",
      modified_at: new Date(),
      _scope: "DEFAULT"
    }},
    \\$setOnInsert: {{
      created_at: new Date()
    }}
  }},
  {{ upsert: true }}
);'''
        commands.append(cmd)

    return commands


if __name__ == '__main__':
    import sys

    rules_dir = Path(__file__).parent

    print("=" * 60)
    print("Converting Sigma Rules to Graylog Pipeline Rules")
    print("=" * 60)

    rules = process_all_rules(rules_dir)

    print(f"\n{len(rules)} rules converted successfully")
    print("\nGenerated rules:")
    print("-" * 60)

    for rule in rules:
        print(f"\n### {rule['title']}")
        print(rule['source'])
        print()

    # Generate output file with the rules for deployment
    output_file = rules_dir / 'graylog-rules-output.txt'
    with open(output_file, 'w') as f:
        for rule in rules:
            f.write(f"=== {rule['title']} ===\n")
            f.write(f"Description: {rule['description']}\n")
            f.write(f"Source:\n{rule['source']}\n")
            f.write("\n" + "=" * 60 + "\n\n")

    print(f"\nRules written to: {output_file}")
