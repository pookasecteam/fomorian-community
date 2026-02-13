#!/usr/bin/env python3
"""
Convert Fomorian attack log templates to NDJSON format for Wazuh injection.
Outputs standard Wazuh alert format ready for alerts.json.
"""
import json
import glob
import os
from datetime import datetime

def convert_logs_to_ndjson(attack_dirs, output_file, batch_id="batch7"):
    """
    Convert attack log templates to NDJSON format.

    Args:
        attack_dirs: List of glob patterns for attack log directories
        output_file: Path to output NDJSON file
        batch_id: Batch identifier for tracking
    """
    all_logs = []

    for pattern in attack_dirs:
        json_files = glob.glob(pattern)
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                metadata = data.get('_metadata', {})
                logs = data.get('logs', [])

                for log_entry in logs:
                    log = log_entry.get('log', {})

                    # Set timestamp to current time if empty
                    if not log.get('timestamp'):
                        log['timestamp'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000+0000')

                    # Add Fomorian tracking fields
                    log['_fomorian_test'] = True
                    log['_fomorian_batch'] = batch_id
                    log['_fomorian_attack_id'] = metadata.get('attack_id', 'unknown')
                    log['_fomorian_variation'] = metadata.get('variation', '001')
                    log['_fomorian_name'] = metadata.get('name', 'unknown')

                    all_logs.append(log)

            except Exception as e:
                print(f"Error processing {json_file}: {e}")

    # Write NDJSON
    with open(output_file, 'w') as f:
        for log in all_logs:
            f.write(json.dumps(log) + '\n')

    print(f"Converted {len(all_logs)} logs to {output_file}")
    return len(all_logs)

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Define patterns for new batch 7 files (002 and 003 variations)
    patterns = [
        f"{base_dir}/attacks/defense-evasion/T1564.004-ntfs-ads/logs/00[23]-*.json",
        f"{base_dir}/attacks/privilege-escalation/T1611-container-escape/logs/00[23]-*.json",
        f"{base_dir}/attacks/credential-access/T1552.006-gpp-passwords/logs/00[23]-*.json",
        f"{base_dir}/attacks/lateral-movement/T1563.002-rdp-hijacking/logs/00[23]-*.json",
        f"{base_dir}/attacks/persistence/T1098.001-additional-cloud-creds/logs/00[23]-*.json",
        f"{base_dir}/attacks/defense-evasion/T1027.004-compile-after-delivery/logs/00[23]-*.json",
        f"{base_dir}/attacks/execution/T1059.006-python/logs/00[23]-*.json",
        f"{base_dir}/attacks/credential-access/T1552.002-credentials-in-registry/logs/00[23]-*.json",
        f"{base_dir}/attacks/defense-evasion/T1564.003-hidden-window/logs/00[23]-*.json",
        f"{base_dir}/attacks/persistence/T1136.002-domain-account/logs/00[23]-*.json",
    ]

    output_file = f"{base_dir}/output/batch7-attack-logs.ndjson"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    count = convert_logs_to_ndjson(patterns, output_file, "batch7")
    print(f"Ready for injection: {output_file}")
