#!/usr/bin/env python3
"""Find duplicate detection rules in CrowdStrike NGSIEM tenants.

This script queries both production and staging CrowdStrike tenants,
identifies rules with duplicate names (different rule_ids), and outputs
CSV reports for analysis.

Excludes rules tracked in our state files (legitimate IaC-managed rules).
"""

import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from falconpy import APIHarnessV2

# Path to state files
STATE_DIR = Path(__file__).parent.parent.parent / ".crowdstrike"


def load_tracked_rule_ids(environment: str) -> set[str]:
    """Load rule_ids of detection rules tracked in our state file.

    These are our legitimate IaC-managed rules that should be excluded.

    NOTE: Some state entries incorrectly store version_id in 'id' field.
    We prefer provider_metadata.rule_id (the permanent identifier).
    """
    state_file = STATE_DIR / f"deployed_state.{environment}.json"

    if not state_file.exists():
        print(f"  Warning: State file not found: {state_file}")
        return set()

    try:
        with open(state_file, 'r') as f:
            state = json.load(f)

        tracked_ids = set()
        detections = state.get('resources', {}).get('detection', {})

        for resource_id, resource_data in detections.items():
            # Prefer provider_metadata.rule_id (permanent identifier)
            pm = resource_data.get('provider_metadata', {})
            rule_id = pm.get('rule_id') or resource_data.get('id')
            if rule_id:
                tracked_ids.add(rule_id)

        print(f"  Loaded {len(tracked_ids)} tracked rule_ids from state")
        return tracked_ids

    except Exception as e:
        print(f"  Error loading state file: {e}")
        return set()


def load_credentials(environment: str) -> dict | None:
    """Load credentials for a specific environment.

    Args:
        environment: 'production' or 'staging'

    Returns:
        Credentials dict or None if loading fails
    """
    base_dir = os.path.expanduser("~/.config/falcon")
    config_path = os.path.join(base_dir, f"credentials.{environment}.json")

    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Credentials file not found: {config_path}")
        return None
    except Exception as e:
        print(f"Error loading credentials from {config_path}: {e}")
        return None


def get_falcon_client(environment: str) -> APIHarnessV2 | None:
    """Create an authenticated FalconPy client for the environment."""
    config = load_credentials(environment)
    if not config:
        return None

    return APIHarnessV2(
        client_id=config.get('falcon_client_id'),
        client_secret=config.get('falcon_client_secret'),
        base_url=config.get('base_url', 'US1')
    )


def fetch_all_rules(falcon: APIHarnessV2, environment: str) -> list[dict]:
    """Fetch all detection rules from CrowdStrike API with pagination.

    Returns a list (not dict) to preserve duplicates.
    """
    all_rules = []
    offset = 0
    limit = 1000  # API max per page

    print(f"  Fetching rules from {environment}...")

    while True:
        response = falcon.command(
            "combined_rules_get_v2",
            limit=limit,
            offset=offset,
            sort="name.asc"
        )

        if response["status_code"] != 200:
            print(f"  ERROR: API request failed: {response.get('body', {}).get('errors', response)}")
            break

        rules = response["body"]["resources"]
        if not rules:
            break

        all_rules.extend(rules)

        # Check pagination
        pagination = response["body"].get("meta", {}).get("pagination", {})
        total = pagination.get("total", 0)
        offset += len(rules)

        print(f"  Fetched {offset}/{total} rules...")

        if total > 0 and offset >= total:
            break
        if len(rules) < limit:
            break

    print(f"  Total rules fetched: {len(all_rules)}")
    return all_rules


def find_duplicates(rules: list[dict]) -> dict[str, list[dict]]:
    """Group rules by name and return only groups with 2+ unique rule_ids (true duplicates).

    Deduplicates by (name, rule_id) first to ignore version history.
    """
    # First, deduplicate by (name, rule_id) - keep the most recent version
    unique_rules = {}
    for rule in rules:
        name = rule.get('name', 'UNNAMED')
        rule_id = rule.get('rule_id') or rule.get('id', 'UNKNOWN')
        key = (name, rule_id)

        # Keep the rule with the latest last_updated_on
        if key not in unique_rules:
            unique_rules[key] = rule
        else:
            existing_updated = unique_rules[key].get('last_updated_on', '')
            new_updated = rule.get('last_updated_on', '')
            if new_updated > existing_updated:
                unique_rules[key] = rule

    # Now group by name
    by_name = defaultdict(list)
    for (name, rule_id), rule in unique_rules.items():
        by_name[name].append(rule)

    # Filter to only duplicates (2+ unique rule_ids with same name)
    duplicates = {name: group for name, group in by_name.items() if len(group) > 1}

    return duplicates


def write_csv(duplicates: dict[str, list[dict]], environment: str, output_path: str,
               tracked_ids: set[str], exclude_tracked: bool = True):
    """Write duplicate rules to CSV file.

    Args:
        duplicates: Dict of rule name -> list of rules
        environment: Environment name
        output_path: CSV output path
        tracked_ids: Set of rule_ids that are tracked in state (legitimate)
        exclude_tracked: If True, only output untracked duplicates
    """

    fieldnames = [
        'environment',
        'name',
        'rule_id',
        'is_tracked',
        'status',
        'severity',
        'created_on',
        'last_updated_on',
        'description'
    ]

    rows_written = 0
    tracked_skipped = 0

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        # Sort by name, then by created_on (oldest first)
        for name in sorted(duplicates.keys()):
            group = duplicates[name]
            # Sort group by created_on
            sorted_group = sorted(group, key=lambda r: r.get('created_on', '') or '')

            for rule in sorted_group:
                rule_id = rule.get('rule_id') or rule.get('id', 'UNKNOWN')
                is_tracked = rule_id in tracked_ids

                # Skip tracked rules if exclude_tracked is True
                if exclude_tracked and is_tracked:
                    tracked_skipped += 1
                    continue

                # Clean description: replace newlines with spaces, truncate
                desc = (rule.get('description', '') or '').replace('\n', ' ').replace('\r', ' ')[:200]

                writer.writerow({
                    'environment': environment,
                    'name': name,
                    'rule_id': rule_id,
                    'is_tracked': 'YES' if is_tracked else 'NO',
                    'status': rule.get('status', ''),
                    'severity': rule.get('severity', ''),
                    'created_on': rule.get('created_on', ''),
                    'last_updated_on': rule.get('last_updated_on', ''),
                    'description': desc
                })
                rows_written += 1

    print(f"  Wrote {output_path} ({rows_written} untracked duplicates, {tracked_skipped} tracked rules excluded)")


def write_all_rules_csv(rules: list[dict], environment: str, output_path: str, tracked_ids: set[str]):
    """Write ALL rules to CSV for complete analysis."""

    fieldnames = [
        'environment',
        'name',
        'rule_id',
        'is_tracked',
        'is_duplicate',
        'status',
        'severity',
        'created_on',
        'last_updated_on',
        'description'
    ]

    # First, deduplicate by (name, rule_id) and find which names have duplicates
    unique_rules = {}
    for rule in rules:
        name = rule.get('name', 'UNNAMED')
        rule_id = rule.get('rule_id') or rule.get('id', 'UNKNOWN')
        key = (name, rule_id)

        if key not in unique_rules:
            unique_rules[key] = rule
        else:
            existing_updated = unique_rules[key].get('last_updated_on', '')
            new_updated = rule.get('last_updated_on', '')
            if new_updated > existing_updated:
                unique_rules[key] = rule

    # Count names to find duplicates
    name_counts = defaultdict(int)
    for (name, rule_id) in unique_rules.keys():
        name_counts[name] += 1

    duplicate_names = {name for name, count in name_counts.items() if count > 1}

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for (name, rule_id), rule in sorted(unique_rules.items(), key=lambda x: (x[0][0], x[1].get('created_on', ''))):
            is_tracked = rule_id in tracked_ids
            is_duplicate = name in duplicate_names
            desc = (rule.get('description', '') or '').replace('\n', ' ').replace('\r', ' ')[:200]

            writer.writerow({
                'environment': environment,
                'name': name,
                'rule_id': rule_id,
                'is_tracked': 'YES' if is_tracked else 'NO',
                'is_duplicate': 'YES' if is_duplicate else 'NO',
                'status': rule.get('status', ''),
                'severity': rule.get('severity', ''),
                'created_on': rule.get('created_on', ''),
                'last_updated_on': rule.get('last_updated_on', ''),
                'description': desc
            })

    print(f"  Wrote {output_path} ({len(unique_rules)} unique rules)")


def main():
    environments = ['production', 'staging']

    print("=" * 60)
    print("CrowdStrike Detection Rule Analysis")
    print("=" * 60)
    print()
    print("Outputs:")
    print("  - all_rules_<env>.csv: Complete list of all unique rules")
    print("  - duplicate_rules_<env>.csv: Only untracked duplicates (to clean up)")

    for env in environments:
        print(f"\n[{env.upper()}]")
        print("-" * 40)

        # Load tracked rule_ids from state file
        tracked_ids = load_tracked_rule_ids(env)

        falcon = get_falcon_client(env)
        if not falcon:
            print(f"  SKIP: Could not authenticate to {env}")
            continue

        # Fetch all rules
        rules = fetch_all_rules(falcon, env)
        if not rules:
            print(f"  No rules found in {env}")
            continue

        # Write complete rules list
        all_rules_path = f"all_rules_{env}.csv"
        write_all_rules_csv(rules, env, all_rules_path, tracked_ids)

        # Find duplicates
        duplicates = find_duplicates(rules)

        if not duplicates:
            print(f"  No duplicate rules found in {env}")
            continue

        # Count and report
        total_duplicate_rules = sum(len(group) for group in duplicates.values())
        print(f"  Found {len(duplicates)} duplicate rule names ({total_duplicate_rules} rules involved)")

        # Write duplicates CSV (excluding tracked rules)
        output_path = f"duplicate_rules_{env}.csv"
        write_csv(duplicates, env, output_path, tracked_ids, exclude_tracked=True)

        # Summary breakdown
        unique_by_name_ruleid = {}
        for rule in rules:
            name = rule.get('name', 'UNNAMED')
            rule_id = rule.get('rule_id') or rule.get('id', 'UNKNOWN')
            key = (name, rule_id)
            if key not in unique_by_name_ruleid:
                unique_by_name_ruleid[key] = rule

        total_unique = len(unique_by_name_ruleid)
        tracked_count = sum(1 for (n, rid) in unique_by_name_ruleid if rid in tracked_ids)
        untracked_count = total_unique - tracked_count
        non_duplicate_count = total_unique - total_duplicate_rules

        print(f"\n  === BREAKDOWN ===")
        print(f"  Total unique rules:        {total_unique}")
        print(f"    - Tracked (in state):    {tracked_count}")
        print(f"    - Untracked:             {untracked_count}")
        print(f"  Rules with unique names:   {non_duplicate_count}")
        print(f"  Rules in duplicate groups: {total_duplicate_rules}")

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    main()
