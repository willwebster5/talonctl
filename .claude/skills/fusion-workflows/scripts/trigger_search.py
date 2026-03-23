"""
List and describe CrowdStrike Fusion workflow trigger types.

Adapted from community fusion-workflows skill. Auth changed to use
~/.config/falcon/credentials.json via cs_auth module.

Queries the API for trigger activities and supplements with a built-in
catalog of trigger type YAML structures.

Usage:
    python trigger_search.py --list                  # Show all trigger types
    python trigger_search.py --type "On demand"      # YAML structure for a type
    python trigger_search.py --list --json           # Machine-readable output
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs_auth import api_get

# Fix Windows console encoding
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Built-in trigger catalog ────────────────────────────────────────────────
# These document the YAML structure for each trigger type, derived from
# the CrowdStrike API Reference and production workflow patterns.

TRIGGER_CATALOG = {
    "On demand": {
        "description": "Manually executed via the Falcon UI or API. Accepts user-defined input parameters via JSON Schema.",
        "yaml_example": """\
trigger:
    next:
        - FirstActionName
    name: On demand
    parameters:
        $schema: https://json-schema.org/draft-07/schema
        properties:
            my_param:
                type: string
                title: My Parameter
                description: Describe this input field.
        required:
            - my_param
        type: object
    type: On demand""",
    },
    "Event": {
        "description": "Fires automatically when a CrowdStrike event occurs (detection, incident, identity event, etc.).",
        "yaml_example": """\
trigger:
    next:
        - FirstActionName
    name: Event
    type: Event
    # Event triggers typically receive data from the event payload.
    # Available fields depend on the event source (detection, incident, etc.).""",
    },
    "Scheduled": {
        "description": "Runs on a cron-like schedule (e.g., every hour, daily).",
        "yaml_example": """\
trigger:
    next:
        - FirstActionName
    name: Scheduled
    type: Scheduled
    schedule:
        cron: "0 */6 * * *"   # Every 6 hours
        timezone: UTC""",
    },
    "API": {
        "description": "Triggered via the CrowdStrike Workflow Execution API endpoint with JSON parameters.",
        "yaml_example": """\
trigger:
    next:
        - FirstActionName
    name: API
    parameters:
        $schema: https://json-schema.org/draft-07/schema
        properties:
            my_param:
                type: string
                title: My Parameter
        required:
            - my_param
        type: object
    type: API""",
    },
}


def list_triggers_from_api():
    """Attempt to fetch trigger types from the API."""
    try:
        resp = api_get("/workflows/combined/activities/v1", params={"limit": 500})
        resources = resp.get("resources", [])
        triggers = [r for r in resources if r.get("category", "").lower() == "trigger"]
        return triggers
    except Exception:
        return []


def list_all_triggers(include_api=True):
    """Merge built-in catalog with any API-discovered triggers."""
    result = {}
    for name, info in TRIGGER_CATALOG.items():
        result[name] = info.copy()

    if include_api:
        api_triggers = list_triggers_from_api()
        for t in api_triggers:
            tname = t.get("name", "")
            if tname and tname not in result:
                result[tname] = {
                    "description": t.get("description", ""),
                    "api_id": t.get("id", ""),
                    "yaml_example": None,
                }

    return result


def main():
    parser = argparse.ArgumentParser(description="List CrowdStrike Fusion trigger types")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", "-l", action="store_true", help="List all trigger types")
    group.add_argument("--type", "-t", metavar="NAME", help="Show YAML structure for a trigger type")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    args = parser.parse_args()

    triggers = list_all_triggers()

    if args.list:
        if args.json:
            out = {}
            for name, info in triggers.items():
                out[name] = {"description": info.get("description", "")}
            print(json.dumps(out, indent=2))
        else:
            print(f"\nTrigger types ({len(triggers)}):\n")
            for name, info in triggers.items():
                desc = info.get("description", "")
                print(f"  {name}")
                if desc:
                    print(f"    {desc[:120]}")
                print()

    elif args.type:
        # Case-insensitive lookup
        match = None
        for name, info in triggers.items():
            if name.lower() == args.type.lower():
                match = (name, info)
                break

        if not match:
            print(f"Unknown trigger type '{args.type}'.")
            print(f"Available: {', '.join(triggers.keys())}")
            sys.exit(1)

        name, info = match
        if args.json:
            print(json.dumps({name: info}, indent=2))
        else:
            print(f"\nTrigger type: {name}")
            print(f"  {info.get('description', '')}\n")
            example = info.get("yaml_example")
            if example:
                print("YAML structure:")
                print(example)
            else:
                print("  (No YAML example available — use the exported structure from an existing workflow)")
            print()


if __name__ == "__main__":
    main()
