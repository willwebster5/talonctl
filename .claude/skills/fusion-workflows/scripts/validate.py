"""
Validate CrowdStrike Fusion workflow YAML files — pre-flight checks only.

Adapted from community fusion-workflows skill. This version performs local
validation only (no API calls). Checks structure, required keys, placeholder
markers, naming conventions, and duplicate detection.

Usage:
    python validate.py workflow.yaml                           # Validate one file
    python validate.py *.yaml                                  # Validate multiple files
    python validate.py --skip-duplicate-check file.yaml        # Skip duplicate name check
    python validate.py --resources-dir path/to/dir file.yaml   # Custom resources directory
"""

import argparse
import glob
import os
import re
import sys

try:
    import yaml
except ImportError:
    yaml = None

# Fix Windows console encoding
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REQUIRED_TOP_LEVEL_KEYS = {"resource_id", "name", "trigger"}
PLACEHOLDER_PATTERN = re.compile(r"PLACEHOLDER_[A-Z_]+")
SNAKE_CASE_PATTERN = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")


def _parse_yaml(file_path):
    """Parse a YAML file, returning (data_dict, error_string).

    Uses PyYAML if available; falls back to a simple regex-based
    extractor for the top-level keys we care about.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        return None, str(e)

    if yaml is not None:
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return None, "YAML root is not a mapping"
            return data, None
        except yaml.YAMLError as e:
            return None, f"YAML parse error: {e}"

    # Fallback: extract top-level keys via regex (no nested parsing)
    data = {}
    for m in re.finditer(r"^([a-z_][a-z0-9_]*)\s*:", content, re.MULTILINE):
        key = m.group(1)
        # Grab the value on the same line (if scalar)
        rest = content[m.end():].split("\n", 1)[0].strip()
        if rest:
            data[key] = rest
        else:
            data[key] = {}  # Placeholder for nested block
    # Try to extract trigger.type via a nested match
    trigger_type_match = re.search(r"^trigger\s*:.*?\n\s+type\s*:\s*(.+)", content, re.MULTILINE)
    if trigger_type_match and "trigger" in data and isinstance(data["trigger"], dict):
        data["trigger"]["type"] = trigger_type_match.group(1).strip()

    if not data:
        return None, "Could not parse any YAML keys (install PyYAML for full parsing)"

    return data, None


def preflight_check(file_path):
    """
    Local pre-flight checks on a workflow YAML file.
    Returns list of issue strings (empty = all checks passed).
    """
    issues = []

    # 1. File exists
    if not os.path.isfile(file_path):
        return [f"ERROR: File not found: {file_path}"]

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()

    # 2. Header comment present
    if not lines or not lines[0].startswith("#"):
        issues.append("WARNING: Missing header comment (first line should start with #)")

    # 3. Valid YAML
    data, parse_error = _parse_yaml(file_path)
    if parse_error:
        issues.append(f"ERROR: {parse_error}")
        # Can't do further structural checks without parsed data
        # But still check for placeholders below

    # 4. Required top-level keys
    if data is not None:
        for key in REQUIRED_TOP_LEVEL_KEYS:
            if key not in data:
                issues.append(f"ERROR: Missing required top-level key '{key}'")

    # 5. Trigger must contain type key
    if data is not None and "trigger" in data:
        trigger = data["trigger"]
        if isinstance(trigger, dict):
            if "type" not in trigger:
                issues.append("ERROR: 'trigger' section missing required 'type' key")
        else:
            # trigger is a scalar or None — likely malformed
            issues.append("ERROR: 'trigger' should be a mapping with at least a 'type' key")

    # 6. No PLACEHOLDER_* markers
    placeholders = PLACEHOLDER_PATTERN.findall(content)
    if placeholders:
        unique = sorted(set(placeholders))
        issues.append(f"ERROR: Found PLACEHOLDER markers that must be replaced: {', '.join(unique)}")

    # 7. resource_id follows snake_case convention
    if data is not None and "resource_id" in data:
        rid = str(data["resource_id"])
        if not SNAKE_CASE_PATTERN.match(rid):
            issues.append(f"WARNING: resource_id '{rid}' does not follow snake_case convention")

    return issues


def duplicate_check(file_path, resources_dir):
    """
    Check if the workflow name in file_path duplicates any existing
    workflow in resources_dir. Returns list of warning strings.
    """
    warnings = []

    data, err = _parse_yaml(file_path)
    if err or data is None or "name" not in data:
        return warnings  # Can't check without a name

    target_name = str(data["name"]).strip()
    abs_file = os.path.abspath(file_path)

    # Scan resources_dir for .yaml files
    if not os.path.isdir(resources_dir):
        return warnings  # Directory doesn't exist — skip silently

    pattern = os.path.join(resources_dir, "**", "*.yaml")
    for existing in glob.glob(pattern, recursive=True):
        if os.path.abspath(existing) == abs_file:
            continue  # Skip self
        existing_data, _ = _parse_yaml(existing)
        if existing_data and "name" in existing_data:
            if str(existing_data["name"]).strip() == target_name:
                warnings.append(
                    f"WARNING: Duplicate name '{target_name}' — "
                    f"also found in {os.path.relpath(existing, resources_dir)}"
                )

    return warnings


def validate_file(file_path, skip_duplicate=False, resources_dir="resources/workflows/"):
    """
    Validate a single file. Returns (passed: bool, messages: list[str]).
    """
    messages = []

    # Pre-flight
    issues = preflight_check(file_path)
    has_errors = any(i.startswith("ERROR") for i in issues)
    messages.extend(issues)

    # Duplicate check
    if not skip_duplicate and not has_errors:
        dup_warnings = duplicate_check(file_path, resources_dir)
        messages.extend(dup_warnings)

    if has_errors:
        messages.append("Pre-flight FAILED — fix errors above")
        return False, messages

    if not issues:
        messages.append("Pre-flight passed")

    return True, messages


def main():
    parser = argparse.ArgumentParser(description="Validate Fusion workflow YAML files (local only)")
    parser.add_argument("files", nargs="+", metavar="FILE", help="YAML file(s) to validate")
    parser.add_argument("--skip-duplicate-check", action="store_true",
                        help="Skip checking for duplicate workflow names")
    parser.add_argument("--resources-dir", default="resources/workflows/",
                        help="Directory to scan for existing workflows (default: resources/workflows/)")
    args = parser.parse_args()

    all_passed = True
    for fp in args.files:
        print(f"\n  {os.path.basename(fp)}")
        passed, messages = validate_file(
            fp,
            skip_duplicate=args.skip_duplicate_check,
            resources_dir=args.resources_dir,
        )
        for m in messages:
            if m.startswith(("ERROR", "WARNING")) or "FAILED" in m:
                prefix = "    \u2717"
            else:
                prefix = "    \u2713"
            print(f"{prefix} {m}")
        if not passed:
            all_passed = False
        print()

    if all_passed:
        print("All files passed validation.")
    else:
        print("Some files failed validation.")
        sys.exit(1)


if __name__ == "__main__":
    main()
