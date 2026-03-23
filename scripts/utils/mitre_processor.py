"""
MITRE ATT&CK Processor

Utilities for processing, validating, and normalizing MITRE ATT&CK framework
references in detection templates.

Handles extraction of MITRE IDs from human-readable names and validation
of tactic/technique values for API submission.
"""

import re
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class MitreProcessor:
    """
    Processes MITRE ATT&CK references in detection templates.

    Features:
    - Extract ID codes from full names (e.g., "Exfiltration (TA0010)" -> "TA0010")
    - Validate tactic and technique values
    - Normalize template data for API submission
    - Support both array and legacy formats
    """

    # Valid MITRE ID patterns
    TACTIC_PATTERN = re.compile(r'^TA\d{4}$')
    TECHNIQUE_PATTERN = re.compile(r'^T\d{4}(?:\.\d{3})?$')

    # Pattern to extract ID from parentheses: "Name (ID)"
    ID_EXTRACTION_PATTERN = re.compile(r'\((TA\d{4}|T\d{4}(?:\.\d{3})?)\)$')

    # Placeholder values to reject
    PLACEHOLDER_PATTERNS = [
        r'^not\s+specified$',
        r'^n/?a$',
        r'^unknown$',
        r'^none$',
        r'^unspecified$',
    ]

    @staticmethod
    def extract_id(value: str) -> str:
        """
        Extract MITRE ATT&CK ID code from full name format.

        The CrowdStrike API expects just the ID code (e.g., "TA0010", "T1543"),
        but templates may contain human-readable full names with codes in
        parentheses (e.g., "Exfiltration (TA0010)").

        This function extracts the ID code from the parenthetical format while
        maintaining backward compatibility for templates that already use just IDs.

        Examples:
            "Exfiltration (TA0010)" -> "TA0010"
            "TA0010" -> "TA0010" (already just ID)
            "T1048.001" -> "T1048.001" (subtechnique)
            "Persistence (TA0003)" -> "TA0003"
            "Create or Modify System Process (T1543)" -> "T1543"

        Args:
            value: MITRE ATT&CK tactic or technique value (full name or ID)

        Returns:
            Extracted ID code (e.g., "TA0010", "T1543", "T1048.001")
        """
        if not value:
            return value

        # Try to extract ID from parentheses
        match = MitreProcessor.ID_EXTRACTION_PATTERN.search(value)
        if match:
            return match.group(1)

        # If no parentheses, assume it's already just the ID
        return value

    @staticmethod
    def is_valid(value: str) -> bool:
        """
        Check if a MITRE ATT&CK value is valid for API submission.

        Invalid values include:
        - None or empty strings
        - Placeholder values like "Not Specified", "N/A", "Unknown"
        - Values that don't match MITRE ID patterns after extraction

        Args:
            value: MITRE ATT&CK tactic or technique value

        Returns:
            True if valid, False otherwise
        """
        if not value or not value.strip():
            return False

        # Check for placeholder values (case-insensitive)
        value_lower = value.strip().lower()
        for pattern in MitreProcessor.PLACEHOLDER_PATTERNS:
            if re.match(pattern, value_lower):
                return False

        # Extract ID and validate format
        extracted = MitreProcessor.extract_id(value)

        if not extracted or not extracted.strip():
            return False

        # Must match MITRE ID pattern (tactic or technique)
        is_tactic = MitreProcessor.TACTIC_PATTERN.match(extracted)
        is_technique = MitreProcessor.TECHNIQUE_PATTERN.match(extracted)

        return bool(is_tactic or is_technique)

    @staticmethod
    def normalize_mitre_array(mitre_array: list) -> List[Dict[str, Any]]:
        """
        Normalize MITRE ATT&CK array format for API submission.

        Processes each entry in the array:
        - Handles string format: "Tactic (TAxxxx):Technique (Txxxx)"
        - Handles dict format: {"tactic_id": "...", "technique_id": "..."}
        - Extracts ID codes from full names
        - Filters out invalid/placeholder values

        Args:
            mitre_array: List of MITRE ATT&CK entries (strings or dicts)

        Returns:
            Normalized list of dicts with tactic_id/technique_id for API
        """
        normalized = []

        for entry in mitre_array:
            normalized_entry = {}

            if isinstance(entry, str):
                # String format: "Tactic (TAxxxx):Technique (Txxxx)"
                if ':' in entry:
                    tactic_part, technique_part = entry.split(':', 1)
                    tactic_id = MitreProcessor.extract_id(tactic_part.strip())
                    technique_id = MitreProcessor.extract_id(technique_part.strip())
                    if MitreProcessor.is_valid(tactic_id):
                        normalized_entry['tactic_id'] = tactic_id
                    if MitreProcessor.is_valid(technique_id):
                        normalized_entry['technique_id'] = technique_id
                else:
                    # Single value (tactic only)
                    extracted = MitreProcessor.extract_id(entry.strip())
                    if MitreProcessor.is_valid(extracted):
                        normalized_entry['tactic_id'] = extracted

            elif isinstance(entry, dict):
                # Dict format: {"tactic_id": "...", "technique_id": "..."}
                if 'tactic_id' in entry:
                    if MitreProcessor.is_valid(entry['tactic_id']):
                        normalized_entry['tactic_id'] = MitreProcessor.extract_id(entry['tactic_id'])

                if 'technique_id' in entry:
                    if MitreProcessor.is_valid(entry['technique_id']):
                        normalized_entry['technique_id'] = MitreProcessor.extract_id(entry['technique_id'])

                # Support legacy field names without _id suffix
                if 'tactic' in entry and 'tactic_id' not in normalized_entry:
                    if MitreProcessor.is_valid(entry['tactic']):
                        normalized_entry['tactic_id'] = MitreProcessor.extract_id(entry['tactic'])

                if 'technique' in entry and 'technique_id' not in normalized_entry:
                    if MitreProcessor.is_valid(entry['technique']):
                        normalized_entry['technique_id'] = MitreProcessor.extract_id(entry['technique'])

            # Only add entry if it has at least one valid field
            if normalized_entry:
                normalized.append(normalized_entry)

        return normalized

    @staticmethod
    def normalize_template_mitre(template: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize MITRE ATT&CK fields in a template for API submission.

        Handles both array format (mitre_attack) and legacy top-level fields
        (tactic, technique).

        Args:
            template: Detection template with MITRE ATT&CK references

        Returns:
            Dictionary with normalized MITRE fields to merge into payload,
            or None if no MITRE references found
        """
        mitre_fields = {}

        # Handle array format (modern)
        if 'mitre_attack' in template:
            normalized_array = MitreProcessor.normalize_mitre_array(template['mitre_attack'])

            # Only add if we have valid entries
            if normalized_array:
                mitre_fields['mitre_attack'] = normalized_array

        # Handle legacy format: top-level tactic/technique fields
        elif 'tactic' in template or 'technique' in template:
            if 'tactic' in template and MitreProcessor.is_valid(template['tactic']):
                mitre_fields['tactic'] = MitreProcessor.extract_id(template['tactic'])

            if 'technique' in template and MitreProcessor.is_valid(template['technique']):
                mitre_fields['technique'] = MitreProcessor.extract_id(template['technique'])

        return mitre_fields if mitre_fields else None

    @staticmethod
    def validate_template_mitre(template: Dict[str, Any]) -> List[str]:
        """
        Validate MITRE ATT&CK references in a template.

        Returns list of validation errors (empty if valid).

        Args:
            template: Detection template to validate

        Returns:
            List of error messages (empty if all valid)
        """
        errors = []

        # Validate array format
        if 'mitre_attack' in template:
            mitre = template['mitre_attack']

            if not isinstance(mitre, list):
                errors.append("'mitre_attack' must be a list")
            else:
                for idx, entry in enumerate(mitre):
                    if isinstance(entry, str):
                        # String format: "Tactic (TAxxxx):Technique (Txxxx)"
                        # Validate that we can extract at least one valid ID
                        if ':' in entry:
                            tactic_part, technique_part = entry.split(':', 1)
                            tactic_valid = MitreProcessor.is_valid(tactic_part.strip())
                            technique_valid = MitreProcessor.is_valid(technique_part.strip())
                            if not (tactic_valid or technique_valid):
                                errors.append(
                                    f"mitre_attack[{idx}] string '{entry}' contains no valid MITRE IDs"
                                )
                        else:
                            if not MitreProcessor.is_valid(entry.strip()):
                                errors.append(
                                    f"mitre_attack[{idx}] string '{entry}' is not a valid MITRE reference"
                                )
                    elif isinstance(entry, dict):
                        # Dict format: {"tactic_id": "...", "technique_id": "..."}
                        has_tactic = 'tactic' in entry or 'tactic_id' in entry
                        has_technique = 'technique' in entry or 'technique_id' in entry

                        if not (has_tactic or has_technique):
                            errors.append(
                                f"mitre_attack[{idx}] must have 'tactic', 'technique', "
                                f"'tactic_id', or 'technique_id'"
                            )

        # Legacy format validation is more lenient (optional fields)

        return errors
