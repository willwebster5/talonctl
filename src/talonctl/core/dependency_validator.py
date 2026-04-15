"""
Dependency Validator

Static analysis of saved search ($function_name()) references in detection CQL.
Verifies that every referenced function corresponds to a discoverable saved search template.
"""

import re
import logging
from dataclasses import dataclass
from typing import List, Set

logger = logging.getLogger(__name__)

# Pattern: $function_name() — optionally with arguments inside parens
FUNCTION_REF_PATTERN = re.compile(r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')


@dataclass
class DependencyIssue:
    """A single broken dependency found in a detection."""
    detection_id: str      # e.g., "detection.aws_broken_rule"
    detection_name: str    # Human-readable name
    missing_function: str  # The $function_name that has no matching saved search
    cql_snippet: str       # Context around the reference (for error messages)


class DependencyValidator:
    """
    Validates that all $function_name() references in detection CQL
    resolve to known saved search templates.

    Usage:
        from core.template_discovery import TemplateDiscovery
        discovery = TemplateDiscovery()
        validator = DependencyValidator(discovery)
        issues = validator.validate_all()
    """

    # Built-in LogScale functions that look like saved search calls but are not.
    # These use the $variable syntax but are not user-defined saved searches.
    BUILTIN_FUNCTIONS: Set[str] = set()

    def __init__(self, template_discovery):
        """
        Args:
            template_discovery: A TemplateDiscovery instance (or mock with discover_all()).
        """
        self._discovery = template_discovery
        self._known_functions: Set[str] = set()
        self._loaded = False

    def _load_known_functions(self) -> None:
        """Build the set of available saved search names from template discovery."""
        if self._loaded:
            return
        all_templates = self._discovery.discover_all()
        for ss in all_templates.get("saved_search", []):
            self._known_functions.add(ss.name)
        self._loaded = True
        logger.debug(f"Loaded {len(self._known_functions)} known saved search functions")

    @staticmethod
    def extract_function_references(cql: str) -> Set[str]:
        """
        Extract all $function_name() references from a CQL string.

        Args:
            cql: The CQL query string (may contain comments, newlines, etc.)

        Returns:
            Set of function names (without the $ prefix or parentheses).
        """
        return set(FUNCTION_REF_PATTERN.findall(cql))

    def validate_detection(self, detection_template) -> List[DependencyIssue]:
        """
        Validate a single detection template's saved search dependencies.

        Args:
            detection_template: A DiscoveredTemplate (or mock) with .name, .resource_id,
                                and .template_data attributes.

        Returns:
            List of DependencyIssue for each broken reference. Empty if all valid.
        """
        self._load_known_functions()

        search = detection_template.template_data.get("search", {})
        cql = search.get("filter", "") or search.get("query", "")
        if not cql:
            return []

        refs = self.extract_function_references(cql)
        issues = []

        for func_name in sorted(refs):
            if func_name in self._known_functions:
                continue
            if func_name in self.BUILTIN_FUNCTIONS:
                continue

            # Find a snippet around the reference for context
            snippet_match = re.search(
                rf'.{{0,30}}\${re.escape(func_name)}\s*\(.{{0,30}}',
                cql
            )
            snippet = snippet_match.group(0).strip() if snippet_match else f"${func_name}()"

            issues.append(DependencyIssue(
                detection_id=detection_template.resource_id,
                detection_name=getattr(detection_template, 'display_name', None) or detection_template.name,
                missing_function=func_name,
                cql_snippet=snippet,
            ))

        return issues

    def validate_all(self) -> List[DependencyIssue]:
        """
        Validate all detection templates for broken saved search dependencies.

        Returns:
            List of all DependencyIssue found across all detections.
        """
        self._load_known_functions()
        all_templates = self._discovery.discover_all()
        all_issues = []

        for detection in all_templates.get("detection", []):
            issues = self.validate_detection(detection)
            all_issues.extend(issues)

        if all_issues:
            logger.warning(
                f"Found {len(all_issues)} broken dependencies across "
                f"{len(set(i.detection_id for i in all_issues))} detections"
            )
        else:
            logger.info("All detection dependencies are valid")

        return all_issues
