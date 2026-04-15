"""
Template Discovery Engine

Discovers and loads resource templates from the resources/ directory tree.
Supports filtering by resource type, tags, and name patterns.
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import fnmatch

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredTemplate:
    """Represents a discovered template with metadata"""

    resource_type: str
    name: str  # Stable resource identifier (from resource_id field or fallback to name)
    file_path: Path
    template_data: Dict
    tags: List[str]
    display_name: Optional[str] = None  # Human-readable name (from name field)

    @property
    def resource_id(self) -> str:
        """Get fully-qualified resource ID (e.g., 'detection.aws_root_login')"""
        return f"{self.resource_type}.{self.name}"


class TemplateDiscovery:
    """
    Discovers resource templates from the resources/ directory.

    Directory structure:
        resources/
        ├── detections/
        ├── workflows/
        ├── saved_searches/
        └── lookup_files/

    Each YAML file must have a 'type' field indicating the resource type.
    """

    # Valid resource types
    VALID_RESOURCE_TYPES = [
        "detection",
        "workflow",
        "saved_search",
        "lookup_file",
        "rtr_script",
        "rtr_put_file",
        "dashboard",
    ]

    # Default resources directory
    DEFAULT_RESOURCES_DIR = "resources"

    def __init__(self, resources_dir: Optional[Path] = None, project_root: Optional[Path] = None):
        """
        Initialize template discovery

        Args:
            resources_dir: Path to resources directory (defaults to 'resources')
            project_root: Project root directory (auto-detected if not provided)
        """
        if project_root is None:
            project_root = self._find_project_root()

        if resources_dir is None:
            resources_dir = project_root / self.DEFAULT_RESOURCES_DIR

        self.resources_dir = Path(resources_dir)
        self.project_root = Path(project_root)
        self._template_cache: Dict[str, DiscoveredTemplate] = {}

    def _find_project_root(self) -> Path:
        """Find project root directory by walking up from CWD looking for .crowdstrike/."""
        from talonctl.project import find_project_root

        return find_project_root()

    def discover_all(
        self,
        resource_types: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        names: Optional[List[str]] = None,
    ) -> Dict[str, List[DiscoveredTemplate]]:
        """
        Discover all templates matching filters

        Args:
            resource_types: Filter by resource types (e.g., ['detection', 'workflow'])
            tags: Filter by tags (e.g., ['aws', 'authentication'])
            names: Filter by name patterns (supports glob, e.g., ['aws_*', '*_login'])

        Returns:
            Dictionary mapping resource type to list of templates
        """
        discovered: Dict[str, List[DiscoveredTemplate]] = {rt: [] for rt in self.VALID_RESOURCE_TYPES}

        # Apply resource type filter
        types_to_scan = resource_types if resource_types else self.VALID_RESOURCE_TYPES

        for resource_type in types_to_scan:
            if resource_type not in self.VALID_RESOURCE_TYPES:
                logger.warning(f"Invalid resource type: {resource_type}")
                continue

            templates = self._discover_by_type(resource_type)

            # Apply tag filter
            if tags:
                templates = self._filter_by_tags(templates, tags)

            # Apply name filter
            if names:
                templates = self._filter_by_names(templates, names)

            discovered[resource_type] = templates

        return discovered

    def _discover_by_type(self, resource_type: str) -> List[DiscoveredTemplate]:
        """
        Discover all templates of a specific type

        Args:
            resource_type: Resource type to discover

        Returns:
            List of discovered templates
        """
        templates = []

        # Map resource type to directory name
        type_to_dir = {
            "detection": "detections",
            "workflow": "workflows",
            "saved_search": "saved_searches",
            "lookup_file": "lookup_files",
            "rtr_script": "rtr_scripts",
            "rtr_put_file": "rtr_put_files",
            "dashboard": "dashboards",
        }

        dir_name = type_to_dir.get(resource_type)
        if not dir_name:
            logger.warning(f"Unknown resource type: {resource_type}")
            return templates

        type_dir = self.resources_dir / dir_name

        if not type_dir.exists():
            logger.debug(f"Directory not found: {type_dir}")
            return templates

        # Recursively find all YAML files
        for yaml_file in type_dir.rglob("*.yaml"):
            try:
                template = self._load_template(yaml_file, resource_type)
                if template:
                    templates.append(template)
                    # Cache template
                    self._template_cache[template.resource_id] = template
            except Exception as e:
                logger.error(f"Error loading template {yaml_file}: {e}")

        logger.info(f"Discovered {len(templates)} {resource_type} templates")
        return templates

    def _load_template(self, file_path: Path, expected_type: str) -> Optional[DiscoveredTemplate]:
        """
        Load and validate a template file

        Args:
            file_path: Path to template YAML file
            expected_type: Expected resource type

        Returns:
            DiscoveredTemplate or None if invalid
        """
        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict):
                logger.warning(f"Template {file_path} is not a valid YAML dictionary")
                return None

            # Infer type from directory if missing (supports legacy templates)
            # Note: 'type' can be a resource type (detection, saved_search) OR a rule
            # sub-type (behavioral). Sub-types like 'behavioral' are valid detection rules
            # that get passed through to the API as the rule type.
            DETECTION_SUBTYPES = {"behavioral"}

            template_type = data.get("type")
            if not template_type:
                logger.debug(f"Template {file_path} missing 'type' field, inferring as {expected_type}")
                template_type = expected_type
            elif template_type in DETECTION_SUBTYPES and expected_type == "detection":
                # 'behavioral' is a sub-type of detection, not a different resource type
                # Keep 'type: behavioral' in data for the API, but route as detection
                template_type = expected_type
            elif template_type != expected_type:
                logger.warning(f"Template {file_path} type mismatch: expected {expected_type}, got {template_type}")
                return None

            # Extract resource_id and name
            # Phase 1: Support resource_id field as stable identifier
            resource_id = data.get("resource_id")  # Stable IaC identifier
            display_name = data.get("name")  # Human-readable display name

            if not display_name:
                logger.warning(f"Template {file_path} missing 'name' field")
                return None

            # Determine stable identifier
            # If resource_id exists, use it as the stable identifier
            # Otherwise fall back to name for backward compatibility
            stable_id = resource_id if resource_id else display_name

            logger.debug(
                f"Template {file_path}: resource_id={resource_id}, name={display_name}, using stable_id={stable_id}"
            )

            # Extract tags
            tags = data.get("tags", [])
            if not isinstance(tags, list):
                tags = []

            # Add template path to data for providers that need to resolve relative paths
            # Use resolve() to ensure absolute path for CI/CD compatibility
            data["_template_path"] = str(file_path.resolve())

            return DiscoveredTemplate(
                resource_type=template_type,
                name=stable_id,  # Use stable identifier for state tracking
                file_path=file_path,
                template_data=data,
                tags=tags,
                display_name=display_name,  # Store display name separately
            )

        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return None

    def _filter_by_tags(self, templates: List[DiscoveredTemplate], tags: List[str]) -> List[DiscoveredTemplate]:
        """
        Filter templates by tags (AND logic)

        Args:
            templates: List of templates to filter
            tags: Required tags (all must match)

        Returns:
            Filtered list of templates
        """
        filtered = []
        tag_set = set(tags)

        for template in templates:
            template_tags = set(template.tags)
            if tag_set.issubset(template_tags):
                filtered.append(template)

        return filtered

    def _filter_by_names(self, templates: List[DiscoveredTemplate], patterns: List[str]) -> List[DiscoveredTemplate]:
        """
        Filter templates by name patterns (glob support)

        Args:
            templates: List of templates to filter
            patterns: Name patterns (supports wildcards)

        Returns:
            Filtered list of templates
        """
        filtered = []

        for template in templates:
            for pattern in patterns:
                if fnmatch.fnmatch(template.name, pattern):
                    filtered.append(template)
                    break

        return filtered

    def get_template(self, resource_id: str) -> Optional[DiscoveredTemplate]:
        """
        Get a specific template by resource ID

        Args:
            resource_id: Fully-qualified resource ID (e.g., 'detection.aws_root_login')

        Returns:
            DiscoveredTemplate or None if not found
        """
        # Check cache first
        if resource_id in self._template_cache:
            return self._template_cache[resource_id]

        # Parse resource ID
        parts = resource_id.split(".", 1)
        if len(parts) != 2:
            logger.error(f"Invalid resource ID format: {resource_id}")
            return None

        resource_type, name = parts

        # Discover templates of this type
        templates = self._discover_by_type(resource_type)

        # Find matching template
        for template in templates:
            if template.name == name:
                return template

        return None

    def get_all_resource_ids(self) -> Set[str]:
        """
        Get all resource IDs from discovered templates

        Returns:
            Set of resource IDs
        """
        all_templates = self.discover_all()
        resource_ids = set()

        for templates_list in all_templates.values():
            for template in templates_list:
                resource_ids.add(template.resource_id)

        return resource_ids

    def clear_cache(self):
        """Clear the template cache"""
        self._template_cache.clear()
