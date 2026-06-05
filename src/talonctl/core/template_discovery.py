"""
Template Discovery Engine

Discovers and loads resource templates from the resources/ directory tree.
Supports filtering by resource type, tags, and name patterns.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, TYPE_CHECKING
from dataclasses import dataclass
import fnmatch

from talonctl.core.envelope_loader import load_envelopes

if TYPE_CHECKING:
    from talonctl.core.envelope import Envelope

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredTemplate:
    """Represents a discovered template with metadata.

    Envelope-backed: the canonical v2 :class:`Envelope` is the source of truth.
    ``template_data`` is a read-only compatibility property reconstructing the
    legacy flat dict consumers still read (via ``envelope.to_working_dict()``).
    """

    resource_type: str
    name: str  # Stable resource identifier (envelope.resource_id)
    file_path: Path
    tags: List[str]
    envelope: "Envelope" = None  # default so non-envelope construction doesn't break
    display_name: Optional[str] = None  # Human-readable name (metadata 'name')

    @property
    def template_data(self) -> Dict:
        """Legacy flat dict reconstructed from the envelope (with _template_path)."""
        return self.envelope.to_working_dict()

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
                for template in self._load_template(yaml_file, resource_type):
                    templates.append(template)
                    # Cache template
                    self._template_cache[template.resource_id] = template
            except Exception as e:
                logger.error(f"Error loading template {yaml_file}: {e}")

        logger.info(f"Discovered {len(templates)} {resource_type} templates")
        return templates

    def _load_template(self, file_path: Path, expected_type: str) -> List[DiscoveredTemplate]:
        """
        Load and validate a template file via the single envelope parse path.

        Delegates to ``load_envelopes`` so v1 (flat dict) and v2 (apiVersion:
        talon/v2) files share one parser. A single file may declare multiple
        resources (multi-doc ``---`` or a top-level list), so this returns a
        list of templates.

        Args:
            file_path: Path to template YAML file
            expected_type: Expected resource type (from the directory)

        Returns:
            List of DiscoveredTemplate (empty if the file fails to parse or
            every declared resource is a kind/dir mismatch).
        """
        try:
            envelopes = load_envelopes(file_path, default_resource_type=expected_type)
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return []

        templates: List[DiscoveredTemplate] = []
        origin = str(file_path.resolve())

        for env in envelopes:
            # Envelope validation owns identity/name checks; here we only guard
            # the kind/dir invariant (a resource authored in the wrong dir).
            if env.resource_type != expected_type:
                logger.warning(
                    f"Template {file_path} kind/dir mismatch: directory implies "
                    f"'{expected_type}' but kind '{env.kind}' maps to '{env.resource_type}' — skipping"
                )
                continue

            env.origin_path = origin  # re-injected as _template_path by to_working_dict

            templates.append(
                DiscoveredTemplate(
                    resource_type=env.resource_type,
                    name=env.resource_id,  # stable identifier for state tracking
                    file_path=file_path,
                    tags=env.metadata.get("tags", []),
                    envelope=env,
                    display_name=env.metadata.get("name"),
                )
            )

        return templates

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
