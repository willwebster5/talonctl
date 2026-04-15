"""
Base Resource Provider Interface

This module defines the abstract base class that all resource providers must implement.
Each provider handles CRUD operations for a specific resource type (detections, workflows,
saved searches, lookup files, correlation rules).
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import hashlib
import json


class ResourceAction(Enum):
    """Represents the type of change to be made to a resource"""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"  # Delete + recreate (e.g., immutable field change like type)
    NO_CHANGE = "no-change"


@dataclass
class ResourceChange:
    """
    Represents a planned change to a resource.

    Used during the plan phase to show users what will happen.
    """

    action: ResourceAction
    resource_type: str
    resource_name: str
    resource_id: Optional[str] = None
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    changes: Optional[Dict[str, Any]] = None  # Detailed diff for updates
    template_path: Optional[str] = None


class BaseResourceProvider(ABC):
    """
    Abstract base class for all resource providers.

    Each provider implements CRUD operations for a specific resource type
    (detections, workflows, saved searches, lookup files, correlation rules).

    Providers are responsible for:
    - Validating resource templates
    - Fetching remote state from CrowdStrike APIs
    - Planning changes (create/update/delete)
    - Applying changes to CrowdStrike
    - Extracting dependencies from templates
    - Computing content hashes for change detection
    """

    def __init__(self, falcon_client: Any, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the resource provider.

        Args:
            falcon_client: FalconPy APIHarnessV2 client instance
            config: Optional configuration dictionary for provider-specific settings
        """
        self.falcon = falcon_client
        self.config = config or {}
        self.resource_type = self.get_resource_type()

    @abstractmethod
    def get_resource_type(self) -> str:
        """
        Return the resource type identifier.

        Examples: 'detection', 'workflow', 'saved_search', 'lookup_file', 'correlation_rule'

        Returns:
            String identifier for this resource type
        """
        pass

    @abstractmethod
    def validate_template(self, template: Dict[str, Any]) -> List[str]:
        """
        Validate a resource template.

        Checks that the template has all required fields, correct data types,
        and valid values. Provider-specific validation (e.g., FQL syntax for detections).

        Args:
            template: The resource template to validate

        Returns:
            List of validation error messages (empty list if valid)
        """
        pass

    @abstractmethod
    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch the current state of a resource from CrowdStrike API.

        Used during plan phase to compare local templates with remote state.

        Args:
            resource_id: The unique identifier for the resource in CrowdStrike

        Returns:
            Dictionary containing current resource state, or None if resource doesn't exist
        """
        pass

    @abstractmethod
    def plan_create(self, template: Dict[str, Any], template_path: str) -> ResourceChange:
        """
        Plan the creation of a new resource.

        Args:
            template: The resource template defining the new resource
            template_path: Path to the template file (for tracking)

        Returns:
            ResourceChange object with action=CREATE
        """
        pass

    @abstractmethod
    def plan_update(
        self, template: Dict[str, Any], current_state: Dict[str, Any], template_path: str
    ) -> ResourceChange:
        """
        Plan an update to an existing resource.

        Compares template with current remote state to determine what changed.

        Args:
            template: The new resource template
            current_state: Current state from CrowdStrike API
            template_path: Path to the template file

        Returns:
            ResourceChange object with action=UPDATE or NO_CHANGE
        """
        pass

    @abstractmethod
    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        """
        Plan the deletion of a resource.

        Args:
            resource_id: ID of the resource to delete
            resource_name: Human-readable name of the resource

        Returns:
            ResourceChange object with action=DELETE
        """
        pass

    @abstractmethod
    def apply_create(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new resource in CrowdStrike.

        Args:
            template: The resource template

        Returns:
            Dictionary with resource metadata including:
            - id: The unique resource ID assigned by CrowdStrike
            - Any provider-specific metadata needed for state tracking

        Raises:
            Exception: If creation fails
        """
        pass

    @abstractmethod
    def apply_update(self, resource_id: str, template: Dict[str, Any], current_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing resource in CrowdStrike.

        Args:
            resource_id: ID of the resource to update
            template: The new resource template
            current_state: Current state (may be needed for partial updates)

        Returns:
            Dictionary with updated resource metadata

        Raises:
            Exception: If update fails
        """
        pass

    @abstractmethod
    def apply_delete(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Delete a resource from CrowdStrike.

        Args:
            resource_id: ID of the resource to delete

        Returns:
            Dict with deletion metadata, at minimum {'id': resource_id}.
            Returns None only if the resource was already absent (idempotent delete).

        Raises:
            Exception: If deletion fails
        """
        pass

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        """
        Compute SHA256 hash of template content.

        Used for change detection - if hash differs from state, resource has changed.
        Providers can override this to customize which fields are included in the hash.

        Args:
            template: The resource template

        Returns:
            SHA256 hash as hex string
        """
        # Sort keys for consistent hashing
        content = json.dumps(template, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def extract_dependencies(self, template: Dict[str, Any]) -> List[str]:
        """
        Extract dependency references from a template.

        Default implementation returns empty list. Providers should override
        to parse template for references to other resources, such as:
        - $saved_search.aws_service_accounts() in FQL queries
        - lookup("trusted_ips.csv") in detection filters
        - detection.aws_root_login in workflow triggers

        Args:
            template: The resource template

        Returns:
            List of resource IDs this resource depends on, in format "type.name"
            Example: ["saved_search.aws_service_accounts", "lookup_file.trusted_ips"]
        """
        return []

    def get_display_name(self, template: Dict[str, Any]) -> str:
        """
        Get a human-readable display name for the resource.

        Default implementation looks for 'name' field. Providers can override.

        Args:
            template: The resource template

        Returns:
            Display name for the resource
        """
        return template.get("name", "Unknown")

    def to_template(self, remote_resource: dict) -> dict:
        """
        Convert a remote API resource (normalized format from _fetch_all_remote_*())
        into a YAML template dict suitable for writing to a template file.

        Providers must override this to map their normalized API fields
        to the template format used by their YAML files.

        Args:
            remote_resource: Normalized resource dict from the provider's fetch method

        Returns:
            Template dict ready for YAML serialization

        Raises:
            NotImplementedError: If the provider does not support import
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support import")

    def suggest_path(self, template: dict) -> str:
        """
        Suggest a relative file path for a generated template.

        The path is relative to the project's resources/ directory.
        Providers should override this to place templates in the correct
        subdirectory with appropriate naming.

        Args:
            template: The template dict (as returned by to_template())

        Returns:
            Relative path string (e.g., 'detections/aws/aws___cloudtrail___console_root_login.yaml')

        Raises:
            NotImplementedError: If the provider does not support import
        """
        raise NotImplementedError(f"{self.__class__.__name__} does not support import")

    @staticmethod
    def _name_to_resource_id(name: str) -> str:
        """
        Convert a display name to a snake_case resource_id.

        Uses '___' (triple underscore) as section separator for ' - ',
        matching the existing naming convention in the codebase.

        Example:
            'AWS - CloudTrail - Console Root Login' -> 'aws___cloudtrail___console_root_login'
            'My Simple Rule' -> 'my_simple_rule'

        Args:
            name: Human-readable display name

        Returns:
            snake_case resource_id string
        """
        import re

        # Use null byte as placeholder for ' - ' section separator
        rid = name.replace(" - ", "\x00")
        rid = rid.replace(" ", "_")
        rid = rid.lower()
        rid = re.sub(r"[^a-z0-9_\x00]", "", rid)
        rid = rid.replace("\x00", "___")
        return rid.strip("_")
