"""
RTRScriptProvider - CrowdStrike Real-Time Response Custom Scripts

This provider implements the BaseResourceProvider interface for managing
CrowdStrike RTR custom scripts as Infrastructure as Code resources.

Manages scripts used with the RTR 'runscript' command for incident response
and investigation automation.
"""

import json
import yaml
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

# Import FalconPy service class for RTR Admin
from falconpy import RealTimeResponseAdmin

# Import core infrastructure
import sys
from pathlib import Path as PathLib

def find_scripts_dir():
    """Find scripts directory from any subdirectory"""
    current = PathLib(__file__).resolve().parent
    while current.name != 'scripts' and current != current.parent:
        current = current.parent
    return current if current.name == 'scripts' else PathLib(__file__).parent

SCRIPTS_DIR = find_scripts_dir()
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from core import (
    BaseResourceProvider,
    ResourceAction,
    ResourceChange
)

logger = logging.getLogger(__name__)


class RTRScriptProvider(BaseResourceProvider):
    """
    Provider for CrowdStrike RTR Custom Scripts

    Manages RTR scripts as IaC resources with support for:
    - Template validation (name, platform, permissions, content)
    - Remote state fetching from RTR Admin API
    - Change detection and planning
    - Script creation, updates, and deletion
    - Multi-platform script support (Windows, Linux, Mac)
    - Permission levels: private, group, public

    API Endpoints:
    - Create: POST /real-time-response/entities/scripts/v1
    - Read: GET /real-time-response/entities/scripts/v2
    - Update: PATCH /real-time-response/entities/scripts/v1
    - Delete: DELETE /real-time-response/entities/scripts/v1
    - List: GET /real-time-response/queries/scripts/v1
    """

    # Valid platform options
    VALID_PLATFORMS = ['windows', 'mac', 'linux']

    # Valid permission types
    VALID_PERMISSION_TYPES = ['private', 'group', 'public']

    def __init__(self, falcon_client: Any, config: Optional[Dict[str, Any]] = None):
        """
        Initialize RTR script provider

        Args:
            falcon_client: Authenticated FalconPy APIHarnessV2 instance (used to extract credentials)
            config: Optional provider configuration
        """
        self.falcon = falcon_client
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self._remote_scripts_cache: Optional[Dict[str, Dict[str, Any]]] = None

        # Create RealTimeResponseAdmin service class instance for RTR operations
        # Service class is proven to work while Uber class returns 403 errors
        # Note: API client is optional for validation-only operations
        self.rtr_admin = None

        try:
            # Try to get credentials from config first (passed from orchestrator)
            creds = self.config.get('credentials')

            if creds:
                client_id = creds.get('falcon_client_id')
                client_secret = creds.get('falcon_client_secret')
                base_url = creds.get('base_url', 'US1')
            else:
                # Fallback: try to extract from falcon_client's auth object
                auth_object = getattr(falcon_client, 'auth_object', None)
                if auth_object:
                    client_id = auth_object.creds.get('client_id')
                    client_secret = auth_object.creds.get('client_secret')
                    base_url = getattr(falcon_client, 'base_url', 'US1')
                else:
                    # No credentials available - this is OK for validation mode
                    logger.info("RTR Script Provider: No credentials available (validation mode)")
                    return

            self.rtr_admin = RealTimeResponseAdmin(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url
            )
            logger.info("RTR Script Provider: Using RealTimeResponseAdmin service class")

        except Exception as e:
            logger.warning(f"Failed to initialize RealTimeResponseAdmin service class: {e}")
            logger.info("RTR Script Provider running in validation-only mode")

    def get_resource_type(self) -> str:
        """Return resource type identifier"""
        return "rtr_script"

    def validate_template(self, template: Dict[str, Any]) -> List[str]:
        """
        Validate RTR script template

        Args:
            template: RTR script template data

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Required fields
        required_fields = ['name', 'description', 'platform']
        for field in required_fields:
            if field not in template:
                errors.append(f"Missing required field: {field}")

        # Validate name is non-empty string
        name = template.get('name', '')
        if not isinstance(name, str) or not name.strip():
            errors.append("'name' must be a non-empty string")

        # Validate description
        description = template.get('description', '')
        if not isinstance(description, str) or not description.strip():
            errors.append("'description' must be a non-empty string")

        # Validate platform (can be string or list)
        platform = template.get('platform')
        if platform:
            # Convert to list if string
            platforms = [platform] if isinstance(platform, str) else platform

            if not isinstance(platforms, list):
                errors.append("'platform' must be a string or list of strings")
            else:
                for p in platforms:
                    if p not in self.VALID_PLATFORMS:
                        errors.append(
                            f"Invalid platform: {p}. "
                            f"Must be one of {self.VALID_PLATFORMS}"
                        )

        # Validate permission_type if provided
        permission_type = template.get('permission_type', 'group')
        if permission_type not in self.VALID_PERMISSION_TYPES:
            errors.append(
                f"Invalid permission_type: {permission_type}. "
                f"Must be one of {self.VALID_PERMISSION_TYPES}"
            )

        # Validate content (must have either 'content' or 'file_path')
        content = template.get('content')
        file_path = template.get('file_path')

        if not content and not file_path:
            errors.append("Must provide either 'content' or 'file_path'")

        if content and not isinstance(content, str):
            errors.append("'content' must be a string")

        if file_path and not isinstance(file_path, str):
            errors.append("'file_path' must be a string")

        # Validate comments_for_audit_log if provided
        if 'comments_for_audit_log' in template:
            if not isinstance(template['comments_for_audit_log'], str):
                errors.append("'comments_for_audit_log' must be a string")

        return errors

    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch current state of an RTR script from API

        Args:
            resource_id: The ID of the RTR script

        Returns:
            Current script state or None if not found
        """
        if not self.rtr_admin:
            logger.debug("RTR admin not initialized - skipping remote state fetch")
            return None

        try:
            # Use service class method (PEP8 syntax)
            response = self.rtr_admin.get_scripts_v2(ids=resource_id)

            if response.get('status_code') == 200:
                body = response.get('body', {})
                resources = body.get('resources', [])

                if resources and len(resources) > 0:
                    script_data = resources[0]
                    logger.debug(f"Fetched RTR script: {script_data.get('name')}")
                    return script_data

            return None

        except Exception as e:
            logger.error(f"Failed to fetch RTR script {resource_id}: {e}")
            return None

    def _fetch_all_remote_scripts(self) -> Dict[str, Dict[str, Any]]:
        """
        Fetch all RTR scripts from API

        Uses the RTR Admin API to retrieve all custom scripts.
        Supports pagination.

        Returns:
            Dictionary of scripts indexed by name
        """
        if not self.rtr_admin:
            logger.debug("RTR admin not initialized - skipping remote scripts fetch")
            return {}

        try:
            # First, get list of script IDs using service class
            response = self.rtr_admin.list_scripts()

            if response.get('status_code') != 200:
                logger.warning(f"Failed to list RTR scripts: status {response.get('status_code')}")
                return {}

            body = response.get('body', {})
            script_ids = body.get('resources', [])

            if not script_ids:
                logger.info("No RTR scripts found")
                return {}

            # Fetch full details for each script using service class
            scripts = {}
            response = self.rtr_admin.get_scripts_v2(ids=script_ids)

            if response.get('status_code') == 200:
                body = response.get('body', {})
                resources = body.get('resources', [])

                for script_data in resources:
                    script_name = script_data.get('name')
                    if script_name:
                        scripts[script_name] = script_data
                        logger.debug(f"Discovered RTR script: {script_name} (ID: {script_data.get('id')})")

            logger.info(f"Discovered {len(scripts)} RTR scripts")
            return scripts

        except Exception as e:
            logger.error(f"Failed to fetch RTR scripts: {e}")
            return {}

    def create_resource(
        self,
        resource_id: Optional[str],
        template: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new RTR script

        Args:
            resource_id: Ignored (API auto-generates ID)
            template: RTR script template data

        Returns:
            Created script metadata including ID

        Raises:
            RuntimeError: If creation fails
        """
        if not self.rtr_admin:
            raise RuntimeError("RTR admin not initialized - cannot create scripts (credentials required)")

        try:
            # Extract script content
            content = template.get('content')
            file_path = template.get('file_path')

            # If file_path provided, load content from file
            if file_path and not content:
                # Resolve path relative to template location
                template_path = Path(template.get('_template_path', '.'))
                template_dir = template_path.parent
                full_path = template_dir / file_path

                logger.debug(f"Resolving script file path:")
                logger.debug(f"  Template path: {template_path}")
                logger.debug(f"  Template dir: {template_dir}")
                logger.debug(f"  File path (from template): {file_path}")
                logger.debug(f"  Full resolved path: {full_path}")
                logger.debug(f"  Full path exists: {full_path.exists()}")

                if not full_path.exists():
                    raise RuntimeError(
                        f"Script file not found: {full_path}\n"
                        f"  Template: {template_path}\n"
                        f"  Relative file_path: {file_path}\n"
                        f"  Template directory: {template_dir}\n"
                        f"  Working directory: {Path.cwd()}\n"
                        f"Ensure file_path in template is correct relative to template location."
                    )

                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                logger.info(f"Loaded script content from {full_path} ({len(content)} bytes)")

            if not content:
                raise RuntimeError("No script content available (content is empty)")

            if len(content) == 0:
                raise RuntimeError("Script content is empty (0 bytes)")

            if len(content) > 5 * 1024 * 1024:  # 5MB limit
                raise RuntimeError(f"Script content too large ({len(content)} bytes, max 5MB)")

            # Normalize platform to list
            platform = template.get('platform', ['windows'])
            if isinstance(platform, str):
                platform = [platform]

            # Prepare multipart/form-data for file upload
            script_filename = f"{template['name']}.ps1"  # Default extension
            if 'linux' in platform or 'mac' in platform:
                script_filename = f"{template['name']}.sh"

            files = [
                ('file', (script_filename, content.encode('utf-8'), 'application/octet-stream'))
            ]

            # Call create_scripts using service class (proven to work!)
            response = self.rtr_admin.create_scripts(
                description=template['description'],
                name=template['name'],
                permission_type=template.get('permission_type', 'group'),
                platform=platform,
                comments_for_audit_log=template.get('comments_for_audit_log', f"Created via IaC: {template['name']}"),
                files=files
            )

            logger.debug(f"Create RTR script response status: {response.get('status_code')}")
            logger.debug(f"Create response body: {json.dumps(response.get('body', {}), indent=2)[:500]}")

            if response.get('status_code') not in (200, 201):
                raise RuntimeError(
                    f"Failed to create RTR script '{template['name']}': {response}"
                )

            # Extract ID from response
            body = response.get('body', {})
            resources = body.get('resources', [])

            if resources and len(resources) > 0:
                script_id = resources[0]
            else:
                script_id = body.get('id', 'unknown')

            logger.info(f"Created RTR script: {template['name']} (ID: {script_id})")

            return {
                'id': script_id,
                'name': template['name'],
                'platform': platform,
                'permission_type': template.get('permission_type', 'group'),
                'created_at': datetime.now(timezone.utc).isoformat(),
                'response': body
            }

        except Exception as e:
            raise RuntimeError(f"Failed to create RTR script: {e}") from e

    def update_resource(
        self,
        resource_id: str,
        template: Dict[str, Any],
        current_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update an existing RTR script

        Args:
            resource_id: Current script ID
            template: New script template data
            current_state: Current state (for comparison)

        Returns:
            Updated script metadata

        Raises:
            RuntimeError: If update fails
        """
        if not self.rtr_admin:
            raise RuntimeError("RTR admin not initialized - cannot update scripts (credentials required)")

        try:
            # Extract script content
            content = template.get('content')
            file_path = template.get('file_path')

            # If file_path provided, load content from file
            if file_path and not content:
                # Resolve path relative to template location
                template_path = Path(template.get('_template_path', '.'))
                template_dir = template_path.parent
                full_path = template_dir / file_path

                logger.debug(f"Resolving script file path for update:")
                logger.debug(f"  Template path: {template_path}")
                logger.debug(f"  Full resolved path: {full_path}")

                if not full_path.exists():
                    raise RuntimeError(
                        f"Script file not found: {full_path}\n"
                        f"  Template: {template_path}\n"
                        f"  Relative file_path: {file_path}\n"
                        f"Ensure file_path in template is correct relative to template location."
                    )

                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                logger.info(f"Loaded script content from {full_path} ({len(content)} bytes)")

            if not content:
                raise RuntimeError("No script content available (content is empty)")

            # Normalize platform to list
            platform = template.get('platform', ['windows'])
            if isinstance(platform, str):
                platform = [platform]

            # Prepare multipart/form-data for file upload
            script_filename = f"{template['name']}.ps1"
            if 'linux' in platform or 'mac' in platform:
                script_filename = f"{template['name']}.sh"

            files = [
                ('file', (script_filename, content.encode('utf-8'), 'application/octet-stream'))
            ]

            # Call update_scripts using service class (PATCH replaces the script)
            response = self.rtr_admin.update_scripts(
                id=resource_id,
                description=template['description'],
                name=template['name'],
                permission_type=template.get('permission_type', 'group'),
                platform=platform,
                comments_for_audit_log=template.get('comments_for_audit_log', f"Updated via IaC: {template['name']}"),
                files=files
            )

            logger.debug(f"Update RTR script response status: {response.get('status_code')}")
            logger.debug(f"Update response body: {json.dumps(response.get('body', {}), indent=2)[:500]}")

            if response.get('status_code') not in (200, 201):
                raise RuntimeError(
                    f"Failed to update RTR script '{template['name']}' (ID: {resource_id}): {response}"
                )

            logger.info(f"Updated RTR script: {template['name']} (ID: {resource_id})")

            return {
                'id': resource_id,
                'name': template['name'],
                'platform': platform,
                'permission_type': template.get('permission_type', 'group'),
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'response': response.get('body', {})
            }

        except Exception as e:
            raise RuntimeError(f"Failed to update RTR script: {e}") from e

    def delete_resource(self, resource_id: str) -> Dict[str, Any]:
        """
        Delete an RTR script

        Args:
            resource_id: Script ID to delete

        Returns:
            Deletion metadata

        Raises:
            RuntimeError: If deletion fails
        """
        if not self.rtr_admin:
            raise RuntimeError("RTR admin not initialized - cannot delete scripts (credentials required)")

        try:
            # Call delete_scripts using service class
            response = self.rtr_admin.delete_scripts(ids=resource_id)

            status_code = response.get('status_code')

            if status_code == 200:
                logger.info(f"Deleted RTR script: {resource_id}")
                return {
                    'id': resource_id,
                    'deleted_at': datetime.now(timezone.utc).isoformat()
                }
            elif status_code == 404:
                logger.warning(f"RTR script {resource_id} not found - may have been already deleted")
                return {
                    'id': resource_id,
                    'deleted_at': datetime.now(timezone.utc).isoformat(),
                    'note': 'Resource not found (may have been already deleted)'
                }
            else:
                raise RuntimeError(
                    f"Failed to delete RTR script {resource_id}: status {status_code}, response {response}"
                )

        except Exception as e:
            raise RuntimeError(f"Failed to delete RTR script: {e}") from e

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        """
        Calculate deterministic hash of RTR script content

        Includes: name, description, platform, permission_type, content

        Args:
            template: RTR script template

        Returns:
            SHA256 hash as hex string
        """
        # Load content if file_path is used
        content = template.get('content', '')
        file_path = template.get('file_path')

        if file_path and not content:
            try:
                template_dir = Path(template.get('_template_path', '.')).parent
                full_path = template_dir / file_path
                if full_path.exists():
                    with open(full_path, 'r', encoding='utf-8') as f:
                        content = f.read()
            except Exception as e:
                logger.warning(f"Failed to read script file for hashing: {e}")

        # Normalize platform to sorted list
        platform = template.get('platform', ['windows'])
        if isinstance(platform, str):
            platform = [platform]
        platform = sorted(platform)

        # Normalize content for consistent hashing
        normalized_content = {
            'name': template.get('name', ''),
            'description': template.get('description', ''),
            'platform': platform,
            'permission_type': template.get('permission_type', 'group'),
            'content': content.strip()
        }

        # Calculate hash
        content_str = json.dumps(normalized_content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def extract_dependencies(self, template: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract resource dependencies from RTR script template

        RTR scripts typically don't depend on other IaC resources.

        Args:
            template: RTR script template

        Returns:
            Empty dict (no dependencies)
        """
        return {}

    # BaseResourceProvider planning methods

    def plan_create(self, template: Dict[str, Any], template_path: str) -> ResourceChange:
        """Plan the creation of a new RTR script"""
        return ResourceChange(
            action=ResourceAction.CREATE,
            resource_type=self.get_resource_type(),
            resource_name=template['name'],
            new_value=template,
            template_path=template_path
        )

    def plan_update(
        self,
        template: Dict[str, Any],
        current_state: Dict[str, Any],
        template_path: str
    ) -> ResourceChange:
        """Plan an update to an existing RTR script"""
        # Calculate content hashes
        template_hash = self.compute_content_hash(template)
        current_hash = self.compute_content_hash(current_state)

        if template_hash == current_hash:
            return ResourceChange(
                action=ResourceAction.NO_CHANGE,
                resource_type=self.get_resource_type(),
                resource_name=template['name'],
                resource_id=current_state.get('id'),
                old_value=current_state,
                new_value=template,
                template_path=template_path
            )

        # Detect changes
        changes = {}
        for key in ['name', 'description', 'platform', 'permission_type', 'content']:
            old_val = current_state.get(key)
            new_val = template.get(key)

            # Normalize platform for comparison
            if key == 'platform':
                if isinstance(old_val, str):
                    old_val = [old_val]
                if isinstance(new_val, str):
                    new_val = [new_val]
                old_val = sorted(old_val or [])
                new_val = sorted(new_val or [])

            if old_val != new_val and (old_val is not None or new_val is not None):
                changes[key] = {'old': old_val, 'new': new_val}

        return ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type=self.get_resource_type(),
            resource_name=template['name'],
            resource_id=current_state.get('id'),
            old_value=current_state,
            new_value=template,
            changes=changes,
            template_path=template_path
        )

    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        """Plan the deletion of an RTR script"""
        return ResourceChange(
            action=ResourceAction.DELETE,
            resource_type=self.get_resource_type(),
            resource_name=resource_name,
            resource_id=resource_id
        )

    # Convenience methods matching BaseResourceProvider naming

    def apply_create(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for create_resource (BaseResourceProvider compatibility)"""
        return self.create_resource(None, template)

    def apply_update(
        self,
        resource_id: str,
        template: Dict[str, Any],
        current_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Alias for update_resource (BaseResourceProvider compatibility)"""
        return self.update_resource(resource_id, template, current_state)

    def apply_delete(self, resource_id: str) -> Dict[str, Any]:
        """Alias for delete_resource (BaseResourceProvider compatibility)"""
        return self.delete_resource(resource_id)

    def to_template(self, remote_resource: dict) -> dict:
        """
        Convert a remote RTR script into a YAML template dict.

        The remote format from _fetch_all_remote_scripts() has the raw API fields.
        Template format uses: name, description, platform, permission_type, content.

        Args:
            remote_resource: RTR script dict from _fetch_all_remote_scripts()

        Returns:
            Template dict ready for YAML serialization
        """
        name = remote_resource.get('name', '')
        resource_id = self._name_to_resource_id(name) if name else 'unknown'

        # Normalize platform to list
        platform = remote_resource.get('platform', [])
        if isinstance(platform, str):
            platform = [platform]

        template = {
            'resource_id': resource_id,
            'name': name,
            'description': remote_resource.get('description', ''),
            'platform': platform,
            'permission_type': remote_resource.get('permission_type', 'group'),
        }

        # Include script content if available
        content = remote_resource.get('content', '')
        if content:
            template['content'] = content

        return template

    def suggest_path(self, template: dict) -> str:
        """
        Suggest a file path for an RTR script template.

        Args:
            template: Template dict from to_template()

        Returns:
            Relative path like 'rtr_scripts/my_investigation_script.yaml'
        """
        resource_id = template.get('resource_id', '')
        if not resource_id:
            resource_id = self._name_to_resource_id(template.get('name', 'unknown'))

        return f"rtr_scripts/{resource_id}.yaml"
