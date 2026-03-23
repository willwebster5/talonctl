"""
RTRPutFileProvider - CrowdStrike Real-Time Response Put Files

This provider implements the BaseResourceProvider interface for managing
CrowdStrike RTR put files as Infrastructure as Code resources.

Manages files/executables used with RTR 'put' and 'put-and-run' commands
for deploying tools and binaries to endpoints during incident response.
"""

import json
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


class RTRPutFileProvider(BaseResourceProvider):
    """
    Provider for CrowdStrike RTR Put Files

    Manages RTR put files as IaC resources with support for:
    - Template validation (name, description, file path)
    - Remote state fetching from RTR Admin API
    - Change detection and planning
    - File creation and deletion
    - Binary file handling for executables and tools

    API Endpoints:
    - Create: POST /real-time-response/entities/put-files/v1
    - Read: GET /real-time-response/entities/put-files/v2
    - Delete: DELETE /real-time-response/entities/put-files/v1
    - List: GET /real-time-response/queries/put-files/v1

    Note: RTR Put Files do not support updates - must delete and recreate
    """

    def __init__(self, falcon_client: Any, config: Optional[Dict[str, Any]] = None):
        """
        Initialize RTR put file provider

        Args:
            falcon_client: Authenticated FalconPy APIHarnessV2 instance (used to extract credentials)
            config: Optional provider configuration
        """
        self.falcon = falcon_client
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self._remote_files_cache: Optional[Dict[str, Any]] = None

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
                    logger.info("RTR Put File Provider: No credentials available (validation mode)")
                    return

            self.rtr_admin = RealTimeResponseAdmin(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url
            )
            logger.info("RTR Put File Provider: Using RealTimeResponseAdmin service class")

        except Exception as e:
            logger.warning(f"Failed to initialize RealTimeResponseAdmin service class: {e}")
            logger.info("RTR Put File Provider running in validation-only mode")

    def get_resource_type(self) -> str:
        """Return resource type identifier"""
        return "rtr_put_file"

    def validate_template(self, template: Dict[str, Any]) -> List[str]:
        """
        Validate RTR put file template

        Args:
            template: RTR put file template data

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Required fields
        required_fields = ['name', 'description', 'file_path']
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

        # Validate file_path
        file_path = template.get('file_path', '')
        if not isinstance(file_path, str) or not file_path.strip():
            errors.append("'file_path' must be a non-empty string")
        else:
            # Check if file exists (relative to template location)
            template_dir = Path(template.get('_template_path', '.')).parent
            full_path = template_dir / file_path

            if not full_path.exists():
                errors.append(f"File not found: {file_path} (resolved to {full_path})")
            elif not full_path.is_file():
                errors.append(f"Path is not a file: {file_path}")

        # Validate comments_for_audit_log if provided
        if 'comments_for_audit_log' in template:
            if not isinstance(template['comments_for_audit_log'], str):
                errors.append("'comments_for_audit_log' must be a string")

        return errors

    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch current state of an RTR put file from API

        Args:
            resource_id: The ID of the RTR put file

        Returns:
            Current file state or None if not found
        """
        if not self.rtr_admin:
            logger.debug("RTR admin not initialized - skipping remote state fetch")
            return None

        try:
            response = self.rtr_admin.get_put_files_v2(ids=resource_id)

            if response.get('status_code') == 200:
                body = response.get('body', {})
                resources = body.get('resources', [])

                if resources and len(resources) > 0:
                    file_data = resources[0]
                    logger.debug(f"Fetched RTR put file: {file_data.get('name')}")
                    return file_data

            return None

        except Exception as e:
            logger.error(f"Failed to fetch RTR put file {resource_id}: {e}")
            return None

    def _fetch_all_remote_put_files(self) -> Dict[str, Dict[str, Any]]:
        """
        Fetch all RTR put files from API

        Uses the RTR Admin API to retrieve all put files.
        Supports pagination.

        Returns:
            Dictionary of put files indexed by name
        """
        if not self.rtr_admin:
            logger.debug("RTR admin not initialized - skipping remote put files fetch")
            return {}

        try:
            # First, get list of put file IDs
            response = self.rtr_admin.list_put_files()

            if response.get('status_code') != 200:
                logger.warning(f"Failed to list RTR put files: status {response.get('status_code')}")
                return {}

            body = response.get('body', {})
            file_ids = body.get('resources', [])

            if not file_ids:
                logger.info("No RTR put files found")
                return {}

            # Fetch full details for each file
            put_files = {}
            response = self.rtr_admin.get_put_files_v2(ids=file_ids)

            if response.get('status_code') == 200:
                body = response.get('body', {})
                resources = body.get('resources', [])

                for file_data in resources:
                    file_name = file_data.get('name')
                    if file_name:
                        put_files[file_name] = file_data
                        logger.debug(f"Discovered RTR put file: {file_name} (ID: {file_data.get('id')})")

            logger.info(f"Discovered {len(put_files)} RTR put files")
            return put_files

        except Exception as e:
            logger.error(f"Failed to fetch RTR put files: {e}")
            return {}

    def create_resource(
        self,
        resource_id: Optional[str],
        template: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new RTR put file

        Args:
            resource_id: Ignored (API auto-generates ID)
            template: RTR put file template data

        Returns:
            Created file metadata including ID

        Raises:
            RuntimeError: If creation fails
        """
        if not self.rtr_admin:
            raise RuntimeError("RTR admin not initialized - cannot create put files (credentials required)")

        try:
            # Resolve file path
            file_path = template['file_path']
            template_path = Path(template.get('_template_path', '.'))
            template_dir = template_path.parent
            full_path = template_dir / file_path

            logger.debug(f"Resolving put file path:")
            logger.debug(f"  Template path: {template_path}")
            logger.debug(f"  Template dir: {template_dir}")
            logger.debug(f"  File path (from template): {file_path}")
            logger.debug(f"  Full resolved path: {full_path}")
            logger.debug(f"  Full path exists: {full_path.exists()}")

            if not full_path.exists():
                raise RuntimeError(
                    f"Put file not found: {full_path}\n"
                    f"  Template: {template_path}\n"
                    f"  Relative file_path: {file_path}\n"
                    f"  Template directory: {template_dir}\n"
                    f"  Working directory: {Path.cwd()}\n"
                    f"Ensure file_path in template is correct relative to template location."
                )

            # Read binary file content
            with open(full_path, 'rb') as f:
                file_content = f.read()

            logger.info(f"Loaded put file from {full_path} ({len(file_content)} bytes)")

            if len(file_content) == 0:
                raise RuntimeError(f"Put file is empty (0 bytes): {full_path}")

            if len(file_content) > 100 * 1024 * 1024:  # 100MB limit
                raise RuntimeError(f"Put file too large ({len(file_content)} bytes, max 100MB)")

            # Prepare multipart/form-data for file upload
            file_name = template['name']

            files = [
                ('file', (file_name, file_content, 'application/octet-stream'))
            ]

            # Call RTR_CreatePut_Files
            response = self.rtr_admin.create_put_files(
                description=template['description'],
                name=file_name,
                comments_for_audit_log=template.get('comments_for_audit_log', f"Created via IaC: {file_name}"),
                files=files
            )

            logger.debug(f"Create RTR put file response status: {response.get('status_code')}")
            logger.debug(f"Create response body: {json.dumps(response.get('body', {}), indent=2)[:500]}")

            if response.get('status_code') not in (200, 201):
                raise RuntimeError(
                    f"Failed to create RTR put file '{file_name}': {response}"
                )

            # Extract ID from response
            body = response.get('body', {})
            resources = body.get('resources', [])

            if resources and len(resources) > 0:
                file_id = resources[0]
            else:
                file_id = body.get('id', 'unknown')

            logger.info(f"Created RTR put file: {file_name} (ID: {file_id})")

            return {
                'id': file_id,
                'name': file_name,
                'size': len(file_content),
                'created_at': datetime.now(timezone.utc).isoformat(),
                'response': body
            }

        except Exception as e:
            raise RuntimeError(f"Failed to create RTR put file: {e}") from e

    def update_resource(
        self,
        resource_id: str,
        template: Dict[str, Any],
        current_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update an existing RTR put file

        Note: RTR Put Files do not support updates via API.
        This method will delete and recreate the file.

        Args:
            resource_id: Current file ID
            template: New file template data
            current_state: Current state (for comparison)

        Returns:
            Updated file metadata with NEW ID

        Raises:
            RuntimeError: If update fails
        """
        try:
            logger.info(f"RTR put files don't support updates - will delete and recreate: {template['name']}")

            # Delete existing file
            self.delete_resource(resource_id)

            # Create new file
            result = self.create_resource(None, template)

            logger.info(
                f"RTR put file recreated: {resource_id} -> {result['id']} "
                f"(delete + create pattern)"
            )

            return result

        except Exception as e:
            raise RuntimeError(f"Failed to update RTR put file: {e}") from e

    def delete_resource(self, resource_id: str) -> Dict[str, Any]:
        """
        Delete an RTR put file

        Args:
            resource_id: File ID to delete

        Returns:
            Deletion metadata

        Raises:
            RuntimeError: If deletion fails
        """
        if not self.rtr_admin:
            raise RuntimeError("RTR admin not initialized - cannot delete put files (credentials required)")

        try:
            response = self.rtr_admin.delete_put_files(
                ids=resource_id
            )

            status_code = response.get('status_code')

            if status_code == 200:
                logger.info(f"Deleted RTR put file: {resource_id}")
                return {
                    'id': resource_id,
                    'deleted_at': datetime.now(timezone.utc).isoformat()
                }
            elif status_code == 404:
                logger.warning(f"RTR put file {resource_id} not found - may have been already deleted")
                return {
                    'id': resource_id,
                    'deleted_at': datetime.now(timezone.utc).isoformat(),
                    'note': 'Resource not found (may have been already deleted)'
                }
            else:
                raise RuntimeError(
                    f"Failed to delete RTR put file {resource_id}: status {status_code}, response {response}"
                )

        except Exception as e:
            raise RuntimeError(f"Failed to delete RTR put file: {e}") from e

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        """
        Calculate deterministic hash of RTR put file content

        Includes: name, description, file content (SHA256 of binary)

        Args:
            template: RTR put file template

        Returns:
            SHA256 hash as hex string
        """
        # Calculate hash of the binary file
        file_path = template.get('file_path', '')
        file_hash = ''

        if file_path:
            try:
                template_dir = Path(template.get('_template_path', '.')).parent
                full_path = template_dir / file_path

                if full_path.exists():
                    with open(full_path, 'rb') as f:
                        file_content = f.read()
                        file_hash = hashlib.sha256(file_content).hexdigest()
            except Exception as e:
                logger.warning(f"Failed to read put file for hashing: {e}")

        # Normalize content for consistent hashing
        normalized_content = {
            'name': template.get('name', ''),
            'description': template.get('description', ''),
            'file_hash': file_hash
        }

        # Calculate hash
        content_str = json.dumps(normalized_content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def extract_dependencies(self, template: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract resource dependencies from RTR put file template

        RTR put files typically don't depend on other IaC resources.

        Args:
            template: RTR put file template

        Returns:
            Empty dict (no dependencies)
        """
        return {}

    # BaseResourceProvider planning methods

    def plan_create(self, template: Dict[str, Any], template_path: str) -> ResourceChange:
        """Plan the creation of a new RTR put file"""
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
        """Plan an update to an existing RTR put file"""
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
        for key in ['name', 'description', 'file_hash']:
            # For file content, compare hashes
            if key == 'file_hash':
                old_hash = self._get_file_hash(current_state)
                new_hash = self._get_file_hash(template)
                if old_hash != new_hash:
                    changes['file_content'] = {'old': f"SHA256:{old_hash[:16]}...", 'new': f"SHA256:{new_hash[:16]}..."}
            else:
                old_val = current_state.get(key)
                new_val = template.get(key)
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

    def _get_file_hash(self, data: Dict[str, Any]) -> str:
        """Helper to extract/compute file hash from template or state"""
        file_path = data.get('file_path', '')
        if file_path:
            try:
                template_dir = Path(data.get('_template_path', '.')).parent
                full_path = template_dir / file_path
                if full_path.exists():
                    with open(full_path, 'rb') as f:
                        return hashlib.sha256(f.read()).hexdigest()
            except Exception:
                pass

        # Try to get from state metadata
        return data.get('file_hash', data.get('sha256', ''))

    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        """Plan the deletion of an RTR put file"""
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
        Convert a remote RTR put file into a YAML template dict.

        Note: RTR put file content cannot be downloaded via API, so the template
        will contain a placeholder file_path that the user must fill in.

        Args:
            remote_resource: RTR put file dict from _fetch_all_remote_put_files()

        Returns:
            Template dict ready for YAML serialization
        """
        name = remote_resource.get('name', '')
        resource_id = self._name_to_resource_id(name) if name else 'unknown'

        template = {
            'resource_id': resource_id,
            'name': name,
            'description': remote_resource.get('description', ''),
            'file_path': f"files/{name}",  # Placeholder — user must provide actual file
        }

        return template

    def suggest_path(self, template: dict) -> str:
        """
        Suggest a file path for an RTR put file template.

        Args:
            template: Template dict from to_template()

        Returns:
            Relative path like 'rtr_put_files/my_binary.yaml'
        """
        resource_id = template.get('resource_id', '')
        if not resource_id:
            resource_id = self._name_to_resource_id(template.get('name', 'unknown'))

        return f"rtr_put_files/{resource_id}.yaml"
