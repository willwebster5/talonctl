"""
Workflow Provider - CrowdStrike SOAR Workflows

This provider implements the BaseResourceProvider interface for managing
CrowdStrike SOAR workflows as Infrastructure as Code resources.
"""

import json
import yaml
import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from talonctl.core.base_provider import (
    BaseResourceProvider,
    ResourceAction,
    ResourceChange
)

try:
    from falconpy import Workflows
    from talonctl.utils.auth import load_credentials
except ImportError as e:
    logging.error(f"Failed to import required modules: {e}")
    Workflows = None

logger = logging.getLogger(__name__)


class WorkflowProvider(BaseResourceProvider):
    """
    Provider for CrowdStrike SOAR Workflows

    Manages SOAR workflows as IaC resources with support for:
    - Template validation
    - Remote state fetching from CrowdStrike API
    - Change detection and planning
    - Workflow creation and updates
    - Dependency extraction (detections that trigger workflows)
    """

    def __init__(self, falcon_client: Any, config: Optional[Dict[str, Any]] = None):
        """
        Initialize workflow provider

        Args:
            falcon_client: Authenticated FalconPy APIHarnessV2 instance (not used, uses Workflows SDK)
            config: Optional provider configuration
        """
        self.falcon = falcon_client
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)

        # Initialize Workflows SDK client
        creds = load_credentials()
        if creds and Workflows:
            self.workflows_client = Workflows(
                client_id=creds["falcon_client_id"],
                client_secret=creds["falcon_client_secret"],
                base_url=creds.get("base_url")
            )
        else:
            self.workflows_client = None
            logger.warning("Workflows SDK not available")

        self._remote_workflows_cache: Optional[Dict[str, Dict[str, Any]]] = None

    def get_resource_type(self) -> str:
        """Return resource type identifier"""
        return "workflow"

    def validate_template(self, template: Dict[str, Any]) -> List[str]:
        """
        Validate workflow template

        Args:
            template: Workflow template data

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Required fields
        required_fields = ['resource_id', 'name', 'trigger', 'actions']
        for field in required_fields:
            if field not in template:
                errors.append(f"Missing required field: {field}")

        # Validate trigger section
        trigger = template.get('trigger', {})
        if not isinstance(trigger, dict):
            errors.append("'trigger' must be a dictionary")
        else:
            if 'event' not in trigger:
                errors.append("Missing 'event' in trigger section")
            if 'type' not in trigger:
                errors.append("Missing 'type' in trigger section")

        # Validate actions section
        actions = template.get('actions', {})
        if not isinstance(actions, dict):
            errors.append("'actions' must be a dictionary")
        elif len(actions) == 0:
            errors.append("'actions' must contain at least one action")

        # Validate conditions section if present
        conditions = template.get('conditions', {})
        if conditions and not isinstance(conditions, dict):
            errors.append("'conditions' must be a dictionary")

        return errors

    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch current state of a workflow from CrowdStrike API

        Args:
            resource_id: The workflow ID or workflow name

        Returns:
            Current workflow state or None if not found
        """
        try:
            if not self.workflows_client:
                return None

            # Use cached workflows if available
            if self._remote_workflows_cache is None:
                self._fetch_all_remote_workflows()

            # Search for workflow by ID or name
            for wf_name, wf_data in (self._remote_workflows_cache or {}).items():
                if wf_data.get('id') == resource_id or wf_name == resource_id:
                    return wf_data

            return None

        except Exception as e:
            logger.error(f"Failed to fetch workflow {resource_id}: {e}")
            return None

    def _fetch_all_remote_workflows(self) -> Dict[str, Dict[str, Any]]:
        """Fetch all deployed workflows from CrowdStrike API"""
        try:
            if not self.workflows_client:
                self._remote_workflows_cache = {}
                return {}

            # Query all workflows
            response = self.workflows_client.search_definitions()

            if response.get("status_code") != 200:
                logger.error(f"Failed to query workflows: {response}")
                self._remote_workflows_cache = {}
                return {}

            workflow_ids = response.get("body", {}).get("resources", [])

            if not workflow_ids:
                self._remote_workflows_cache = {}
                return {}

            # Fetch workflow details in batches
            all_workflows = {}
            batch_size = 100

            for i in range(0, len(workflow_ids), batch_size):
                batch_ids = workflow_ids[i:i+batch_size]

                details_response = self.workflows_client.get_definitions(
                    ids=batch_ids
                )

                if details_response.get("status_code") == 200:
                    for workflow in details_response.get("body", {}).get("resources", []):
                        wf_name = workflow.get("name")
                        if wf_name:
                            normalized = self._normalize_workflow(workflow)
                            all_workflows[wf_name] = normalized

            self._remote_workflows_cache = all_workflows
            return all_workflows

        except Exception as e:
            logger.error(f"Failed to fetch deployed workflows: {e}")
            self._remote_workflows_cache = {}
            return {}

    def _normalize_workflow(self, workflow: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize workflow from API response format"""
        normalized = {
            'id': workflow.get('id'),
            'name': workflow.get('name'),
            'enabled': workflow.get('enabled', True),
            'trigger': workflow.get('trigger', {}),
            'actions': workflow.get('actions', {}),
            'conditions': workflow.get('conditions', {})
        }

        return normalized

    def plan_create(self, template: Dict[str, Any], template_path: str) -> ResourceChange:
        """
        Plan creation of a new workflow

        Args:
            template: Workflow template data
            template_path: Path to template file

        Returns:
            ResourceChange describing the creation
        """
        return ResourceChange(
            action=ResourceAction.CREATE,
            resource_type=self.get_resource_type(),
            resource_name=template['name'],
            resource_id=None,
            old_value=None,
            new_value=template,
            changes=None,
            template_path=template_path
        )

    def plan_update(
        self,
        template: Dict[str, Any],
        current_state: Dict[str, Any],
        template_path: str
    ) -> ResourceChange:
        """
        Plan update of an existing workflow

        Args:
            template: New workflow template data
            current_state: Current deployed workflow state
            template_path: Path to template file

        Returns:
            ResourceChange describing the update or no-change
        """
        # Calculate hashes to detect changes
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
                changes=None,
                template_path=template_path
            )

        # Detect specific field changes
        changes = self._detect_field_changes(template, current_state)

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

    def _detect_field_changes(
        self,
        new: Dict[str, Any],
        old: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Detect specific field changes between templates"""
        changes = {}

        # Check simple fields
        simple_fields = ['name', 'enabled']
        for field in simple_fields:
            new_val = new.get(field)
            old_val = old.get(field)
            if new_val != old_val:
                changes[field] = {'old': old_val, 'new': new_val}

        # Check trigger
        new_trigger = new.get('trigger', {})
        old_trigger = old.get('trigger', {})
        if new_trigger != old_trigger:
            changes['trigger'] = {'old': old_trigger, 'new': new_trigger}

        # Check actions
        new_actions = new.get('actions', {})
        old_actions = old.get('actions', {})
        if new_actions != old_actions:
            changes['actions'] = {'old': old_actions, 'new': new_actions}

        # Check conditions
        new_conditions = new.get('conditions', {})
        old_conditions = old.get('conditions', {})
        if new_conditions != old_conditions:
            changes['conditions'] = {'old': old_conditions, 'new': new_conditions}

        return changes

    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        """
        Plan deletion of a workflow

        Args:
            resource_id: Workflow ID to delete
            resource_name: Workflow name

        Returns:
            ResourceChange describing the deletion
        """
        # Fetch current state for context
        current_state = self.fetch_remote_state(resource_id)

        return ResourceChange(
            action=ResourceAction.DELETE,
            resource_type=self.get_resource_type(),
            resource_name=resource_name,
            resource_id=resource_id,
            old_value=current_state,
            new_value=None,
            changes=None,
            template_path=None
        )

    def apply_create(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a workflow in CrowdStrike

        Args:
            template: Workflow template data

        Returns:
            Created workflow metadata including workflow_id
        """
        if not self.workflows_client:
            raise RuntimeError("Workflows SDK not available")

        workflow_name = template['name']

        # Strip IaC-only fields before API submission
        api_template = {k: v for k, v in template.items() if k not in ('resource_id', 'description')}

        # Save workflow to temporary file for import
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(api_template, f, default_flow_style=False)
            temp_file = f.name

        try:
            # Import the workflow
            response = self.workflows_client.import_definition(
                name=workflow_name,
                data_file=temp_file,
                validate_only=False
            )

            if response.get("status_code") != 200:
                raise RuntimeError(
                    f"Failed to create workflow '{workflow_name}': {response}"
                )

            workflow_resource = response.get("body", {}).get("resources", [{}])[0]
            workflow_id = workflow_resource.get("id")

            return {
                'id': workflow_id,
                'name': workflow_name,
                'enabled': workflow_resource.get("enabled", True),
                'created_at': datetime.now(timezone.utc).isoformat(),
                'response': workflow_resource
            }

        finally:
            # Clean up temp file
            import os
            try:
                os.unlink(temp_file)
            except:
                pass

    def apply_update(
        self, resource_id: str, template: Dict[str, Any], current_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Workflow updates are not supported — all changes go through requires_replacement() → REPLACE."""
        raise NotImplementedError(
            "Workflow updates are not supported by the CrowdStrike API. "
            "All changes should go through the REPLACE path (delete + recreate)."
        )

    def apply_delete(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Delete a workflow from CrowdStrike

        Args:
            resource_id: Workflow ID to delete

        Returns:
            Dict with 'id' key on success, None/False otherwise
        """
        if not self.workflows_client:
            raise RuntimeError("Workflows SDK not available")

        response = self.workflows_client.delete_definition(
            ids=[resource_id]
        )

        if response.get("status_code") in (200, 204):
            return {'id': resource_id}

        logger.error(f"Failed to delete workflow ID {resource_id}: {response}")
        return False

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        """
        Calculate deterministic hash of workflow content

        Only includes fields that affect workflow behavior
        """
        # Normalize content for consistent hashing
        normalized_content = {
            'name': template.get('name', ''),
            'enabled': template.get('enabled', True),
            'trigger': template.get('trigger', {}),
            'actions': template.get('actions', {}),
            'conditions': template.get('conditions', {})
        }

        # Calculate hash
        content_str = json.dumps(normalized_content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def extract_dependencies(self, template: Dict[str, Any]) -> List[str]:
        """
        Extract resource dependencies from workflow

        Detects references to:
        - Detection rules (from trigger conditions or workflow name)

        Returns:
            List of dependency resource IDs in "type.name" format
        """
        dependencies = []

        # Extract detection from workflow name pattern
        # Workflows created by generator follow pattern: {rule_id}_response_workflow
        workflow_name = template.get('name', '')
        if workflow_name.endswith('_response_workflow'):
            # Extract rule_id
            rule_id = workflow_name.replace('_response_workflow', '')
            if rule_id:
                dependencies.append(f"detection.{rule_id}")

        # Check trigger conditions for detection name references
        conditions = template.get('conditions', {})
        for cond_name, cond_data in conditions.items():
            expression = cond_data.get('expression', '')
            # Pattern: Trigger.Category.Investigatable.Name:'RuleName'
            import re
            match = re.search(r"Name:'([^']+)'", expression)
            if match:
                detection_name = match.group(1)
                # Sanitize name to resource ID format
                sanitized = detection_name.lower().replace(' ', '_').replace('-', '_')
                dependencies.append(f"detection.{sanitized}")

        return dependencies

    def clear_cache(self):
        """Clear the remote workflows cache"""
        self._remote_workflows_cache = None

    def requires_replacement(
        self, template: Dict[str, Any], current_state: Dict[str, Any]
    ) -> Optional[str]:
        """
        CrowdStrike Workflows API does not support updates — only create and delete.
        All content changes require replacement (delete old + create new).
        """
        return "CrowdStrike Workflows API does not support updates — requires delete and recreate"

    def to_template(self, remote_resource: dict) -> dict:
        """
        Convert a normalized remote workflow into a YAML template dict.

        Args:
            remote_resource: Normalized workflow dict from _fetch_all_remote_workflows()

        Returns:
            Template dict ready for YAML serialization
        """
        name = remote_resource.get('name', '')
        resource_id = self._name_to_resource_id(name) if name else 'unknown'

        template = {
            'resource_id': resource_id,
            'name': name,
            'enabled': remote_resource.get('enabled', True),
            'trigger': remote_resource.get('trigger', {}),
            'actions': remote_resource.get('actions', {}),
        }

        conditions = remote_resource.get('conditions', {})
        if conditions:
            template['conditions'] = conditions

        return template

    def suggest_path(self, template: dict) -> str:
        """
        Suggest a file path for a workflow template.

        Args:
            template: Template dict from to_template()

        Returns:
            Relative path like 'workflows/aws_root_login_response_workflow.yaml'
        """
        resource_id = template.get('resource_id', '')
        if not resource_id:
            resource_id = self._name_to_resource_id(template.get('name', 'unknown'))

        return f"workflows/{resource_id}.yaml"
