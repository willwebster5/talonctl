"""
Provider Adapter

This module provides a unified interface for managing multiple resource providers.
It coordinates provider initialization, state management, and provides convenience
methods for common operations across all resource types.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from core import (
    BaseResourceProvider,
    ResourceAction,
    ResourceChange
)
from core.state_manager import StateManager, ResourceState

logger = logging.getLogger(__name__)


class ProviderAdapter:
    """
    Unified provider management and coordination.

    Responsibilities:
    1. Initialize and manage all resource providers
    2. Coordinate state management across providers
    3. Provide convenience methods for resource operations
    """

    def __init__(self, falcon_client, state_file_path: Path, auto_save: bool = True, credentials: Optional[Dict[str, str]] = None):
        """
        Initialize adapter with API client and state file.

        Args:
            falcon_client: Authenticated FalconPy APIHarnessV2 instance
            state_file_path: Path to deployment state file
            auto_save: Whether to automatically save state after each resource change.
                      Set to False for batch deployments to reduce I/O overhead.
                      Default: True for backward compatibility.
            credentials: Optional credentials dict (required for RTR providers to use service class)
        """
        self.falcon = falcon_client
        self.state_manager = StateManager(state_file_path)
        self.auto_save = auto_save
        self.credentials = credentials

        # Initialize providers (lazy import to avoid circular dependency)
        from providers import (
            DetectionProvider,
            WorkflowProvider,
            SavedSearchProvider,
            LookupFileProvider,
            RTRScriptProvider,
            RTRPutFileProvider
        )

        # All providers get credentials config for customer_id and other auth needs
        provider_config = {'credentials': credentials} if credentials else {}

        self.detection_provider = DetectionProvider(falcon_client, config=provider_config)
        self.workflow_provider = WorkflowProvider(falcon_client)
        self.saved_search_provider = SavedSearchProvider(falcon_client)
        self.lookup_file_provider = LookupFileProvider(falcon_client)

        # RTR providers need credentials to create service class instances
        self.rtr_script_provider = RTRScriptProvider(falcon_client, config=provider_config)
        self.rtr_put_file_provider = RTRPutFileProvider(falcon_client, config=provider_config)

        # Provider registry
        self.providers: Dict[str, BaseResourceProvider] = {
            'detection': self.detection_provider,
            'workflow': self.workflow_provider,
            'saved_search': self.saved_search_provider,
            'lookup_file': self.lookup_file_provider,
            'rtr_script': self.rtr_script_provider,
            'rtr_put_file': self.rtr_put_file_provider
        }

    def plan_detection_changes(
        self,
        templates: Dict[str, Dict[str, Any]],
        draft_mode: bool = False
    ) -> Dict[str, List[ResourceChange]]:
        """
        DEPRECATED: Use plan_resource_changes('detection', templates) instead.

        Generate a plan for detection changes using the provider.

        Args:
            templates: Dictionary mapping rule names to template data
            draft_mode: Whether to plan for draft/inactive deployment

        Returns:
            Dictionary with 'create', 'update', 'delete' lists
        """
        to_create = []
        to_update = []
        to_delete = []

        # Get current deployed rules from state
        deployed_rules = self.state_manager.get_all_resources('detection')
        deployed_rule_names = {name.split('.')[1] for name in deployed_rules.keys()}

        # Plan creates and updates
        for rule_name, template in templates.items():
            # Validate template first
            errors = self.detection_provider.validate_template(template)
            if errors:
                logger.warning(f"Template validation failed for {rule_name}: {errors}")
                continue

            # Check if rule exists in state
            resource_state = self.state_manager.get_resource('detection', rule_name)

            if resource_state:
                # Fetch remote state
                remote_state = self.detection_provider.fetch_remote_state(resource_state.id)

                if remote_state:
                    # Plan update
                    template_path = template.get('_template_path', '')
                    change = self.detection_provider.plan_update(
                        template,
                        remote_state,
                        template_path
                    )

                    if change.action == ResourceAction.UPDATE:
                        to_update.append(change)
                else:
                    # Rule in state but not deployed - recreate
                    template_path = template.get('_template_path', '')
                    change = self.detection_provider.plan_create(template, template_path)
                    to_create.append(change)
            else:
                # New rule
                template_path = template.get('_template_path', '')
                change = self.detection_provider.plan_create(template, template_path)
                to_create.append(change)

        # Plan deletes for rules in state but not in templates
        template_names = set(templates.keys())
        for rule_id in deployed_rule_names:
            if rule_id not in template_names:
                resource_state = self.state_manager.get_resource('detection', rule_id)
                if resource_state:
                    change = self.detection_provider.plan_delete(
                        resource_state.id,
                        rule_id
                    )
                    to_delete.append(change)

        return {
            'create': to_create,
            'update': to_update,
            'delete': to_delete
        }

    def apply_detection_change(
        self,
        change: ResourceChange,
        draft_mode: bool = False
    ) -> Dict[str, Any]:
        """
        DEPRECATED: Use apply_resource_change('detection', change, template) instead.

        Apply a single detection change.

        Args:
            change: ResourceChange to apply
            draft_mode: Whether to deploy as inactive

        Returns:
            Result metadata
        """
        if change.action == ResourceAction.CREATE:
            # Apply create
            result = self.detection_provider.apply_create(change.new_value)

            # Update state
            content_hash = self.detection_provider.compute_content_hash(change.new_value)
            dependencies = self.detection_provider.extract_dependencies(change.new_value)

            resource_state = ResourceState(
                type='detection',
                id=result['rule_id'],
                content_hash=content_hash,
                template_path=change.template_path or '',
                deployed_at=result.get('created_at', datetime.now(timezone.utc).isoformat()),
                last_modified=result.get('created_at', datetime.now(timezone.utc).isoformat()),
                provider_metadata={
                    'rule_id': result['rule_id'],
                    'status': 'inactive' if draft_mode else 'active'
                },
                dependencies=dependencies
            )

            self.state_manager.set_resource('detection', change.resource_name, resource_state)
            if self.auto_save:
                self.state_manager.save()

            return result

        elif change.action == ResourceAction.UPDATE:
            # Fetch current state
            current_state = self.detection_provider.fetch_remote_state(change.resource_id)

            # Apply update
            result = self.detection_provider.apply_update(
                change.resource_id,
                change.new_value,
                current_state or {}
            )

            # Update state
            content_hash = self.detection_provider.compute_content_hash(change.new_value)
            dependencies = self.detection_provider.extract_dependencies(change.new_value)

            resource_state = ResourceState(
                type='detection',
                id=change.resource_id,
                content_hash=content_hash,
                template_path=change.template_path or '',
                deployed_at=result.get('deployed_at', ''),
                last_modified=result.get('updated_at', datetime.now(timezone.utc).isoformat()),
                provider_metadata={
                    'rule_id': change.resource_id,
                    'status': 'inactive' if draft_mode else 'active'
                },
                dependencies=dependencies
            )

            self.state_manager.set_resource('detection', change.resource_name, resource_state)
            if self.auto_save:
                self.state_manager.save()

            return result

        elif change.action == ResourceAction.DELETE:
            # Apply delete
            result = self.detection_provider.apply_delete(change.resource_id)

            # Remove from state
            self.state_manager.delete_resource('detection', change.resource_name)
            if self.auto_save:
                self.state_manager.save()

            return result

        return {}

    def get_provider(self, resource_type: str) -> Optional[BaseResourceProvider]:
        """
        Get provider for a resource type.

        Args:
            resource_type: Type of resource (detection, workflow, etc.)

        Returns:
            Provider instance or None
        """
        return self.providers.get(resource_type)

    def get_provider_registry(self) -> Dict[str, BaseResourceProvider]:
        """
        Get the complete provider registry.

        Returns:
            Dictionary mapping resource types to provider instances
        """
        return self.providers

    def save_state(self) -> None:
        """
        Manually save the current state to disk.

        This method should be called when auto_save is disabled to persist
        state changes at controlled intervals (e.g., after each deployment wave).
        """
        self.state_manager.save()
        logger.debug("State saved manually")

    # =========================================================================
    # Generic Resource Management Methods
    # =========================================================================

    def plan_resource_changes(
        self,
        resource_type: str,
        templates: Dict[str, Dict[str, Any]],
        **kwargs
    ) -> Dict[str, List[ResourceChange]]:
        """
        Generate a plan for resource changes using the provider.

        Generic method that works with any resource type.

        Args:
            resource_type: Type of resource (detection, saved_search, etc.)
            templates: Dictionary mapping resource names to template data
            **kwargs: Provider-specific options (e.g., draft_mode, search_domain)

        Returns:
            Dictionary with 'create', 'update', 'delete' lists
        """
        provider = self.providers.get(resource_type)
        if not provider:
            raise ValueError(f"No provider for resource type: {resource_type}")

        to_create = []
        to_update = []
        to_delete = []

        # Get current deployed resources from state
        deployed = self.state_manager.get_all_resources(resource_type)
        deployed_names = {name.split('.', 1)[1] if '.' in name else name for name in deployed.keys()}

        # Plan creates and updates
        for name, template in templates.items():
            # Validate template first
            errors = provider.validate_template(template)
            if errors:
                logger.warning(f"Template validation failed for {name}: {errors}")
                continue

            # Check if resource exists in state
            resource_state = self.state_manager.get_resource(resource_type, name)

            if resource_state:
                # Fetch remote state
                remote_state = provider.fetch_remote_state(resource_state.id)

                if remote_state:
                    # Plan update
                    template_path = template.get('_template_path', template.get('template_path', ''))
                    change = provider.plan_update(template, remote_state, template_path)

                    if change.action == ResourceAction.UPDATE:
                        to_update.append(change)
                else:
                    # Resource in state but not deployed - recreate
                    template_path = template.get('_template_path', template.get('template_path', ''))
                    change = provider.plan_create(template, template_path)
                    to_create.append(change)
            else:
                # New resource
                template_path = template.get('_template_path', template.get('template_path', ''))
                change = provider.plan_create(template, template_path)
                to_create.append(change)

        # Plan deletes for resources in state but not in templates
        template_names = set(templates.keys())
        for name in deployed_names:
            if name not in template_names:
                resource_state = self.state_manager.get_resource(resource_type, name)
                if resource_state:
                    change = provider.plan_delete(resource_state.id, name)
                    to_delete.append(change)

        return {
            'create': to_create,
            'update': to_update,
            'delete': to_delete
        }

    def apply_resource_change(
        self,
        resource_type: str,
        change: ResourceChange,
        template: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Apply a single resource change.

        Generic method that works with any resource type.

        Args:
            resource_type: Type of resource (detection, saved_search, etc.)
            change: ResourceChange to apply
            template: Resource template
            **kwargs: Provider-specific options

        Returns:
            Result metadata from the provider
        """
        provider = self.providers.get(resource_type)
        if not provider:
            raise ValueError(f"No provider for resource type: {resource_type}")

        if change.action == ResourceAction.CREATE:
            # Apply create
            result = provider.apply_create(template)

            # Build resource ID (provider-specific)
            resource_id = self._extract_resource_id(result, resource_type)

            # Update state
            content_hash = provider.compute_content_hash(template)
            dependencies = provider.extract_dependencies(template)

            resource_state = ResourceState(
                type=resource_type,
                id=resource_id,
                content_hash=content_hash,
                template_path=change.template_path or '',
                deployed_at=result.get('created_at', datetime.now(timezone.utc).isoformat()),
                last_modified=result.get('created_at', datetime.now(timezone.utc).isoformat()),
                provider_metadata=result,
                dependencies=list(dependencies.keys()) if isinstance(dependencies, dict) else dependencies
            )

            self.state_manager.set_resource(resource_type, change.resource_name, resource_state)
            if self.auto_save:
                self.state_manager.save()

            return result

        elif change.action == ResourceAction.UPDATE:
            # Fetch current state
            current_state = provider.fetch_remote_state(change.resource_id)

            # Apply update
            result = provider.apply_update(
                change.resource_id,
                template,
                current_state or {}
            )

            # Extract resource ID (may have changed for some resources like saved_search)
            resource_id = self._extract_resource_id(result, resource_type)

            # Update state
            content_hash = provider.compute_content_hash(template)
            dependencies = provider.extract_dependencies(template)

            # Get old deployed_at timestamp
            old_state = self.state_manager.get_resource(resource_type, change.resource_name)
            deployed_at = old_state.deployed_at if old_state else datetime.now(timezone.utc).isoformat()

            resource_state = ResourceState(
                type=resource_type,
                id=resource_id,
                content_hash=content_hash,
                template_path=change.template_path or '',
                deployed_at=deployed_at,
                last_modified=result.get('updated_at', datetime.now(timezone.utc).isoformat()),
                provider_metadata=result,
                dependencies=list(dependencies.keys()) if isinstance(dependencies, dict) else dependencies
            )

            self.state_manager.set_resource(resource_type, change.resource_name, resource_state)
            if self.auto_save:
                self.state_manager.save()

            return result

        elif change.action == ResourceAction.DELETE:
            # Apply delete
            result = provider.apply_delete(change.resource_id)

            # Remove from state
            self.state_manager.delete_resource(resource_type, change.resource_name)
            if self.auto_save:
                self.state_manager.save()

            return result

        else:
            logger.warning(f"Unknown action: {change.action}")
            return {}

    def _extract_resource_id(self, result: Dict[str, Any], resource_type: str) -> str:
        """
        Extract resource ID from provider result.

        Different providers return IDs in different fields (rule_id, id, filename, etc.)

        Args:
            result: Provider result dictionary
            resource_type: Type of resource

        Returns:
            Resource ID string
        """
        # Detection uses rule_id
        if resource_type == 'detection' and 'rule_id' in result:
            return result['rule_id']

        # Lookup files use filename
        if resource_type == 'lookup_file' and 'filename' in result:
            return result['filename']

        # Default to 'id' field
        return result.get('id', '')

    # =========================================================================
    # Legacy Resource-Specific Methods (DEPRECATED - use generic methods above)
    # =========================================================================

    # Saved Search Management Methods

    def plan_saved_search_changes(
        self,
        templates: Dict[str, Dict[str, Any]],
        search_domain: str = 'falcon'
    ) -> Dict[str, List[ResourceChange]]:
        """
        DEPRECATED: Use plan_resource_changes('saved_search', templates) instead.

        Generate a plan for saved search changes using the provider.

        Args:
            templates: Dictionary mapping saved search names to template data
            search_domain: Search domain (all/falcon/third-party/dashboards)

        Returns:
            Dictionary with 'create', 'update', 'delete' lists
        """
        to_create = []
        to_update = []
        to_delete = []

        # Get current deployed saved searches from state
        deployed_searches = self.state_manager.get_all_resources('saved_search')
        deployed_search_names = {name.split('.')[1] for name in deployed_searches.keys()}

        # Plan creates and updates
        for search_name, template in templates.items():
            # Ensure search_domain is set
            if 'search_domain' not in template:
                template['search_domain'] = search_domain

            # Validate template first
            errors = self.saved_search_provider.validate_template(template)
            if errors:
                logger.warning(f"Template validation failed for {search_name}: {errors}")
                continue

            # Check if exists in state
            resource_id = f"saved_search.{search_name}"
            if resource_id in deployed_searches:
                # Plan update
                resource_state = deployed_searches[resource_id]

                # Fetch current remote state
                current_state = self.saved_search_provider.fetch_remote_state(resource_state.id)

                if current_state:
                    change = self.saved_search_provider.plan_update(
                        template,
                        current_state,
                        template.get('template_path', '')
                    )

                    if change.action == ResourceAction.UPDATE:
                        to_update.append(change)
                else:
                    # Resource in state but not found remotely - recreate
                    change = self.saved_search_provider.plan_create(
                        template,
                        template.get('template_path', '')
                    )
                    to_create.append(change)
            else:
                # Plan create
                change = self.saved_search_provider.plan_create(
                    template,
                    template.get('template_path', '')
                )
                to_create.append(change)

        # Plan deletes for deployed searches not in templates
        template_names = set(templates.keys())
        for search_name in deployed_search_names:
            if search_name not in template_names:
                resource_id = f"saved_search.{search_name}"
                resource_state = deployed_searches[resource_id]

                change = self.saved_search_provider.plan_delete(
                    resource_state.id,
                    search_name
                )
                to_delete.append(change)

        return {
            'create': to_create,
            'update': to_update,
            'delete': to_delete
        }

    def apply_saved_search_change(
        self,
        change: ResourceChange,
        template: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        DEPRECATED: Use apply_resource_change('saved_search', change, template) instead.

        Apply a single saved search change.

        Args:
            change: ResourceChange to apply
            template: Saved search template

        Returns:
            Result metadata
        """
        if change.action == ResourceAction.CREATE:
            # Apply create
            result = self.saved_search_provider.apply_create(template)

            # Update state
            content_hash = self.saved_search_provider.compute_content_hash(template)
            dependencies = self.saved_search_provider.extract_dependencies(template)

            resource_state = ResourceState(
                type='saved_search',
                id=result['id'],
                content_hash=content_hash,
                template_path=change.template_path or '',
                deployed_at=result.get('created_at', datetime.now(timezone.utc).isoformat()),
                last_modified=result.get('created_at', datetime.now(timezone.utc).isoformat()),
                provider_metadata={
                    'id': result['id'],
                    'name': result['name'],
                    'search_domain': result['search_domain']
                },
                dependencies=list(dependencies.keys()) if dependencies else []
            )

            self.state_manager.set_resource('saved_search', change.resource_name, resource_state)
            if self.auto_save:
                self.state_manager.save()

            return result

        elif change.action == ResourceAction.UPDATE:
            # Apply update
            current_state = self.saved_search_provider.fetch_remote_state(change.resource_id)
            result = self.saved_search_provider.apply_update(
                change.resource_id,
                template,
                current_state
            )

            # IMPORTANT: Update returns NEW ID!
            new_id = result['id']
            old_id = result.get('old_id', change.resource_id)

            # Update state with new ID
            content_hash = self.saved_search_provider.compute_content_hash(template)
            dependencies = self.saved_search_provider.extract_dependencies(template)

            resource_state = ResourceState(
                type='saved_search',
                id=new_id,  # Use new ID!
                content_hash=content_hash,
                template_path=change.template_path or '',
                deployed_at=self.state_manager.get_resource('saved_search', change.resource_name).deployed_at,
                last_modified=result.get('updated_at', datetime.now(timezone.utc).isoformat()),
                provider_metadata={
                    'id': new_id,
                    'old_id': old_id,  # Track ID change
                    'name': result['name'],
                    'search_domain': result['search_domain']
                },
                dependencies=list(dependencies.keys()) if dependencies else []
            )

            self.state_manager.set_resource('saved_search', change.resource_name, resource_state)
            if self.auto_save:
                self.state_manager.save()

            logger.info(f"Saved search ID changed: {old_id} -> {new_id}")
            return result

        elif change.action == ResourceAction.DELETE:
            # Apply delete
            result = self.saved_search_provider.apply_delete(change.resource_id)

            # Remove from state
            self.state_manager.delete_resource('saved_search', change.resource_name)
            if self.auto_save:
                self.state_manager.save()

            return result

        else:
            logger.warning(f"Unknown action: {change.action}")
            return {}

    def plan_lookup_file_changes(
        self,
        templates: Dict[str, Dict[str, Any]],
        search_domain: str = 'falcon'
    ) -> Dict[str, List[ResourceChange]]:
        """
        DEPRECATED: Use plan_resource_changes('lookup_file', templates) instead.

        Generate a plan for lookup file changes using the provider.

        Args:
            templates: Dictionary mapping lookup file names to template data
            search_domain: Search domain (all/falcon/third-party/dashboards/parsers-repository)

        Returns:
            Dictionary with 'create', 'update', 'delete' lists
        """
        to_create = []
        to_update = []
        to_delete = []

        # Get current deployed lookup files from state
        deployed_files = self.state_manager.get_all_resources('lookup_file')
        deployed_file_names = {name.split('.')[1] for name in deployed_files.keys()}

        # Plan creates and updates
        for file_name, template in templates.items():
            # Ensure _search_domain is set
            if '_search_domain' not in template:
                template['_search_domain'] = search_domain

            # Validate template first
            errors = self.lookup_file_provider.validate_template(template)
            if errors:
                logger.warning(f"Template validation failed for {file_name}: {errors}")
                continue

            # Check if exists in state
            resource_id = f"lookup_file.{file_name}"
            if resource_id in deployed_files:
                # Plan update
                resource_state = deployed_files[resource_id]

                # Fetch current remote state
                current_state = self.lookup_file_provider.fetch_remote_state(resource_state.id)

                if current_state:
                    change = self.lookup_file_provider.plan_update(
                        template,
                        current_state,
                        template.get('template_path', '')
                    )

                    if change.action == ResourceAction.UPDATE:
                        to_update.append(change)
                else:
                    # Resource in state but not found remotely - recreate
                    change = self.lookup_file_provider.plan_create(
                        template,
                        template.get('template_path', '')
                    )
                    to_create.append(change)
            else:
                # Plan create
                change = self.lookup_file_provider.plan_create(
                    template,
                    template.get('template_path', '')
                )
                to_create.append(change)

        # Plan deletes for deployed files not in templates
        template_names = set(templates.keys())
        for file_name in deployed_file_names:
            if file_name not in template_names:
                resource_id = f"lookup_file.{file_name}"
                resource_state = deployed_files[resource_id]

                change = self.lookup_file_provider.plan_delete(
                    resource_state.id,
                    file_name
                )
                to_delete.append(change)

        return {
            'create': to_create,
            'update': to_update,
            'delete': to_delete
        }

    def apply_lookup_file_change(
        self,
        change: ResourceChange,
        template: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        DEPRECATED: Use apply_resource_change('lookup_file', change, template) instead.

        Apply a single lookup file change.

        Args:
            change: ResourceChange to apply
            template: Lookup file template

        Returns:
            Result metadata from the provider
        """
        if change.action == ResourceAction.CREATE:
            # Apply create
            result = self.lookup_file_provider.apply_create(template)

            # Extract dependencies
            dependencies = self.lookup_file_provider.extract_dependencies(template)

            # Add to state
            resource_state = ResourceState(
                type='lookup_file',
                id=result['filename'],
                content_hash=self.lookup_file_provider.compute_content_hash(template),
                template_path=template.get('template_path', ''),
                deployed_at=result.get('created_at', datetime.now(timezone.utc).isoformat()),
                last_modified=result.get('created_at', datetime.now(timezone.utc).isoformat()),
                provider_metadata={
                    'filename': result['filename'],
                    'format': result['format'],
                    'search_domain': result['search_domain'],
                    'size_bytes': result.get('size_bytes', 0)
                },
                dependencies=list(dependencies.keys()) if dependencies else []
            )

            self.state_manager.set_resource('lookup_file', change.resource_name, resource_state)
            if self.auto_save:
                self.state_manager.save()

            return result

        elif change.action == ResourceAction.UPDATE:
            # Fetch current state
            current_state = self.lookup_file_provider.fetch_remote_state(change.resource_id)

            # Apply update
            result = self.lookup_file_provider.apply_update(
                change.resource_id,
                template,
                current_state or {}
            )

            # Extract dependencies
            dependencies = self.lookup_file_provider.extract_dependencies(template)

            # Update state
            resource_state = ResourceState(
                type='lookup_file',
                id=result['filename'],
                content_hash=self.lookup_file_provider.compute_content_hash(template),
                template_path=template.get('template_path', ''),
                deployed_at=self.state_manager.get_resource('lookup_file', change.resource_name).deployed_at,
                last_modified=result.get('updated_at', datetime.now(timezone.utc).isoformat()),
                provider_metadata={
                    'filename': result['filename'],
                    'format': result['format'],
                    'search_domain': result['search_domain'],
                    'size_bytes': result.get('size_bytes', 0)
                },
                dependencies=list(dependencies.keys()) if dependencies else []
            )

            self.state_manager.set_resource('lookup_file', change.resource_name, resource_state)
            if self.auto_save:
                self.state_manager.save()

            return result

        elif change.action == ResourceAction.DELETE:
            # Apply delete
            result = self.lookup_file_provider.apply_delete(change.resource_id)

            # Remove from state
            self.state_manager.delete_resource('lookup_file', change.resource_name)
            if self.auto_save:
                self.state_manager.save()

            return result

        else:
            logger.warning(f"Unknown action: {change.action}")
            return {}
