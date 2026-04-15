"""
SavedSearchProvider - CrowdStrike NGSIEM Saved Queries

This provider implements the BaseResourceProvider interface for managing
CrowdStrike NGSIEM saved queries as Infrastructure as Code resources.

Uses raw NGSIEM Content API endpoints (not yet in FalconPy SDK).
"""

import json
import yaml
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone

from talonctl.core.base_provider import (
    BaseResourceProvider,
    ResourceAction,
    ResourceChange
)

logger = logging.getLogger(__name__)


class SavedSearchProvider(BaseResourceProvider):
    """
    Provider for CrowdStrike NGSIEM Saved Queries

    Manages saved queries as IaC resources with support for:
    - Template validation (LogScale YAML format)
    - Remote state fetching from NGSIEM Content API
    - Change detection and planning
    - Saved query creation and updates
    - Raw API endpoint integration (not yet in FalconPy SDK)

    Note: PATCH operations return a NEW ID for the updated query.
    """

    # Valid search domain options
    VALID_SEARCH_DOMAINS = ['all', 'falcon', 'third-party', 'dashboards']

    # Default values for optional fields (matches CrowdStrike API defaults)
    # These ensure consistent hash computation between templates and remote state
    DEFAULT_TIME_INTERVAL = {"isLive": True, "start": "24h"}
    DEFAULT_VISUALIZATION = {"options": {}, "type": "list-view"}

    def __init__(self, falcon_client: Any, config: Optional[Dict[str, Any]] = None):
        """
        Initialize saved search provider

        Args:
            falcon_client: Authenticated FalconPy APIHarnessV2 instance
            config: Optional provider configuration
        """
        self.falcon = falcon_client
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)
        self._remote_searches_cache: Optional[Dict[str, Dict[str, Any]]] = None

    def get_resource_type(self) -> str:
        """Return resource type identifier"""
        return "saved_search"

    def validate_template(self, template: Dict[str, Any]) -> List[str]:
        """
        Validate saved query template

        Args:
            template: Saved query template data (LogScale YAML format)

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Required fields for LogScale saved query schema
        required_fields = ['$schema', 'name', 'queryString']
        for field in required_fields:
            if field not in template:
                errors.append(f"Missing required field: {field}")

        # Check for API parameter
        if '_search_domain' not in template:
            errors.append("Missing required API parameter: _search_domain")

        # Validate _search_domain
        search_domain = template.get('_search_domain')
        if search_domain and search_domain not in self.VALID_SEARCH_DOMAINS:
            errors.append(
                f"Invalid _search_domain: {search_domain}. "
                f"Must be one of {self.VALID_SEARCH_DOMAINS}"
            )

        # Validate queryString is non-empty string
        query_string = template.get('queryString', '')
        if not isinstance(query_string, str) or not query_string.strip():
            errors.append("'queryString' must be a non-empty string")

        # Validate name is non-empty string
        name = template.get('name', '')
        if not isinstance(name, str) or not name.strip():
            errors.append("'name' must be a non-empty string")

        # Validate optional fields if present
        if 'description' in template:
            if not isinstance(template['description'], str):
                errors.append("'description' must be a string")

        if 'timeInterval' in template:
            time_interval = template['timeInterval']
            if not isinstance(time_interval, (str, int)):
                errors.append("'timeInterval' must be a string or integer")

        return errors

    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch current state of a saved query from NGSIEM Content API

        Args:
            resource_id: The ID of the saved query

        Returns:
            Current saved query state or None if not found
        """
        try:
            # Try all search domains since we may not know which one it's in
            for search_domain in self.VALID_SEARCH_DOMAINS:
                result = self._fetch_saved_query_by_id(resource_id, search_domain)
                if result:
                    return result

            return None

        except Exception as e:
            logger.error(f"Failed to fetch saved query {resource_id}: {e}")
            return None

    def _fetch_saved_query_by_id(
        self,
        resource_id: str,
        search_domain: str
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch a specific saved query by ID from a search domain

        Uses raw NGSIEM Content API endpoint

        Args:
            resource_id: Saved query ID
            search_domain: Search domain (all/falcon/third-party/dashboards)

        Returns:
            Saved query data or None if not found
        """
        try:
            endpoint = "/ngsiem-content/entities/savedqueries-template/v1"
            override = f"GET,{endpoint}"

            response = self.falcon.command(
                override=override,
                parameters={
                    'ids': resource_id,
                    'search_domain': search_domain
                }
            )

            if response.get('status_code') == 200:
                body = response.get('body', {})
                resources = body.get('resources', [])

                if resources and len(resources) > 0:
                    # Parse YAML template
                    yaml_content = resources[0]

                    if isinstance(yaml_content, str):
                        # API returned YAML as string
                        query_data = yaml.safe_load(yaml_content)
                        query_data['id'] = resource_id
                        query_data['_search_domain'] = search_domain
                        query_data['yaml_template'] = yaml_content  # Keep raw YAML
                        return query_data

                    elif isinstance(yaml_content, dict):
                        # API returned a dict - check if it has yaml_template field to parse
                        if 'yaml_template' in yaml_content:
                            # Parse the embedded YAML template
                            yaml_str = yaml_content['yaml_template']
                            parsed_data = yaml.safe_load(yaml_str)
                            # Merge parsed data with metadata
                            parsed_data['id'] = resource_id
                            parsed_data['_search_domain'] = search_domain
                            parsed_data['yaml_template'] = yaml_str  # Keep raw YAML
                            return parsed_data
                        else:
                            # No yaml_template field, use dict as-is
                            yaml_content['id'] = resource_id
                            yaml_content['_search_domain'] = search_domain
                            return yaml_content

            return None

        except Exception as e:
            logger.debug(f"Saved query {resource_id} not found in {search_domain}: {e}")
            return None

    def _fetch_all_remote_searches(
        self,
        search_domain: str = 'all'
    ) -> Dict[str, Dict[str, Any]]:
        """
        Fetch all saved queries from a search domain

        Uses the NGSIEM Content API endpoint: GET /ngsiem-content/queries/savedqueries/v1
        Supports pagination to retrieve all saved queries.

        Args:
            search_domain: Search domain to query (all, falcon, third-party, dashboards)

        Returns:
            Dictionary of saved queries indexed by name
        """
        try:
            endpoint = "/ngsiem-content/queries/savedqueries/v1"
            override = f"GET,{endpoint}"

            saved_queries = {}
            limit = 100  # Fetch in batches of 100
            offset = 0

            while True:
                # Fetch batch of saved query IDs
                response = self.falcon.command(
                    override=override,
                    parameters={
                        'search_domain': search_domain,
                        'limit': limit,
                        'offset': offset
                    }
                )

                if response.get('status_code') != 200:
                    logger.warning(
                        f"Failed to fetch saved queries (offset {offset}): "
                        f"status {response.get('status_code')}"
                    )
                    break

                body = response.get('body', {})
                resources = body.get('resources', [])

                if not resources:
                    # No more results
                    break

                # Fetch full details for each saved query ID
                # Note: API returns query IDs, need to fetch details separately
                for query_id in resources:
                    try:
                        query_data = self._fetch_saved_query_by_id(query_id, search_domain)
                        if query_data:
                            query_name = query_data.get('name')
                            if query_name:
                                saved_queries[query_name] = query_data
                                logger.debug(f"Discovered saved query: {query_name} (ID: {query_id})")
                    except Exception as e:
                        logger.debug(f"Failed to fetch details for query {query_id}: {e}")
                        continue

                # Check pagination
                meta = body.get('meta', {})
                pagination = meta.get('pagination', {})
                total = pagination.get('total', 0)

                offset += limit

                # Stop if we've fetched all results
                if offset >= total or len(resources) < limit:
                    break

            logger.info(f"Discovered {len(saved_queries)} saved queries in domain '{search_domain}'")
            return saved_queries

        except Exception as e:
            logger.error(f"Failed to fetch saved queries from {search_domain}: {e}")
            return {}

    def create_resource(
        self,
        resource_id: Optional[str],
        template: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a new saved query in NGSIEM

        Args:
            resource_id: Ignored (API auto-generates ID)
            template: Saved query template data

        Returns:
            Created saved query metadata including ID

        Raises:
            RuntimeError: If creation fails
        """
        try:
            # Extract API parameter (not part of YAML template)
            search_domain = template.get('_search_domain', 'falcon')

            # DEBUG: Log template before cleaning
            logger.debug(f"[DEBUG] Original template keys: {list(template.keys())}")
            logger.debug(f"[DEBUG] Template name: '{template.get('name')}'")

            # Create clean template without API parameters and IaC-only metadata fields
            # Exclude: fields starting with '_' (e.g., _search_domain), 'type' (added by template discovery),
            # and IaC-only fields that are not part of the LogScale saved query schema
            IAC_ONLY_FIELDS = {'type', 'resource_id', 'dependencies'}
            clean_template = {k: v for k, v in template.items() if not k.startswith('_') and k not in IAC_ONLY_FIELDS}

            # DEBUG: Log cleaned template
            logger.debug(f"[DEBUG] Cleaned template keys: {list(clean_template.keys())}")
            logger.debug(f"[DEBUG] Cleaned template:\n{json.dumps(clean_template, indent=2)[:1000]}...")

            # Convert template to YAML
            yaml_template = yaml.dump(clean_template, default_flow_style=False)

            # DEBUG: Log YAML output and save to file for inspection
            logger.debug(f"[DEBUG] YAML length: {len(yaml_template)} bytes")
            logger.debug(f"[DEBUG] YAML first 500 chars:\n{yaml_template[:500]}")

            # Save to temp file for inspection
            import tempfile
            temp_yaml_path = f"/tmp/saved_search_debug_{template.get('name', 'unknown')}.yaml"
            with open(temp_yaml_path, 'w') as f:
                f.write(yaml_template)
            logger.debug(f"[DEBUG] Full YAML saved to: {temp_yaml_path}")

            endpoint = "/ngsiem-content/entities/savedqueries-template/v1"
            override = f"POST,{endpoint}"

            # Prepare multipart/form-data
            # yaml_template must be sent as file content
            files = [
                ('yaml_template', ('query.yaml', yaml_template.encode('utf-8'), 'text/yaml'))
            ]

            # search_domain as query parameter
            params = {
                'search_domain': search_domain
            }

            # DEBUG: Log API request details
            logger.debug(f"[DEBUG] Creating saved search with endpoint: {endpoint}")
            logger.debug(f"[DEBUG] Parameters: {params}")

            response = self.falcon.command(
                override=override,
                files=files,
                parameters=params
            )

            # DEBUG: Log API response
            logger.debug(f"[DEBUG] Create response status: {response.get('status_code')}")
            logger.debug(f"[DEBUG] Create response body:\n{json.dumps(response.get('body', {}), indent=2)[:1000]}...")

            if response.get('status_code') not in (200, 201):
                logger.debug(f"[DEBUG] Full error response:\n{json.dumps(response, indent=2)}")
                raise RuntimeError(
                    f"Failed to create saved query '{template['name']}': {response}"
                )

            # Extract ID from response
            body = response.get('body', {})
            resources = body.get('resources', [])

            if resources and len(resources) > 0:
                # API may return string ID or dict with 'id' field
                resource = resources[0]
                if isinstance(resource, str):
                    query_id = resource
                elif isinstance(resource, dict):
                    query_id = resource.get('id', 'unknown')
                else:
                    query_id = str(resource)
            else:
                # Fallback - try to extract from body
                query_id = body.get('id', 'unknown')

            return {
                'id': query_id,
                'name': template['name'],
                'search_domain': search_domain,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'response': body
            }

        except Exception as e:
            raise RuntimeError(f"Failed to create saved query: {e}") from e

    def update_resource(
        self,
        resource_id: str,
        template: Dict[str, Any],
        current_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update an existing saved query in NGSIEM

        IMPORTANT: PATCH operation returns a NEW ID for the updated query!

        Args:
            resource_id: Current saved query ID
            template: New saved query template data
            current_state: Current state (for comparison)

        Returns:
            Updated saved query metadata with NEW ID

        Raises:
            RuntimeError: If update fails
        """
        try:
            # Extract API parameter (not part of YAML template)
            search_domain = template.get('_search_domain', 'falcon')

            # DEBUG: Log template before cleaning
            logger.debug(f"[DEBUG] UPDATE - Original template keys: {list(template.keys())}")
            logger.debug(f"[DEBUG] UPDATE - Template name: '{template.get('name')}'")

            # Create clean template without API parameters and IaC-only metadata fields
            # Exclude: fields starting with '_' (e.g., _search_domain), 'type' (added by template discovery),
            # and IaC-only fields that are not part of the LogScale saved query schema
            IAC_ONLY_FIELDS = {'type', 'resource_id', 'dependencies'}
            clean_template = {k: v for k, v in template.items() if not k.startswith('_') and k not in IAC_ONLY_FIELDS}

            # DEBUG: Log cleaned template
            logger.debug(f"[DEBUG] UPDATE - Cleaned template keys: {list(clean_template.keys())}")

            # Convert template to YAML
            yaml_template = yaml.dump(clean_template, default_flow_style=False)

            # DEBUG: Log YAML output
            logger.debug(f"[DEBUG] UPDATE - YAML length: {len(yaml_template)} bytes")
            logger.debug(f"[DEBUG] UPDATE - YAML first 500 chars:\n{yaml_template[:500]}")

            endpoint = "/ngsiem-content/entities/savedqueries-template/v1"
            override = f"PATCH,{endpoint}"

            # Prepare multipart/form-data
            # yaml_template must be sent as file content
            files = [
                ('yaml_template', ('query.yaml', yaml_template.encode('utf-8'), 'text/yaml'))
            ]

            # search_domain and ids as query parameters
            params = {
                'search_domain': search_domain,
                'ids': resource_id
            }

            # DEBUG: Log API request details
            logger.debug(f"[DEBUG] UPDATE - Updating saved search with endpoint: {endpoint}")
            logger.debug(f"[DEBUG] UPDATE - Parameters: {params}")

            response = self.falcon.command(
                override=override,
                files=files,
                parameters=params
            )

            # DEBUG: Log API response
            logger.debug(f"[DEBUG] UPDATE - Response status: {response.get('status_code')}")
            logger.debug(f"[DEBUG] UPDATE - Response body:\n{json.dumps(response.get('body', {}), indent=2)[:1000]}...")

            if response.get('status_code') not in (200, 201):
                logger.debug(f"[DEBUG] UPDATE - Full error response:\n{json.dumps(response, indent=2)}")
                raise RuntimeError(
                    f"Failed to update saved query '{template['name']}' (ID: {resource_id}): {response}"
                )

            # Extract NEW ID from response
            body = response.get('body', {})
            resources = body.get('resources', [])

            if resources and len(resources) > 0:
                # API may return string ID or dict with 'id' field
                resource = resources[0]
                if isinstance(resource, str):
                    new_id = resource
                elif isinstance(resource, dict):
                    new_id = resource.get('id', resource_id)
                else:
                    new_id = str(resource)
            else:
                # Fallback
                new_id = body.get('id', resource_id)

            logger.info(
                f"Saved query updated: {resource_id} -> {new_id} "
                f"(PATCH returns new ID)"
            )

            return {
                'id': new_id,
                'old_id': resource_id,  # Track the ID change!
                'name': template['name'],
                'search_domain': search_domain,
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'response': body
            }

        except Exception as e:
            raise RuntimeError(f"Failed to update saved query: {e}") from e

    def delete_resource(self, resource_id: str) -> Dict[str, Any]:
        """
        Delete a saved query from NGSIEM

        Args:
            resource_id: Saved query ID to delete

        Returns:
            Deletion metadata

        Raises:
            RuntimeError: If deletion fails
        """
        try:
            # Try deleting from all search domains
            # (we may not know which domain it's in)
            deleted = False
            last_error = None
            last_response = None

            for search_domain in self.VALID_SEARCH_DOMAINS:
                try:
                    endpoint = "/ngsiem-content/entities/savedqueries/v1"
                    override = f"DELETE,{endpoint}"

                    response = self.falcon.command(
                        override=override,
                        parameters={
                            'ids': resource_id,
                            'search_domain': search_domain
                        }
                    )

                    last_response = response
                    status_code = response.get('status_code')
                    body = response.get('body', {})

                    # Check for successful deletion (200 with resources_affected > 0)
                    if status_code == 200:
                        # Verify deletion in response body
                        resources_affected = body.get('meta', {}).get('writes', {}).get('resources_affected', 0)
                        resources = body.get('resources', [])

                        if resources_affected > 0 or (resources and resource_id in resources):
                            logger.info(
                                f"Deleted saved query {resource_id} from {search_domain} "
                                f"(resources_affected: {resources_affected})"
                            )
                            deleted = True
                            break
                        else:
                            # 200 but no resources affected - may be wrong domain
                            logger.debug(
                                f"Got 200 but no resources affected in {search_domain}, trying next domain"
                            )
                            continue

                    # 404 means resource not found in this domain - try next
                    elif status_code == 404:
                        logger.debug(f"Saved query {resource_id} not found in {search_domain}")
                        continue

                    # Other error codes
                    else:
                        logger.debug(
                            f"Failed to delete from {search_domain}: status {status_code}"
                        )
                        continue

                except Exception as e:
                    last_error = e
                    logger.debug(f"Exception deleting from {search_domain}: {e}")
                    continue

            if not deleted:
                # Check if we got 404 from all domains - resource might not exist
                if last_response and last_response.get('status_code') == 404:
                    logger.warning(
                        f"Saved query {resource_id} not found in any domain - "
                        "may have been already deleted or never existed"
                    )
                    # Don't raise error for 404 - resource is gone (desired state)
                    return {
                        'id': resource_id,
                        'deleted_at': datetime.now(timezone.utc).isoformat(),
                        'note': 'Resource not found (may have been already deleted)'
                    }

                raise RuntimeError(
                    f"Failed to delete saved query {resource_id} from any domain. "
                    f"Last error: {last_error}, Last response: {last_response}"
                )

            return {
                'id': resource_id,
                'deleted_at': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            raise RuntimeError(f"Failed to delete saved query: {e}") from e

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        """
        Calculate deterministic hash of saved query content

        Includes: name, query, description, timeInterval, visualization, labels
        Always applies defaults for timeInterval and visualization to ensure
        consistent hashing between templates and remote state.

        Args:
            template: Saved query template

        Returns:
            SHA256 hash as hex string
        """
        # Normalize content for consistent hashing
        # Only hash the LogScale schema fields (exclude API parameters like _search_domain)
        normalized_content = {
            '$schema': template.get('$schema', 'https://schemas.humio.com/query/v0.6.0'),
            'name': template.get('name', ''),
            'queryString': template.get('queryString', ''),
            # Always include timeInterval and visualization with defaults
            # This ensures consistent hashing between templates and remote state
            'timeInterval': template.get('timeInterval', self.DEFAULT_TIME_INTERVAL),
            'visualization': template.get('visualization', self.DEFAULT_VISUALIZATION),
        }

        # Add other optional fields if present
        if 'description' in template:
            normalized_content['description'] = template['description']

        if 'interactions' in template:
            normalized_content['interactions'] = template['interactions']

        if 'labels' in template:
            normalized_content['labels'] = template['labels']

        # Calculate hash
        content_str = json.dumps(normalized_content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def extract_dependencies(self, template: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract resource dependencies from saved query template

        Saved queries typically don't depend on other resources.
        They are usually consumed BY detections (reverse dependency).

        Args:
            template: Saved query template

        Returns:
            Empty dict (no dependencies)
        """
        # Saved queries don't typically depend on other resources
        # Detections depend on saved queries (via query_id)
        return {}

    # BaseResourceProvider planning methods

    def plan_create(self, template: Dict[str, Any], template_path: str) -> ResourceChange:
        """Plan the creation of a new saved query"""
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
        """Plan an update to an existing saved query"""
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

        # Detect changes (compare LogScale schema fields)
        changes = {}
        for key in ['$schema', 'name', 'queryString', 'description', 'timeInterval', 'visualization', 'interactions', 'labels']:
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

    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        """Plan the deletion of a saved query"""
        return ResourceChange(
            action=ResourceAction.DELETE,
            resource_type=self.get_resource_type(),
            resource_name=resource_name,
            resource_id=resource_id
        )

    # Convenience methods matching DetectionProvider naming

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

    # Helper method for calculating content hash (alternate name for consistency)
    def calculate_content_hash(self, template: Dict[str, Any]) -> str:
        """Alias for compute_content_hash"""
        return self.compute_content_hash(template)

    def to_template(self, remote_resource: dict) -> dict:
        """
        Convert a remote saved query into a YAML template dict.

        The remote format from _fetch_all_remote_searches() closely matches
        the template format (LogScale YAML schema), so mostly a passthrough
        with cleanup of API-only metadata fields.

        Args:
            remote_resource: Saved query dict from _fetch_all_remote_searches()

        Returns:
            Template dict ready for YAML serialization
        """
        name = remote_resource.get('name', '')
        resource_id = self._name_to_resource_id(name) if name else 'unknown'

        template = {
            '$schema': remote_resource.get('$schema', 'https://schemas.humio.com/query/v0.6.0'),
            'resource_id': resource_id,
            'name': name,
        }

        # Description
        description = remote_resource.get('description', '')
        if description:
            template['description'] = description

        # Query string (the core content)
        query_string = remote_resource.get('queryString', '')
        if query_string:
            template['queryString'] = query_string

        # Search domain (API parameter)
        search_domain = remote_resource.get('_search_domain', 'all')
        template['_search_domain'] = search_domain

        # Optional fields
        if 'timeInterval' in remote_resource:
            ti = remote_resource['timeInterval']
            # Only include if non-default
            if ti != self.DEFAULT_TIME_INTERVAL:
                template['timeInterval'] = ti

        if 'visualization' in remote_resource:
            viz = remote_resource['visualization']
            # Only include if non-default
            if viz != self.DEFAULT_VISUALIZATION:
                template['visualization'] = viz

        if 'interactions' in remote_resource:
            template['interactions'] = remote_resource['interactions']

        if 'labels' in remote_resource:
            template['labels'] = remote_resource['labels']

        return template

    def suggest_path(self, template: dict) -> str:
        """
        Suggest a file path for a saved search template.

        Args:
            template: Template dict from to_template()

        Returns:
            Relative path like 'saved_searches/aws_enrich_user_identity.yaml'
        """
        resource_id = template.get('resource_id', '')
        if not resource_id:
            resource_id = self._name_to_resource_id(template.get('name', 'unknown'))

        return f"saved_searches/{resource_id}.yaml"

