"""
State Synchronizer

Manages state updates after successful deployments, including:
- Fetching actual deployed state from CrowdStrike API
- Computing template hashes for change detection
- Managing provider metadata for robust tracking
- Writing resource IDs back to template files
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

import yaml

from talonctl.core.base_provider import ResourceChange, ResourceAction
from talonctl.core.envelope import API_VERSION

logger = logging.getLogger(__name__)


def _contains_v2_document(raw_text: str) -> bool:
    """True if any mapping document in `raw_text` declares `apiVersion: talon/v2`.

    Mirrors ``envelope_loader._iter_documents``' flattening (multi-doc streams and
    top-level lists). Unparseable YAML returns False so the caller falls back to
    its legacy line-based path rather than silently skipping a v1 template.
    """
    try:
        raw_docs = list(yaml.safe_load_all(raw_text))
    except yaml.YAMLError:
        return False
    for item in raw_docs:
        if isinstance(item, list):
            if any(isinstance(d, dict) and d.get("apiVersion") == API_VERSION for d in item):
                return True
        elif isinstance(item, dict) and item.get("apiVersion") == API_VERSION:
            return True
    return False


class StateSynchronizer:
    """
    Synchronizes deployment state after successful operations.

    Responsibilities:
    - Fetch actual deployed state from CrowdStrike API
    - Update state manager with current deployment status
    - Write resource IDs back to template files (for CREATE actions)
    - Compute and store template content hashes
    - Manage provider metadata for robust state tracking
    """

    @staticmethod
    def select_persisted_id(provider_result: dict) -> Optional[str]:
        """Pick the identifier that is safe to persist in state.

        CrowdStrike correlation rules carry three identifiers: `id` (a per-version
        ULID that changes on every update), `rule_id` (the permanent ULID the
        console addresses) and `executor_rule_id`. Only `rule_id` is stable, so it
        wins wherever both are present — persisting `id` yields a state entry that
        stops addressing the rule after its next update.

        Providers that expose a single identifier (saved searches, dashboards, ...)
        return only `id`, which stays correct via the fallback.
        """
        return provider_result.get("rule_id") or provider_result.get("id") or None

    def __init__(self, state_manager, provider_adapter):
        """
        Initialize state synchronizer.

        Args:
            state_manager: StateManager instance for persisting state
            provider_adapter: ProviderAdapter instance for provider access
        """
        self.state_manager = state_manager
        self.provider_adapter = provider_adapter

    def update_after_deployment(
        self, deployed: List[str], changes: List[ResourceChange], deploy_results: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Update state after successful deployment.

        Fetches actual deployed state from CrowdStrike API to ensure
        state reflects the real deployed configuration (including any
        API normalizations or defaults).

        Args:
            deployed: List of deployed resource IDs
            changes: All changes that were attempted
        """
        state = self.state_manager.export_to_dict()

        # Pre-fetch remote caches ONCE for all CREATE actions (optimization)
        # This prevents fetching all rules N times for N CREATE actions
        create_resources = [
            r
            for r in deployed
            if any(c.resource_id == r and c.action in (ResourceAction.CREATE, ResourceAction.REPLACE) for c in changes)
        ]
        if create_resources:
            self._prefetch_remote_caches(create_resources, changes)

        for resource_id in deployed:
            # Find corresponding change
            change = next((c for c in changes if c.resource_id == resource_id), None)
            if not change:
                continue

            # Update state for this resource
            resource_type = change.resource_type
            resource_name = change.resource_name

            if resource_type not in state["resources"]:
                state["resources"][resource_type] = {}

            provider = self.provider_adapter.providers.get(resource_type)
            if not provider:
                logger.warning(f"No provider for {resource_type}, skipping state update")
                continue

            # Fast path: use UUID directly from provider response (most reliable — no re-fetch needed)
            provider_result = (deploy_results or {}).get(resource_id, {})
            fast_path_id = self.select_persisted_id(provider_result)

            if provider_result and not fast_path_id:
                logger.warning(
                    f"Provider result for {resource_id} has neither 'id' nor 'rule_id' — "
                    f"falling back to remote fetch. Keys present: {list(provider_result.keys())}"
                )

            if fast_path_id:
                actual_resource_id = fast_path_id
                remote_state = provider_result  # store as provider_metadata
            else:
                # Fallback: fetch current state from CrowdStrike API
                actual_resource_id, remote_state = self._fetch_deployed_state(provider, change, resource_name)
                # Override UUID from remote_state if available (slow-path only)
                if remote_state:
                    if "rule_id" in remote_state:
                        actual_resource_id = remote_state["rule_id"]
                        logger.debug(f"Updated actual_resource_id from remote_state rule_id: {actual_resource_id}")
                    elif "id" in remote_state:
                        actual_resource_id = remote_state["id"]
                        logger.debug(f"Updated actual_resource_id from remote_state id: {actual_resource_id}")

            # Always compute hash from template for consistent change detection (Terraform model)
            content_hash = provider.compute_content_hash(change.new_value)

            logger.debug(f"Stored template hash for {resource_id} (hash: {content_hash[:8]}...)")

            # Extract display_name from template
            display_name = change.new_value.get("name") if change.new_value else None

            # Create state entry with all metadata
            state_entry = self._build_state_entry(
                resource_type=resource_type,
                resource_id=actual_resource_id if actual_resource_id else resource_id,
                content_hash=content_hash,
                template_path=change.template_path or "",
                remote_state=remote_state,
                display_name=display_name,
            )

            # Store provider_metadata if we fetched remote state (makes state more robust)
            if remote_state:
                logger.debug(f"[DEBUG] Stored provider_metadata for {resource_name}")

            state["resources"][resource_type][resource_name] = state_entry

            logger.debug(f"[DEBUG] Stored state for {resource_name} with id: {actual_resource_id}")

            # Write rule_id back to template file for CREATE actions
            # This allows templates to be self-contained and resilient to name changes in console
            if (
                change.action in (ResourceAction.CREATE, ResourceAction.REPLACE)
                and actual_resource_id
                and change.template_path
            ):
                self._write_resource_id_to_template(
                    template_path=change.template_path,
                    resource_id=actual_resource_id,
                    resource_type=resource_type,
                    resource_name=resource_name,
                )

        # Save updated state
        self.state_manager.save()
        logger.info("State updated successfully")

    def _prefetch_remote_caches(self, create_resource_ids: List[str], changes: List[ResourceChange]) -> None:
        """
        Pre-fetch remote caches for CREATE operations (one API call per resource type).

        This optimization prevents fetching all remote resources N times for N CREATE
        actions. Instead, we fetch once per resource type before processing.

        Args:
            create_resource_ids: List of resource IDs that were created
            changes: All changes that were attempted
        """
        # Group by resource type
        types_to_fetch = set()
        for rid in create_resource_ids:
            change = next((c for c in changes if c.resource_id == rid), None)
            if change:
                types_to_fetch.add(change.resource_type)

        # Fetch each type once
        for resource_type in types_to_fetch:
            provider = self.provider_adapter.providers.get(resource_type)
            if not provider:
                continue

            if hasattr(provider, "_fetch_all_remote_rules"):
                logger.info(f"Pre-fetching remote rules cache for {len(create_resource_ids)} CREATE operations")
                provider._fetch_all_remote_rules()
            elif hasattr(provider, "_fetch_all_remote_searches"):
                logger.info("Pre-fetching remote searches cache for CREATE operations")
                provider._fetch_all_remote_searches()
            elif hasattr(provider, "_fetch_all_remote_dashboards"):
                logger.info("Pre-fetching remote dashboards cache for CREATE operations")
                provider._fetch_all_remote_dashboards()

    def _fetch_deployed_state(
        self, provider, change: ResourceChange, resource_name: str
    ) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
        """
        Fetch actual deployed state from CrowdStrike API.

        For updates, uses existing resource ID from state.
        For creates, searches by name in provider cache.

        Args:
            provider: Resource provider instance
            change: Resource change that was deployed
            resource_name: Name of the resource

        Returns:
            Tuple of (actual_resource_id, remote_state)
        """
        actual_resource_id = None
        remote_state = None

        # CRITICAL: For detections, we need rule_id (permanent), not version_id

        # First try to get rule_id from provider_metadata if available (most reliable)
        if change.old_value and "provider_metadata" in change.old_value:
            actual_resource_id = change.old_value["provider_metadata"].get("rule_id")
            logger.debug(f"Using rule_id from provider_metadata: {actual_resource_id}")

        # Fallback to 'id' field from old_value (may be stale for detections)
        if not actual_resource_id and change.old_value:
            actual_resource_id = change.old_value.get("id")
            logger.debug(f"Using id from old_value: {actual_resource_id}")

        if not hasattr(provider, "fetch_remote_state"):
            return actual_resource_id, None

        try:
            if actual_resource_id:
                # For updates, fetch by resource ID
                logger.debug(f"Fetching remote state for {change.resource_id} by ID")
                remote_state = provider.fetch_remote_state(actual_resource_id)
            else:
                # For creates, try to find by name since we don't have ID yet
                # Cache is already pre-fetched by _prefetch_remote_caches() before the loop
                logger.debug(f"Fetching remote state for {change.resource_id} (newly created)")

                # Try to find by searching the cache by name
                # Detection provider uses _remote_rules_cache with 'rule_id'
                # Saved search provider uses _remote_searches_cache with 'id'
                cache = None
                id_field = "rule_id"  # Default for detections

                if hasattr(provider, "_remote_rules_cache") and provider._remote_rules_cache:
                    cache = provider._remote_rules_cache
                    id_field = "rule_id"
                elif hasattr(provider, "_remote_searches_cache") and provider._remote_searches_cache:
                    cache = provider._remote_searches_cache
                    id_field = "id"

                if cache:
                    for resource_key, resource_data in cache.items():
                        if resource_key == resource_name:
                            remote_state = resource_data
                            actual_resource_id = resource_data.get(id_field)
                            logger.debug(
                                f"Found newly created resource {change.resource_id} with {id_field} {actual_resource_id}"
                            )
                            break

                if not remote_state:
                    logger.debug(f"Could not find remote state for newly created {change.resource_id}")

        except Exception as e:
            logger.warning(f"Failed to fetch remote state for {change.resource_id}: {e}")

        return actual_resource_id, remote_state

    def _build_state_entry(
        self,
        resource_type: str,
        resource_id: str,
        content_hash: str,
        template_path: str,
        remote_state: Optional[Dict[str, Any]],
        display_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build state entry for a deployed resource.

        Args:
            resource_type: Type of resource
            resource_id: Resource ID (rule_id for detections)
            content_hash: Hash of template content
            template_path: Path to template file
            remote_state: Remote state fetched from API (if available)
            display_name: Human-readable display name (from template 'name' field)

        Returns:
            State entry dictionary
        """
        state_entry = {
            "type": resource_type,
            "id": resource_id,  # Use rule_id for detections
            "content_hash": content_hash,
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "last_modified": datetime.now(timezone.utc).isoformat(),
            "template_path": template_path,
            "dependencies": [],  # Dependencies are handled by resource graph, not stored per-resource
        }

        # Store display_name if provided
        if display_name:
            state_entry["display_name"] = display_name

        # Store provider_metadata if we fetched remote state (makes state more robust)
        if remote_state:
            # Filter out non-JSON-serializable fields (e.g., bytes content from lookup files)
            filtered_metadata = {k: v for k, v in remote_state.items() if not isinstance(v, bytes)}
            state_entry["provider_metadata"] = filtered_metadata

        return state_entry

    def _write_resource_id_to_template(
        self, template_path: str, resource_id: str, resource_type: str, resource_name: str
    ) -> None:
        """
        Write resource ID back to template file after creation.

        This allows templates to track their deployed resource ID for resilient matching,
        even if the resource name changes in the console.

        Currently only implemented for detection templates (rule_id field).

        Args:
            template_path: Path to template file
            resource_id: Resource ID from CrowdStrike
            resource_type: Type of resource
            resource_name: Name of resource
        """
        try:
            template_file = Path(template_path)

            if not template_file.exists():
                logger.warning(f"Template file not found: {template_path}")
                return

            # Only write rule_id for detection templates
            if resource_type != "detection":
                return

            # Read template file preserving formatting
            raw_text = template_file.read_text(encoding="utf-8")

            # talon/v2 has no authored home for rule_id: the envelope schema is
            # `additionalProperties: false` at the top level, and v1_compat drops
            # the key on load. The permanent rule UUID already lives in state as
            # provider_metadata.rule_id and surfaces through the read-only
            # `status` projection, so there is nothing to write back. The
            # line-based insert below assumes the first `name:` line is the
            # top-level name -- in v2 it is the indented `metadata.name`, and a
            # column-0 insert there corrupts the file (issue #37).
            if _contains_v2_document(raw_text):
                logger.debug(
                    f"Skipping rule_id write-back for talon/v2 template: {template_file.name} "
                    f"(rule_id lives in state, not the template)"
                )
                return

            # splitlines() -- not readlines() -- because it also breaks on \x85, \u2028
            # and \u2029, which YAML 1.1 counts as line breaks. That keeps this
            # line-based scan aligned with the parser's own view of the file.
            lines = raw_text.splitlines(keepends=True)

            # Whether a rule_id line exists must be decided over the WHOLE file
            # before rewriting: a single forward pass that inserts after `name:`
            # on the way to a later `rule_id:` line writes a duplicate key.
            rule_id_exists = any(line.strip().startswith("rule_id:") for line in lines)

            modified_lines = []
            rule_id_written = False

            for line in lines:
                if rule_id_exists:
                    # Update the existing rule_id in place (first occurrence wins;
                    # any further ones are left alone rather than multiplied).
                    if not rule_id_written and line.strip().startswith("rule_id:"):
                        modified_lines.append(f"rule_id: {resource_id}\n")
                        rule_id_written = True
                        continue
                    modified_lines.append(line)
                    continue

                modified_lines.append(line)

                # No rule_id anywhere in the file: insert one after the name field.
                if not rule_id_written and line.strip().startswith("name:"):
                    modified_lines.append(f"rule_id: {resource_id}\n")
                    rule_id_written = True

            if rule_id_written:
                # Write back to file
                with open(template_file, "w", encoding="utf-8") as f:
                    f.writelines(modified_lines)

                if rule_id_exists:
                    logger.debug(f"Updated rule_id in template: {template_file.name}")
                else:
                    logger.info(f"✓ Added rule_id to template: {resource_name} ({resource_id})")
            else:
                logger.warning(f"Could not find suitable location to insert rule_id in {template_path}")

        except Exception as e:
            logger.error(f"Failed to write rule_id to template {template_path}: {e}")
            # Don't fail deployment if template write-back fails
            # The state file still has the correct ID
