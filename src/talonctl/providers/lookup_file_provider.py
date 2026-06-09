"""
LookupFileProvider - CrowdStrike NGSIEM Lookup Files

This provider implements the BaseResourceProvider interface for managing
CrowdStrike NGSIEM lookup files (CSV/JSON) as Infrastructure as Code resources.

Uses NGSIEM Content API endpoints for full CRUD operations.
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, TYPE_CHECKING
from datetime import datetime, timezone

from talonctl.core.base_provider import BaseResourceProvider, ResourceAction, ResourceChange
from talonctl.project import find_project_root

if TYPE_CHECKING:
    from talonctl.core.envelope import Envelope
from talonctl.core.metadata_validators import reject_old_shape, validate_maturity
from talonctl.core.template_sanitizer import strip_for_hash

logger = logging.getLogger(__name__)


class LookupFileProvider(BaseResourceProvider):
    """
    Provider for CrowdStrike NGSIEM Lookup Files

    Manages lookup files (CSV/JSON) as IaC resources with support for:
    - Template validation (file existence, size limits, format)
    - Remote state fetching from NGSIEM Content API
    - Change detection via content hashing
    - Full CRUD operations (create, read, update, delete)
    - Binary file handling (CSV and JSON formats)

    File Size Limits:
    - CSV: 209.7 MB
    - JSON: 104.9 MB
    """

    # Valid search domain options
    VALID_SEARCH_DOMAINS = ["all", "falcon", "third-party", "dashboards", "parsers-repository"]

    # Valid file formats
    VALID_FORMATS = ["csv", "json"]

    # File size limits in bytes
    MAX_FILE_SIZE_CSV = 209.7 * 1024 * 1024  # 209.7 MB
    MAX_FILE_SIZE_JSON = 104.9 * 1024 * 1024  # 104.9 MB

    def __init__(self, falcon_client: Any, config: Optional[Dict[str, Any]] = None):
        """
        Initialize lookup file provider

        Args:
            falcon_client: Authenticated FalconPy APIHarnessV2 instance
            config: Optional provider configuration
        """
        self.falcon = falcon_client
        self.config = config or {}
        self.timeout = self.config.get("timeout", 30)

    def get_resource_type(self) -> str:
        """Return resource type identifier"""
        return "lookup_file"

    def _resolve_source_path(self, template: Dict[str, Any]) -> str:
        """Resolve a lookup file's ``source`` to an absolute path.

        Absolute sources pass through. Relative sources are authored
        project-root-relative (e.g. ``resources/lookup_files/x.csv``), so they
        anchor to the project root walked up from the template's own location
        (``_template_path``) — never the current working directory. This keeps
        ``talonctl --path`` (and any run from a foreign CWD) correct. When the
        template's origin is unknown (e.g. a hand-built dict in tests), fall
        back to CWD-relative resolution to preserve historical behavior.
        """
        source = template["source"]
        if os.path.isabs(source):
            return source
        template_path = template.get("_template_path")
        if template_path:
            root = find_project_root(Path(template_path).parent)
            return str((root / source).resolve())
        return os.path.abspath(source)

    def validate_template(self, env: "Envelope") -> List[str]:
        """
        Validate lookup file template

        Args:
            env: Lookup file Envelope

        Returns:
            List of validation error messages (empty if valid)
        """
        template = env.to_working_dict()
        errors = []

        # v0.3.0: reject pre-v0.3.0 shapes and validate metadata.maturity universally.
        errors.extend(reject_old_shape(template))
        errors.extend(validate_maturity(template))

        # metadata.ads is detection-only; flag on this provider.
        metadata_block = template.get("metadata")
        if isinstance(metadata_block, dict) and "ads" in metadata_block:
            errors.append("metadata.ads is only supported on detection resources (this is a lookup_file template)")

        # Required fields
        required_fields = ["name", "format", "source"]
        for field in required_fields:
            if field not in template:
                errors.append(f"Missing required field: {field}")

        # Validate format
        file_format = template.get("format", "").lower()
        if file_format and file_format not in self.VALID_FORMATS:
            errors.append(f"Invalid format: {file_format}. Must be one of {self.VALID_FORMATS}")

        # Validate search_domain if present
        search_domain = template.get("_search_domain")
        if search_domain and search_domain not in self.VALID_SEARCH_DOMAINS:
            errors.append(f"Invalid _search_domain: {search_domain}. Must be one of {self.VALID_SEARCH_DOMAINS}")

        # Validate source file exists
        source_path = template.get("source")
        if source_path:
            # Relative sources anchor to the template's project root, not CWD.
            abs_path = self._resolve_source_path(template)

            if not os.path.exists(abs_path):
                errors.append(f"Source file not found: {source_path} (resolved to {abs_path})")
            else:
                # Check file size
                file_size = os.path.getsize(abs_path)

                if file_format == "csv" and file_size > self.MAX_FILE_SIZE_CSV:
                    size_mb = file_size / (1024 * 1024)
                    errors.append(f"CSV file exceeds 209.7 MB limit: {size_mb:.2f} MB")
                elif file_format == "json" and file_size > self.MAX_FILE_SIZE_JSON:
                    size_mb = file_size / (1024 * 1024)
                    errors.append(f"JSON file exceeds 104.9 MB limit: {size_mb:.2f} MB")

        # Validate name is non-empty
        name = template.get("name", "")
        if not isinstance(name, str) or not name.strip():
            errors.append("'name' must be a non-empty string")

        # Validate optional fields
        if "description" in template:
            if not isinstance(template["description"], str):
                errors.append("'description' must be a string")

        return errors

    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch current state of a lookup file from NGSIEM Content API

        Args:
            resource_id: The filename of the lookup file

        Returns:
            Current lookup file state or None if not found
        """
        try:
            # Try all search domains since we may not know which one it's in
            for search_domain in self.VALID_SEARCH_DOMAINS:
                result = self._fetch_lookup_file(resource_id, search_domain)
                if result:
                    return result

            return None

        except Exception as e:
            logger.error(f"Failed to fetch lookup file {resource_id}: {e}")
            return None

    def _fetch_lookup_file(self, filename: str, search_domain: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a lookup file from a specific search domain

        Args:
            filename: Lookup file filename
            search_domain: Search domain to query

        Returns:
            Lookup file metadata or None if not found
        """
        try:
            endpoint = "/ngsiem-content/entities/lookupfiles/v1"
            override = f"GET,{endpoint}"

            response = self.falcon.command(
                override=override, parameters={"filename": filename, "search_domain": search_domain}
            )

            # Check response type - API may return file content directly
            if isinstance(response, bytes):
                # Direct bytes response (file content)
                content = response
                return {
                    "filename": filename,
                    "search_domain": search_domain,
                    "content": content,
                    "content_hash": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                }

            # Check for successful response in dict format
            if isinstance(response, dict) and response.get("status_code") in (200, 201):
                body = response.get("body", {})

                # Response may contain file content in 'resources' or directly
                if isinstance(body, bytes):
                    # Direct file content in body
                    content = body
                elif isinstance(body, dict):
                    resources = body.get("resources", [])
                    if resources and len(resources) > 0:
                        content = resources[0]
                        if isinstance(content, dict):
                            content = content.get("content", b"")
                    else:
                        content = body.get("content", b"")
                else:
                    content = b""

                # Ensure content is bytes
                if isinstance(content, str):
                    content = content.encode("utf-8")

                if content:
                    return {
                        "filename": filename,
                        "search_domain": search_domain,
                        "content": content,
                        "content_hash": hashlib.sha256(content).hexdigest(),
                        "size_bytes": len(content),
                    }

            return None

        except Exception as e:
            logger.debug(f"Lookup file {filename} not found in {search_domain}: {e}")
            return None

    def plan_create(self, env: "Envelope", template_path: str) -> ResourceChange:
        """
        Plan creation of a new lookup file

        Args:
            env: Lookup file Envelope
            template_path: Path to template file

        Returns:
            ResourceChange with action=CREATE
        """
        template = env.to_working_dict()
        return ResourceChange(
            action=ResourceAction.CREATE,
            resource_type=self.get_resource_type(),
            resource_name=template["name"],
            new_value=template,
            template_path=template_path,
            envelope=env,
        )

    def plan_update(self, env: "Envelope", current_state: Dict[str, Any], template_path: str) -> ResourceChange:
        """
        Plan update of an existing lookup file

        Args:
            env: New lookup file Envelope
            current_state: Current state from remote
            template_path: Path to template file

        Returns:
            ResourceChange with action=UPDATE or NO_CHANGE
        """
        template = env.to_working_dict()
        # Compute hashes to detect changes
        new_hash = self.compute_content_hash(template)
        old_hash = current_state.get("content_hash", "")

        if new_hash != old_hash:
            return ResourceChange(
                action=ResourceAction.UPDATE,
                resource_type=self.get_resource_type(),
                resource_name=template["name"],
                resource_id=current_state.get("filename"),
                old_value=current_state,
                new_value=template,
                template_path=template_path,
                envelope=env,
            )
        else:
            return ResourceChange(
                action=ResourceAction.NO_CHANGE,
                resource_type=self.get_resource_type(),
                resource_name=template["name"],
                resource_id=current_state.get("filename"),
                template_path=template_path,
                envelope=env,
            )

    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        """
        Plan deletion of a lookup file

        Args:
            resource_id: Filename of lookup file to delete
            resource_name: Human-readable name

        Returns:
            ResourceChange with action=DELETE
        """
        return ResourceChange(
            action=ResourceAction.DELETE,
            resource_type=self.get_resource_type(),
            resource_name=resource_name,
            resource_id=resource_id,
        )

    def apply_create(self, env: "Envelope") -> Dict[str, Any]:
        """
        Create a new lookup file in NGSIEM

        Args:
            env: Lookup file Envelope

        Returns:
            Created lookup file metadata

        Raises:
            RuntimeError: If creation fails
        """
        template = env.to_working_dict()
        try:
            # Read file content (relative source anchors to template's project root)
            source_path = self._resolve_source_path(template)

            with open(source_path, "rb") as f:
                file_content = f.read()

            # Determine content type
            file_format = template["format"].lower()
            content_type = "text/csv" if file_format == "csv" else "application/json"

            # Get search domain
            search_domain = template.get("_search_domain", "falcon")
            filename = template["name"]

            # Prepare multipart file upload
            files = [("file", (filename, file_content, content_type))]

            # API parameters as formData
            data = {"search_domain": search_domain, "filename": filename}

            endpoint = "/ngsiem-content/entities/lookupfiles/v1"
            override = f"POST,{endpoint}"

            response = self.falcon.command(override=override, files=files, data=data)

            if response.get("status_code") not in (200, 201):
                raise RuntimeError(f"Failed to create lookup file '{filename}': {response}")

            return {
                "id": filename,
                "filename": filename,
                "search_domain": search_domain,
                "format": file_format,
                "size_bytes": len(file_content),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            raise RuntimeError(f"Failed to create lookup file: {e}") from e

    def apply_update(self, resource_id: str, env: "Envelope", current_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing lookup file in NGSIEM

        Args:
            resource_id: Current filename
            env: New lookup file Envelope
            current_state: Current state (for comparison)

        Returns:
            Updated lookup file metadata

        Raises:
            RuntimeError: If update fails
        """
        template = env.to_working_dict()
        try:
            # Read file content (relative source anchors to template's project root)
            source_path = self._resolve_source_path(template)

            with open(source_path, "rb") as f:
                file_content = f.read()

            # Determine content type
            file_format = template["format"].lower()
            content_type = "text/csv" if file_format == "csv" else "application/json"

            # Get search domain (prefer from current state if not in template)
            search_domain = template.get("_search_domain") or current_state.get("search_domain", "falcon")
            filename = template["name"]

            # Prepare multipart file upload
            files = [("file", (filename, file_content, content_type))]

            # API parameters as formData
            data = {"search_domain": search_domain, "filename": filename}

            endpoint = "/ngsiem-content/entities/lookupfiles/v1"
            override = f"PATCH,{endpoint}"

            response = self.falcon.command(override=override, files=files, data=data)

            if response.get("status_code") not in (200, 201):
                raise RuntimeError(f"Failed to update lookup file '{filename}': {response}")

            return {
                "id": filename,
                "filename": filename,
                "search_domain": search_domain,
                "format": file_format,
                "size_bytes": len(file_content),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            raise RuntimeError(f"Failed to update lookup file: {e}") from e

    def apply_delete(self, resource_id: str) -> Dict[str, Any]:
        """
        Delete a lookup file from NGSIEM

        Args:
            resource_id: Filename of lookup file to delete

        Returns:
            Dict with 'id' key on success

        Raises:
            RuntimeError: If deletion fails
        """
        try:
            # Try deleting from all search domains
            deleted = False
            last_error = None

            for search_domain in self.VALID_SEARCH_DOMAINS:
                try:
                    endpoint = "/ngsiem-content/entities/lookupfiles/v1"
                    override = f"DELETE,{endpoint}"

                    response = self.falcon.command(
                        override=override, parameters={"filename": resource_id, "search_domain": search_domain}
                    )

                    if response.get("status_code") in (200, 204):
                        deleted = True
                        logger.info(f"Deleted lookup file {resource_id} from {search_domain}")
                        break

                except Exception as e:
                    last_error = e
                    continue

            if not deleted:
                raise RuntimeError(
                    f"Failed to delete lookup file {resource_id} from any domain. Last error: {last_error}"
                )

            return {"id": resource_id}

        except Exception as e:
            raise RuntimeError(f"Failed to delete lookup file: {e}") from e

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        """
        Calculate deterministic hash of lookup file content

        Includes: file content + metadata (name, format, description)

        Args:
            template: Lookup file template

        Returns:
            SHA256 hash as hex string
        """
        # Resolve the source against the template's project root BEFORE stripping
        # internal fields — strip_for_hash drops `_template_path`, the anchor.
        source_path = self._resolve_source_path(template)
        # v0.3.0: strip universal IaC-only + internal + metadata fields first.
        template = strip_for_hash(template)

        try:
            with open(source_path, "rb") as f:
                file_content = f.read()
        except Exception as e:
            logger.warning(f"Failed to read file for hashing: {e}")
            file_content = b""

        # Hash file content
        content_hash = hashlib.sha256(file_content).hexdigest()

        # Include metadata in hash
        metadata = {
            "name": template.get("name", ""),
            "format": template.get("format", ""),
            "description": template.get("description", ""),
            "content_hash": content_hash,
        }

        metadata_str = json.dumps(metadata, sort_keys=True)
        return hashlib.sha256(metadata_str.encode()).hexdigest()

    def extract_dependencies(self, template: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extract resource dependencies from lookup file template

        Lookup files are typically leaf nodes (no dependencies on other resources).

        Args:
            template: Lookup file template

        Returns:
            Empty dict (lookup files don't depend on other resources)
        """
        return {}

    def _fetch_all_remote_lookup_files(self, search_domain: str = "all") -> Dict[str, Dict[str, Any]]:
        """
        Fetch all lookup files from a search domain.

        Uses the NGSIEM Content API endpoint: GET /ngsiem-content/queries/lookupfiles/v1
        to list lookup file names, then fetches metadata for each.

        Args:
            search_domain: Search domain to query (all, falcon, third-party, dashboards)

        Returns:
            Dictionary of lookup files indexed by filename
        """
        try:
            endpoint = "/ngsiem-content/queries/lookupfiles/v1"
            override = f"GET,{endpoint}"

            lookup_files = {}
            limit = 100
            offset = 0

            while True:
                response = self.falcon.command(
                    override=override, parameters={"search_domain": search_domain, "limit": limit, "offset": offset}
                )

                if response.get("status_code") != 200:
                    logger.warning(
                        f"Failed to list lookup files (offset {offset}): status {response.get('status_code')}"
                    )
                    break

                body = response.get("body", {})
                resources = body.get("resources", [])

                if not resources:
                    break

                for filename in resources:
                    try:
                        # Store basic metadata (content is not fetched for listing)
                        lookup_files[filename] = {
                            "filename": filename,
                            "name": filename,
                            "search_domain": search_domain,
                        }
                        logger.debug(f"Discovered lookup file: {filename}")
                    except Exception as e:
                        logger.debug(f"Failed to process lookup file {filename}: {e}")
                        continue

                # Check pagination
                meta = body.get("meta", {})
                pagination = meta.get("pagination", {})
                total = pagination.get("total", 0)

                offset += limit

                if offset >= total or len(resources) < limit:
                    break

            logger.info(f"Discovered {len(lookup_files)} lookup files in domain '{search_domain}'")
            return lookup_files

        except Exception as e:
            logger.error(f"Failed to fetch lookup files from {search_domain}: {e}")
            return {}

    def to_template(self, remote_resource: dict) -> dict:
        """
        Convert a remote lookup file into a YAML template dict.

        Note: Lookup file content is not downloaded during import. The template
        will reference a placeholder source path that the user must provide.

        Args:
            remote_resource: Lookup file dict from _fetch_all_remote_lookup_files()

        Returns:
            Template dict ready for YAML serialization
        """
        filename = remote_resource.get("filename", remote_resource.get("name", ""))
        resource_id = self._name_to_resource_id(filename) if filename else "unknown"

        # Determine format from filename extension
        file_format = "csv"
        if filename.endswith(".json"):
            file_format = "json"

        template = {
            "resource_id": resource_id,
            "name": filename,
            "format": file_format,
            "source": f"data/{filename}",  # Placeholder — user must provide actual file
            "_search_domain": remote_resource.get("search_domain", "all"),
        }

        description = remote_resource.get("description", "")
        if description:
            template["description"] = description

        return template

    def suggest_path(self, template: dict) -> str:
        """
        Suggest a file path for a lookup file template.

        Args:
            template: Template dict from to_template()

        Returns:
            Relative path like 'lookup_files/trusted_ips.yaml'
        """
        resource_id = template.get("resource_id", "")
        if not resource_id:
            resource_id = self._name_to_resource_id(template.get("name", "unknown"))

        return f"lookup_files/{resource_id}.yaml"

    # Convenience methods (aliases for apply_* methods)
    # WARNING: these forward to Envelope-taking apply_create/apply_update. They
    # have no current callers; if reused, pass an Envelope, not a dict (a dict
    # would AttributeError inside apply_* on .to_working_dict()). Reverse-alias
    # direction differs from other providers — consolidation deferred.
    def create_resource(self, env: "Envelope") -> Dict[str, Any]:
        """Alias for apply_create"""
        return self.apply_create(env)

    def update_resource(self, resource_id: str, env: "Envelope", current_state: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for apply_update"""
        return self.apply_update(resource_id, env, current_state)

    def delete_resource(self, resource_id: str) -> bool:
        """Alias for apply_delete"""
        return self.apply_delete(resource_id)
