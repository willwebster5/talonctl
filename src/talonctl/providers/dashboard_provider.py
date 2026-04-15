"""Dashboard resource provider for CrowdStrike NGSIEM IaC.

Manages LogScale dashboards via raw API endpoints (not in FalconPy SDK).
Follows SavedSearchProvider pattern:
- YAML template upload via multipart form
- PATCH returns NEW dashboard ID (must track in state)
- Widget UUIDs normalized in content hash to prevent false diffs after sync
"""

import copy
import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional

import yaml

from talonctl.core.base_provider import BaseResourceProvider, ResourceChange, ResourceAction

logger = logging.getLogger(__name__)

# IaC-only fields stripped before API calls and content hashing
IAC_ONLY_FIELDS = {"resource_id", "type", "description", "tags", "_search_domain", "dependencies"}

# Widget types that do NOT require a queryString
NON_QUERY_WIDGET_TYPES = {"note", "parameterPanel"}


class DashboardProvider(BaseResourceProvider):
    """Provider for LogScale dashboard resources.

    API endpoints (undocumented, raw override):
        GET    /ngsiem-content/queries/dashboards/v1             (list)
        GET    /ngsiem-content/entities/dashboards-template/v1   (fetch)
        POST   /ngsiem-content/entities/dashboards-template/v1   (create)
        PATCH  /ngsiem-content/entities/dashboards-template/v1   (update → new ID)
        DELETE /ngsiem-content/entities/dashboards/v1            (delete)
    """

    def __init__(self, falcon_client, config: Optional[Dict] = None):
        self.falcon = falcon_client
        self.config = config or {}
        self._remote_dashboards_cache = None

    def get_resource_type(self) -> str:
        return "dashboard"

    # ── Validation ──────────────────────────────────────────────

    def validate_template(self, template: Dict[str, Any]) -> List[str]:
        errors = []

        for field in ("resource_id", "name", "sections", "widgets"):
            if field not in template or not template[field]:
                errors.append(f"Required field '{field}' is missing or empty")

        if errors:
            return errors

        sections = template.get("sections", {})
        widgets = template.get("widgets", {})

        # Every widget ref in sections must exist in widgets
        for section_id, section in sections.items():
            for widget_id in section.get("widgetIds", []):
                if widget_id not in widgets:
                    errors.append(
                        f"Section '{section_id}' references widget '{widget_id}' which does not exist in widgets"
                    )

        # Query widgets must have a non-empty queryString
        for widget_id, widget in widgets.items():
            widget_type = widget.get("type", "")
            if widget_type in NON_QUERY_WIDGET_TYPES:
                continue
            if widget_type == "query" and not widget.get("queryString", "").strip():
                errors.append(f"Widget '{widget_id}' has type 'query' but empty or missing queryString")

        return errors

    # ── Content Hash ────────────────────────────────────────────

    @staticmethod
    def _normalize_for_hash(template: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize dashboard YAML for deterministic hashing.

        1. Strip IaC-only fields
        2. Re-key widgets by (section_order, position) to remove UUID sensitivity
        3. Update section widgetIds to match
        """
        data = copy.deepcopy(template)

        # Strip IaC-only fields
        for field in IAC_ONLY_FIELDS:
            data.pop(field, None)

        sections = data.get("sections", {})
        widgets = data.get("widgets", {})

        # Build ordered widget list: sort sections by order, then iterate widgetIds
        ordered_widget_ids = []
        for _section_id, section in sorted(sections.items(), key=lambda s: s[1].get("order", 0)):
            for wid in section.get("widgetIds", []):
                if wid not in ordered_widget_ids:
                    ordered_widget_ids.append(wid)

        # Include widgets not referenced by any section (append at end)
        for wid in widgets:
            if wid not in ordered_widget_ids:
                ordered_widget_ids.append(wid)

        # Re-key widgets as widget-0, widget-1, ...
        new_widgets = {}
        id_map = {}
        for i, old_id in enumerate(ordered_widget_ids):
            new_id = f"widget-{i}"
            id_map[old_id] = new_id
            if old_id in widgets:
                new_widgets[new_id] = widgets[old_id]

        data["widgets"] = new_widgets

        # Update section widgetIds
        for section in sections.values():
            section["widgetIds"] = [id_map.get(wid, wid) for wid in section.get("widgetIds", [])]

        return data

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        normalized = self._normalize_for_hash(template)
        content = json.dumps(normalized, sort_keys=True, default=str)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    # ── YAML Payload Preparation ────────────────────────────────

    @staticmethod
    def _prepare_yaml_payload(template: Dict[str, Any]) -> str:
        """Prepare dashboard YAML for API upload.

        Strips IaC-only fields, converts tags->labels, preserves everything else.
        """
        data = copy.deepcopy(template)

        # Convert tags -> labels
        tags = data.pop("tags", [])
        if tags:
            data["labels"] = tags

        # Strip IaC-only fields (except tags, already handled)
        for field in IAC_ONLY_FIELDS - {"tags"}:
            data.pop(field, None)

        return yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)

    # ── Single Dashboard Fetch ──────────────────────────────────

    def _fetch_dashboard_by_id(self, dashboard_id: str, search_domain: str = "falcon") -> Optional[Dict]:
        """Fetch a single dashboard by ID via raw API override."""
        try:
            response = self.falcon.command(
                override="GET,/ngsiem-content/entities/dashboards-template/v1",
                parameters={"ids": dashboard_id, "search_domain": search_domain},
            )
            status = response.get("status_code", 0)
            resources = response.get("body", {}).get("resources", [])

            if status == 200 and resources:
                return resources[0] if isinstance(resources[0], dict) else None

            if not resources:
                logger.debug(f"Dashboard {dashboard_id} not found")
                return None

            logger.warning(f"Unexpected response fetching dashboard {dashboard_id}: {status}")
            return None

        except Exception as e:
            logger.error(f"Error fetching dashboard {dashboard_id}: {e}")
            return None

    # ── Dependency Extraction ───────────────────────────────────

    # Patterns for extracting references from CQL queries
    _SAVED_SEARCH_RE = re.compile(r"\$(\w+)\(\)")
    _LOOKUP_FILE_RE = re.compile(r'match\(file="([^"]+)"')

    @classmethod
    def _filename_to_resource_id(cls, filename: str) -> str:
        """Convert a lookup filename to a resource_id.

        Example: 'cato-users.csv' -> 'cato_users'
        """
        name = filename.rsplit(".", 1)[0] if "." in filename else filename
        return name.replace("-", "_")

    def _scan_queries(self, template: Dict[str, Any]) -> List[str]:
        """Collect all CQL query strings from widgets and parameters."""
        queries = []
        for widget in template.get("widgets", {}).values():
            qs = widget.get("queryString", "")
            if qs:
                queries.append(qs)
        for param in template.get("parameters", {}).values():
            q = param.get("query", "")
            if q:
                queries.append(q)
        return queries

    def extract_dependencies(self, template: Dict[str, Any]) -> List[str]:
        deps = set()

        # Scan all queries for references
        for query in self._scan_queries(template):
            for match in self._SAVED_SEARCH_RE.finditer(query):
                deps.add(f"saved_search.{match.group(1)}")
            for match in self._LOOKUP_FILE_RE.finditer(query):
                rid = self._filename_to_resource_id(match.group(1))
                deps.add(f"lookup_file.{rid}")

        # Merge explicit dependencies
        for dep in template.get("dependencies", []):
            deps.add(dep)

        return sorted(deps)

    # ── Fetch All Remote Dashboards ─────────────────────────────

    def _fetch_all_remote_dashboards(self, search_domain: str = "falcon") -> Dict[str, Dict]:
        """Fetch all dashboards from LogScale, keyed by name. Cached after first call.

        IMPLEMENTATION NOTE: The list endpoint may return full objects OR just IDs
        (like saved searches). This implementation handles both: if items are strings
        (IDs), it fetches each individually via _fetch_dashboard_by_id(). Verify
        actual response shape against the live API and simplify if full objects are
        always returned.

        NOTE: Uses limit=500 without pagination. Acceptable for current dashboard
        count. Add offset/limit pagination loop (see SavedSearchProvider pattern)
        if dashboard count exceeds 500.
        """
        if self._remote_dashboards_cache is not None:
            return self._remote_dashboards_cache

        dashboards = {}
        try:
            response = self.falcon.command(
                override="GET,/ngsiem-content/queries/dashboards/v1",
                parameters={"search_domain": search_domain, "limit": 500},
            )

            status = response.get("status_code", 0)
            resources = response.get("body", {}).get("resources", [])

            if status == 200:
                for item in resources:
                    if isinstance(item, dict):
                        # List endpoint returns full objects
                        name = item.get("name", "")
                        if name:
                            dashboards[name] = item
                    elif isinstance(item, str):
                        # List endpoint returns IDs only — fetch individually
                        detail = self._fetch_dashboard_by_id(item, search_domain)
                        if detail:
                            name = detail.get("name", "")
                            if name:
                                dashboards[name] = detail
                logger.info(f"Fetched {len(dashboards)} dashboards from CrowdStrike")
            else:
                logger.warning(f"Failed to list dashboards: HTTP {status}")

        except Exception as e:
            logger.error(f"Error fetching dashboards: {e}")

        self._remote_dashboards_cache = dashboards
        return dashboards

    # ── Create ──────────────────────────────────────────────────

    def create_resource(self, template: Dict[str, Any]) -> Dict[str, Any]:
        yaml_content = self._prepare_yaml_payload(template)
        search_domain = template.get("_search_domain", "falcon")
        name = template.get("name", "")

        response = self.falcon.command(
            override="POST,/ngsiem-content/entities/dashboards-template/v1",
            files=[("yaml_template", ("dashboard.yaml", yaml_content.encode("utf-8"), "text/yaml"))],
            parameters={"search_domain": search_domain, "name": name},
        )

        status = response.get("status_code", 0)
        body = response.get("body", {})
        resources = body.get("resources", [])
        errors = body.get("errors", [])

        if status != 200 or not resources:
            error_msg = errors[0].get("message", "Unknown error") if errors else f"HTTP {status}"
            raise RuntimeError(f"Failed to create dashboard '{name}': {error_msg}")

        resource = resources[0]
        dashboard_id = resource.get("id", "")
        logger.info(f"Created dashboard '{name}' with ID {dashboard_id}")

        return {"id": dashboard_id, "dashboard_id": dashboard_id, "name": name}

    # ── Update ──────────────────────────────────────────────────

    def update_resource(
        self, resource_id: str, template: Dict[str, Any], current_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        yaml_content = self._prepare_yaml_payload(template)
        search_domain = template.get("_search_domain", "falcon")
        name = template.get("name", "")

        # Use the current dashboard_id for the PATCH
        dashboard_id = current_state.get("provider_metadata", {}).get("dashboard_id", resource_id)

        response = self.falcon.command(
            override="PATCH,/ngsiem-content/entities/dashboards-template/v1",
            files=[("yaml_template", ("dashboard.yaml", yaml_content.encode("utf-8"), "text/yaml"))],
            parameters={"search_domain": search_domain, "ids": dashboard_id},
        )

        status = response.get("status_code", 0)
        body = response.get("body", {})
        resources = body.get("resources", [])
        errors = body.get("errors", [])

        if status != 200 or not resources:
            error_msg = errors[0].get("message", "Unknown error") if errors else f"HTTP {status}"
            raise RuntimeError(f"Failed to update dashboard '{name}': {error_msg}")

        resource = resources[0]
        new_id = resource.get("id", dashboard_id)

        if new_id != dashboard_id:
            logger.info(f"Dashboard '{name}' ID changed: {dashboard_id} -> {new_id}")

        return {"id": new_id, "dashboard_id": new_id, "name": name}

    # ── Delete ──────────────────────────────────────────────────

    def delete_resource(self, resource_id: str, search_domain: str = "falcon") -> Optional[Dict[str, Any]]:
        response = self.falcon.command(
            override="DELETE,/ngsiem-content/entities/dashboards/v1",
            parameters={"ids": resource_id, "search_domain": search_domain},
        )

        status = response.get("status_code", 0)
        errors = response.get("body", {}).get("errors", [])

        if status != 200:
            error_msg = errors[0].get("message", "Unknown error") if errors else f"HTTP {status}"
            raise RuntimeError(f"Failed to delete dashboard '{resource_id}': {error_msg}")

        logger.info(f"Deleted dashboard {resource_id}")
        return {"id": resource_id}

    # ── Fetch Remote State ──────────────────────────────────────

    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        result = self._fetch_dashboard_by_id(resource_id)
        if result:
            return {
                "id": result.get("id", ""),
                "name": result.get("name", ""),
                "provider_metadata": {"dashboard_id": result.get("id", "")},
            }
        return None

    # ── Plan Methods ────────────────────────────────────────────

    def plan_create(self, template: Dict[str, Any], template_path: str) -> ResourceChange:
        return ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="dashboard",
            resource_id=template.get("resource_id", ""),
            resource_name=template.get("name", ""),
            new_value=template,
            template_path=template_path,
        )

    def plan_update(
        self, template: Dict[str, Any], current_state: Dict[str, Any], template_path: str
    ) -> ResourceChange:
        # Compare content hashes — if identical, no change needed
        new_hash = self.compute_content_hash(template)
        old_hash = current_state.get("content_hash", "")

        if new_hash == old_hash:
            return ResourceChange(
                action=ResourceAction.NO_CHANGE,
                resource_type="dashboard",
                resource_id=template.get("resource_id", ""),
                resource_name=template.get("name", ""),
                template_path=template_path,
            )

        return ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type="dashboard",
            resource_id=template.get("resource_id", ""),
            resource_name=template.get("name", ""),
            old_value=current_state,
            new_value=template,
            template_path=template_path,
        )

    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        return ResourceChange(
            action=ResourceAction.DELETE,
            resource_type="dashboard",
            resource_id=resource_id,
            resource_name=resource_name,
        )

    # ── Apply Aliases ───────────────────────────────────────────

    def apply_create(self, template: Dict[str, Any]) -> Dict[str, Any]:
        return self.create_resource(template)

    def apply_update(self, resource_id: str, template: Dict[str, Any], current_state: Dict[str, Any]) -> Dict[str, Any]:
        return self.update_resource(resource_id, template, current_state)

    def apply_delete(self, resource_id: str) -> Optional[Dict[str, Any]]:
        return self.delete_resource(resource_id)

    # ── Sync/Import ─────────────────────────────────────────────

    # Platform detection for suggest_path
    _PLATFORM_TAGS = {
        "crowdstrike": "crowdstrike",
        "aws": "aws",
        "microsoft": "cross-platform",
        "entraid": "cross-platform",
        "google": "cross-platform",
        "cato": "cross-platform",
    }

    # Fields to carry over from remote dashboard to IaC template
    _DASHBOARD_CONTENT_FIELDS = {
        "sections",
        "widgets",
        "parameters",
        "sharedTimeInterval",
        "updateFrequency",
        "timeSelector",
        "$schema",
        "labels",
    }

    def to_template(self, remote_resource: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a remote dashboard to a local IaC template."""
        data = copy.deepcopy(remote_resource)

        name = data.get("name", "")
        resource_id = self._name_to_resource_id(name)
        description = data.get("description", "")
        labels = data.get("labels", [])

        template = {
            "resource_id": resource_id,
            "name": name,
            "type": "dashboard",
            "description": description,
            "tags": labels,
            "_search_domain": "falcon",
        }

        # Explicitly carry over known dashboard content fields
        for field in self._DASHBOARD_CONTENT_FIELDS:
            if field in data and field != "labels":  # labels -> tags already handled
                template[field] = data[field]

        return template

    def suggest_path(self, template: Dict[str, Any]) -> str:
        """Suggest a file path for a dashboard template."""
        resource_id = template.get("resource_id", "unknown")
        tags = [t.lower() for t in template.get("tags", [])]

        # Infer platform from tags
        platform = "general"
        for tag in tags:
            tag_lower = tag.lower()
            if tag_lower in self._PLATFORM_TAGS:
                platform = self._PLATFORM_TAGS[tag_lower]
                break

        # Fallback: infer from resource_id prefix
        if platform == "general":
            rid_lower = resource_id.lower()
            for prefix, plat in self._PLATFORM_TAGS.items():
                if rid_lower.startswith(prefix):
                    platform = plat
                    break

        return f"resources/dashboards/{platform}/{resource_id}.yaml"
