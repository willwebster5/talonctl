"""Provider for CrowdStrike Case Management SLAs."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from talonctl.core.base_provider import BaseResourceProvider, ResourceAction, ResourceChange
from talonctl.core.template_sanitizer import strip_for_api, strip_for_hash

if TYPE_CHECKING:
    from talonctl.core.envelope import Envelope

logger = logging.getLogger(__name__)

_BASE = "/casemgmt/entities/slas/v1"
_QUERY = "/casemgmt/queries/slas/v1"
_NG_QUERY = "/casemgmt/queries/notification-groups/v2"
_NG_BASE = "/casemgmt/entities/notification-groups/v2"


class CaseSlaProvider(BaseResourceProvider):
    def get_resource_type(self) -> str:
        return "case_sla"

    def validate_template(self, env: "Envelope") -> List[str]:
        t = env.to_working_dict()
        errors: List[str] = []
        if not t.get("name"):
            errors.append("case_sla: 'name' is required")
        if not t.get("resource_id"):
            errors.append("case_sla: 'resource_id' is required")
        goals = t.get("goals")
        if not goals or not isinstance(goals, list):
            errors.append("case_sla: 'goals' must be a non-empty list")
        else:
            for i, g in enumerate(goals):
                if not isinstance(g.get("duration_seconds"), int):
                    errors.append(f"case_sla: goals[{i}].duration_seconds must be an integer")
        return errors

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        content = json.dumps(strip_for_hash(template), sort_keys=True, default=str)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def extract_dependencies(self, template: Dict[str, Any]) -> List[str]:
        deps = set()
        for g in template.get("goals", []) or []:
            for step in (g.get("escalation_policy") or {}).get("steps", []) or []:
                ref = step.get("notification_group_ref")
                if ref:
                    deps.add(f"case_notification_group.{ref}")
        for dep in template.get("dependencies", []) or []:
            deps.add(dep)
        return sorted(deps)

    def _build_body(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Strip IaC fields, then replace notification_group_ref -> notification_group_id."""
        body = copy.deepcopy(strip_for_api(template))
        for g in body.get("goals", []) or []:
            for step in (g.get("escalation_policy") or {}).get("steps", []) or []:
                ref = step.pop("notification_group_ref", None)
                if ref is not None:
                    step["notification_group_id"] = self.ref_resolver.resolve("case_notification_group", ref)
        return body

    def fetch_remote_state(self, resource_id: str) -> Optional[Dict[str, Any]]:
        resp = self.falcon.command(override=f"GET,{_BASE}", parameters={"ids": [resource_id]})
        resources = (resp.get("body") or {}).get("resources") or []
        if not resources:
            return None
        r = resources[0]
        return {"id": r.get("id", ""), "name": r.get("name", ""), "provider_metadata": r}

    def plan_create(self, env: "Envelope", template_path: str) -> ResourceChange:
        t = env.to_working_dict()
        return ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="case_sla",
            resource_id=t.get("resource_id", ""),
            resource_name=t.get("name", ""),
            new_value=t,
            template_path=template_path,
            envelope=env,
        )

    def plan_update(self, env: "Envelope", current_state: Dict[str, Any], template_path: str) -> ResourceChange:
        t = env.to_working_dict()
        if self.compute_content_hash(t) == current_state.get("content_hash", ""):
            return ResourceChange(
                action=ResourceAction.NO_CHANGE,
                resource_type="case_sla",
                resource_id=current_state.get("id"),
                resource_name=t.get("name", ""),
                envelope=env,
            )
        return ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type="case_sla",
            resource_id=current_state.get("id"),
            resource_name=t.get("name", ""),
            old_value=current_state,
            new_value=t,
            template_path=template_path,
            envelope=env,
        )

    def plan_delete(self, resource_id: str, resource_name: str) -> ResourceChange:
        return ResourceChange(
            action=ResourceAction.DELETE,
            resource_type="case_sla",
            resource_id=resource_id,
            resource_name=resource_name,
        )

    def apply_create(self, env: "Envelope") -> Dict[str, Any]:
        t = env.to_working_dict()
        resp = self.falcon.command(override=f"POST,{_BASE}", body=self._build_body(t))
        return self._result_from_response(resp, t["resource_id"])

    def apply_update(self, resource_id: str, env: "Envelope", current_state: Dict[str, Any]) -> Dict[str, Any]:
        t = env.to_working_dict()
        body = self._build_body(t)
        body["id"] = resource_id
        resp = self.falcon.command(override=f"PATCH,{_BASE}", body=body)
        return self._result_from_response(resp, t["resource_id"], fallback_id=resource_id)

    def apply_delete(self, resource_id: str) -> Optional[Dict[str, Any]]:
        resp = self.falcon.command(override=f"DELETE,{_BASE}", parameters={"ids": [resource_id]})
        status = resp.get("status_code", 0)
        errors = (resp.get("body") or {}).get("errors") or []
        if status != 200:
            msg = errors[0].get("message", "Unknown error") if errors else f"HTTP {status}"
            raise RuntimeError(f"Failed to delete case SLA '{resource_id}': {msg}")
        return {"id": resource_id}

    def _result_from_response(
        self, resp: Dict[str, Any], resource_id: str, fallback_id: Optional[str] = None
    ) -> Dict[str, Any]:
        body = resp.get("body") or {}
        errors = body.get("errors") or []
        if errors:
            raise RuntimeError(f"Case SLA API error: {errors}")
        resources = body.get("resources") or []
        api_id = (resources[0].get("id") if resources else None) or fallback_id
        if not api_id:
            raise RuntimeError("Case SLA API returned no id")
        result = dict(resources[0]) if resources else {}
        result["id"] = api_id
        result["resource_id"] = resource_id
        return result

    def _fetch_all_remote_slas(self) -> Dict[str, Dict[str, Any]]:
        """List + fetch all SLAs, keyed by display name (for import/sync)."""
        out: Dict[str, Dict[str, Any]] = {}
        offset = 0
        limit = 100
        while True:
            q = self.falcon.command(override=f"GET,{_QUERY}", parameters={"limit": limit, "offset": offset})
            ids = (q.get("body") or {}).get("resources") or []
            if not ids:
                break
            g = self.falcon.command(override=f"GET,{_BASE}", parameters={"ids": ids})
            for r in (g.get("body") or {}).get("resources") or []:
                name = r.get("name")
                if name:
                    out[name] = r
            if len(ids) < limit:
                break
            offset += limit
        return out

    def _notification_group_reverse_map(self) -> Dict[str, str]:
        """Map live notification-group api_id -> its stable resource_id, for import. Cached per instance."""
        if getattr(self, "_ng_reverse_cache", None) is not None:
            return self._ng_reverse_cache
        cache: Dict[str, str] = {}
        offset = 0
        limit = 100
        while True:
            q = self.falcon.command(override=f"GET,{_NG_QUERY}", parameters={"limit": limit, "offset": offset})
            ids = (q.get("body") or {}).get("resources") or []
            if not ids:
                break
            g = self.falcon.command(override=f"GET,{_NG_BASE}", parameters={"ids": ids})
            for r in (g.get("body") or {}).get("resources") or []:
                api_id, name = r.get("id"), r.get("name")
                if api_id and name:
                    cache[api_id] = self._name_to_resource_id(name)
            if len(ids) < limit:
                break
            offset += limit
        self._ng_reverse_cache = cache
        return cache

    def to_template(self, remote_resource: dict) -> dict:
        data = copy.deepcopy(remote_resource)
        name = data.get("name", "")
        ng_map = None
        goals = data.get("goals", [])
        for g in goals or []:
            for step in (g.get("escalation_policy") or {}).get("steps", []) or []:
                ng_id = step.pop("notification_group_id", None)
                if ng_id is None:
                    continue
                if ng_map is None:
                    ng_map = self._notification_group_reverse_map()
                ref = ng_map.get(ng_id)
                if ref:
                    step["notification_group_ref"] = ref
                else:
                    step["notification_group_id"] = ng_id  # unresolved; preserve
                    logger.warning(
                        "case_sla import: could not resolve notification_group_id=%r to a ref; preserving raw id", ng_id
                    )
        return {
            "resource_id": self._name_to_resource_id(name),
            "name": name,
            "type": "case_sla",
            "description": data.get("description", ""),
            "goals": goals,
        }

    def suggest_path(self, template: dict) -> str:
        return f"resources/case_slas/{template.get('resource_id', 'unknown')}.yaml"
