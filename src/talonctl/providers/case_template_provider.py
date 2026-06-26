"""Provider for CrowdStrike Case Management templates."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from talonctl.core.base_provider import BaseResourceProvider, ResourceAction, ResourceChange
from talonctl.core.template_sanitizer import strip_for_api, strip_for_hash

if TYPE_CHECKING:
    from talonctl.core.envelope import Envelope

_BASE = "/casemgmt/entities/templates/v1"
_VALID_DATA_TYPES = {"string", "number", "boolean", "datetime"}
_VALID_INPUT_TYPES = {"text", "textarea", "select", "multiselect", "checkbox", "date"}


class CaseTemplateProvider(BaseResourceProvider):
    def get_resource_type(self) -> str:
        return "case_template"

    def validate_template(self, env: "Envelope") -> List[str]:
        t = env.to_working_dict()
        errors: List[str] = []
        if not t.get("name"):
            errors.append("case_template: 'name' is required")
        if not t.get("resource_id"):
            errors.append("case_template: 'resource_id' is required")
        fields = t.get("fields")
        if not fields or not isinstance(fields, list):
            errors.append("case_template: 'fields' must be a non-empty list")
        else:
            for i, f in enumerate(fields):
                if not f.get("name"):
                    errors.append(f"case_template: fields[{i}].name is required")
                if f.get("data_type") not in _VALID_DATA_TYPES:
                    errors.append(
                        f"case_template: fields[{i}].data_type '{f.get('data_type')}' invalid "
                        f"(expected one of {sorted(_VALID_DATA_TYPES)})"
                    )
                if f.get("input_type") not in _VALID_INPUT_TYPES:
                    errors.append(
                        f"case_template: fields[{i}].input_type '{f.get('input_type')}' invalid "
                        f"(expected one of {sorted(_VALID_INPUT_TYPES)})"
                    )
        return errors

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        content = json.dumps(strip_for_hash(template), sort_keys=True, default=str)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def extract_dependencies(self, template: Dict[str, Any]) -> List[str]:
        deps = set()
        ref = template.get("sla_ref")
        if ref:
            deps.add(f"case_sla.{ref}")
        for dep in template.get("dependencies", []) or []:
            deps.add(dep)
        return sorted(deps)

    def _build_body(self, template: Dict[str, Any]) -> Dict[str, Any]:
        """Strip IaC fields, then replace sla_ref -> sla_id."""
        body = copy.deepcopy(strip_for_api(template))
        ref = body.pop("sla_ref", None)
        if ref is not None:
            body["sla_id"] = self.ref_resolver.resolve("case_sla", ref)
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
            resource_type="case_template",
            resource_id=t.get("resource_id", ""),
            resource_name=t.get("name", ""),
            new_value=t,
            template_path=template_path,
            envelope=env,
        )

    def plan_update(self, env: "Envelope", current_state: Dict[str, Any], template_path: str) -> ResourceChange:
        t = env.to_working_dict()
        new_hash = self.compute_content_hash(t)
        if new_hash == current_state.get("content_hash", ""):
            return ResourceChange(
                action=ResourceAction.NO_CHANGE,
                resource_type="case_template",
                resource_id=current_state.get("id"),
                resource_name=t.get("name", ""),
                envelope=env,
            )
        return ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type="case_template",
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
            resource_type="case_template",
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
            raise RuntimeError(f"Failed to delete case template '{resource_id}': {msg}")
        return {"id": resource_id}

    def _result_from_response(
        self, resp: Dict[str, Any], resource_id: str, fallback_id: Optional[str] = None
    ) -> Dict[str, Any]:
        body = resp.get("body") or {}
        errors = body.get("errors") or []
        if errors:
            raise RuntimeError(f"Case template API error: {errors}")
        resources = body.get("resources") or []
        api_id = (resources[0].get("id") if resources else None) or fallback_id
        if not api_id:
            raise RuntimeError("Case template API returned no id")
        result = dict(resources[0]) if resources else {}
        result["id"] = api_id
        result["resource_id"] = resource_id  # stamped for RefResolver matching
        return result

    def to_template(self, remote_resource: dict) -> dict:
        data = dict(remote_resource)
        name = data.get("name", "")
        template = {
            "resource_id": self._name_to_resource_id(name),
            "name": name,
            "type": "case_template",
            "description": data.get("description", ""),
            "fields": data.get("fields", []),
        }
        if data.get("sla_id"):
            template["sla_id"] = data["sla_id"]
        return template

    def suggest_path(self, template: dict) -> str:
        return f"resources/case_templates/{template.get('resource_id', 'unknown')}.yaml"
