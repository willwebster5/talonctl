# Case Management Resources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three new talonctl resource types — `case_notification_group`, `case_sla`, `case_template` — managed as v2 IaC, plus a shared `RefResolver` that substitutes a sibling resource's live API id into a payload at apply time.

**Architecture:** Each type is a `BaseResourceProvider` subclass mirroring the existing `dashboard_provider`/`saved_search_provider` pattern (validate → plan via content-hash → apply via FalconPy). Cross-references are authored as `*_ref` fields holding a sibling's stable `resource_id`; providers derive `depends_on` from them (so deploy order is automatic) and resolve them to API ids (`sla_id`, `notification_group_id`) only at apply time. Hashing uses the stable ref, never the resolved id, so redeploying a sibling never spuriously drifts a dependent.

**Tech Stack:** Python 3, Click, FalconPy 1.6.3 (`APIHarnessV2` uber client via `self.falcon.command(override="METHOD,/path", ...)`), pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-06-26-case-management-resource-design.md`

---

## Implementation notes (refinements discovered during planning)

These refine — not contradict — the spec:

1. **No separate `CaseManagement` client factory.** All 7 existing providers share the single `APIHarnessV2` `falcon_client` and call `self.falcon.command(override="POST,/casemgmt/...", body=...)`. The case providers follow that exact convention; the spec's `utils/case_management_client.py` is dropped in favor of the established pattern.
2. **`RefResolver` matches on `provider_metadata["resource_id"]`.** Providers stamp their stable `resource_id` into the dict returned from `apply_create`/`apply_update` (which the orchestrator persists as `provider_metadata`). The resolver scans `state_manager.get_all_resources(type)` and matches that field — robust regardless of the state key's display-name vs resource_id semantics.
3. **State is saved after each deployment wave** (`deployment_orchestrator.py:577-580`), so a wave-1 notification group is committed before a wave-2 SLA resolves it. Cross-wave resolution via committed state is sound.

## File structure

| File | Responsibility | Action |
|---|---|---|
| `src/talonctl/core/ref_resolver.py` | `RefResolver` + `UnresolvedRefError` (stable resource_id → live API id) | Create |
| `src/talonctl/providers/case_notification_group_provider.py` | `CaseNotificationGroupProvider` (no refs) | Create |
| `src/talonctl/providers/case_sla_provider.py` | `CaseSlaProvider` (refs notification groups) | Create |
| `src/talonctl/providers/case_template_provider.py` | `CaseTemplateProvider` (refs SLA, inline fields) | Create |
| `src/talonctl/providers/__init__.py` | Export the three providers | Modify |
| `src/talonctl/core/envelope.py` | Register 3 kinds in `KIND_TO_TYPE` | Modify |
| `src/talonctl/core/template_discovery.py` | Add 3 types to `VALID_RESOURCE_TYPES` + `TYPE_TO_DIR` | Modify |
| `src/talonctl/core/provider_adapter.py` | Instantiate + register 3 providers; build & inject `RefResolver` | Modify |
| `src/talonctl/commands/init.py` | Add 3 dirs to `RESOURCE_DIRS` | Modify |
| `examples/resources/case_notification_group.yaml`, `case_sla.yaml`, `case_template.yaml` | Annotated reference templates | Create |
| `tests/unit/test_ref_resolver.py` | RefResolver unit tests | Create |
| `tests/unit/test_case_notification_group_provider.py` | Provider unit tests | Create |
| `tests/unit/test_case_sla_provider.py` | Provider unit tests | Create |
| `tests/unit/test_case_template_provider.py` | Provider unit tests | Create |
| `tests/unit/test_case_management_integration.py` | 3-resource order + hash-stability | Create |

**Conventions (verified against existing code):**
- Provider methods receive `env: Envelope`; call `env.to_working_dict()` once at the top.
- FalconPy: `resp = self.falcon.command(override="POST,/casemgmt/entities/templates/v1", body={...})`; read `resp["status_code"]` and `resp["body"]["resources"]` / `resp["body"]["errors"]`.
- `strip_for_hash(working)` / `strip_for_api(working)` (from `core.template_sanitizer`) drop `resource_id`, `type`, `dependencies`, `metadata`, and `_`-prefixed keys. They KEEP `*_ref` fields (stable) and `name`/`description`/`fields`/`goals`/`channels`.
- Tests build envelopes with `make_envelope(flat_dict, resource_type)` from `tests/unit/_helpers.py`.

---

## Task 1: RefResolver (shared cross-ref utility)

**Files:**
- Create: `src/talonctl/core/ref_resolver.py`
- Test: `tests/unit/test_ref_resolver.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_ref_resolver.py
from types import SimpleNamespace

import pytest

from talonctl.core.ref_resolver import RefResolver, UnresolvedRefError


def _state(**kw):
    # Mimics ResourceState fields the resolver reads.
    return SimpleNamespace(id=kw["id"], provider_metadata=kw["provider_metadata"])


class _FakeStateManager:
    def __init__(self, by_type):
        self._by_type = by_type  # {resource_type: {qualified_key: state}}

    def get_all_resources(self, resource_type=None):
        return self._by_type.get(resource_type, {})


def test_resolve_matches_provider_metadata_resource_id():
    sm = _FakeStateManager(
        {
            "case_notification_group": {
                "case_notification_group.secops_email_oncall": _state(
                    id="api-ng-123",
                    provider_metadata={"resource_id": "secops_email_oncall", "id": "api-ng-123"},
                )
            }
        }
    )
    resolver = RefResolver(sm)
    assert resolver.resolve("case_notification_group", "secops_email_oncall") == "api-ng-123"


def test_resolve_raises_when_missing():
    resolver = RefResolver(_FakeStateManager({"case_sla": {}}))
    with pytest.raises(UnresolvedRefError) as exc:
        resolver.resolve("case_sla", "nonexistent")
    assert "case_sla" in str(exc.value)
    assert "nonexistent" in str(exc.value)


def test_resolve_does_not_cross_types():
    sm = _FakeStateManager(
        {
            "case_sla": {
                "case_sla.standard_sla": _state(
                    id="api-sla-1", provider_metadata={"resource_id": "standard_sla", "id": "api-sla-1"}
                )
            }
        }
    )
    resolver = RefResolver(sm)
    with pytest.raises(UnresolvedRefError):
        resolver.resolve("case_notification_group", "standard_sla")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_ref_resolver.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'talonctl.core.ref_resolver'`

- [ ] **Step 3: Write minimal implementation**

```python
# src/talonctl/core/ref_resolver.py
"""Resolve a sibling resource's stable resource_id to its live API id.

Case-management resources reference each other by API id in their payloads
(case_sla.goals[].escalation_policy.steps[].notification_group_id, and
case_template.sla_id). Authors write the sibling's stable resource_id in a
`*_ref` field; this resolver maps that to the deployed API id at apply time.

Matching is on provider_metadata["resource_id"] (which each case provider stamps
into its apply result), not the state dict key, so it is independent of the
display-name-vs-resource_id key semantics elsewhere in state.
"""

from __future__ import annotations

from typing import Any


class UnresolvedRefError(Exception):
    """Raised when a `*_ref` points at a resource not yet deployed / not in state."""


class RefResolver:
    def __init__(self, state_manager: Any):
        self._state_manager = state_manager

    def resolve(self, resource_type: str, resource_id: str) -> str:
        """Return the live API id of the deployed sibling identified by
        (resource_type, stable resource_id). Raise UnresolvedRefError if absent."""
        deployed = self._state_manager.get_all_resources(resource_type)
        for state in deployed.values():
            metadata = getattr(state, "provider_metadata", None) or {}
            if metadata.get("resource_id") == resource_id:
                return state.id
        raise UnresolvedRefError(
            f"Unresolved reference: no deployed {resource_type} with resource_id "
            f"'{resource_id}' found in state. Ensure it is applied first."
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_ref_resolver.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/talonctl/core/ref_resolver.py tests/unit/test_ref_resolver.py
git commit -m "feat(core): add RefResolver for cross-resource API-id resolution"
```

---

## Task 2: Register the three kinds, types, and directories

**Files:**
- Modify: `src/talonctl/core/envelope.py:18-26` (`KIND_TO_TYPE`)
- Modify: `src/talonctl/core/template_discovery.py:64-83` (`VALID_RESOURCE_TYPES`, `TYPE_TO_DIR`)
- Modify: `src/talonctl/commands/init.py:12-20` (`RESOURCE_DIRS`)
- Test: `tests/unit/test_case_registration.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_case_registration.py
from talonctl.commands.init import RESOURCE_DIRS
from talonctl.core.envelope import KIND_TO_TYPE, TYPE_TO_KIND
from talonctl.core.template_discovery import TemplateDiscovery


def test_kinds_registered():
    assert KIND_TO_TYPE["CaseNotificationGroup"] == "case_notification_group"
    assert KIND_TO_TYPE["CaseSla"] == "case_sla"
    assert KIND_TO_TYPE["CaseTemplate"] == "case_template"
    # inverse map stays in lockstep
    assert TYPE_TO_KIND["case_template"] == "CaseTemplate"


def test_discovery_types_and_dirs():
    for t in ("case_notification_group", "case_sla", "case_template"):
        assert t in TemplateDiscovery.VALID_RESOURCE_TYPES
    assert TemplateDiscovery.TYPE_TO_DIR["case_notification_group"] == "case_notification_groups"
    assert TemplateDiscovery.TYPE_TO_DIR["case_sla"] == "case_slas"
    assert TemplateDiscovery.TYPE_TO_DIR["case_template"] == "case_templates"


def test_init_scaffolds_dirs():
    for d in ("case_notification_groups", "case_slas", "case_templates"):
        assert d in RESOURCE_DIRS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_case_registration.py -v`
Expected: FAIL — `KeyError: 'CaseNotificationGroup'`

- [ ] **Step 3a: Add kinds to `KIND_TO_TYPE`**

In `src/talonctl/core/envelope.py`, extend the `KIND_TO_TYPE` dict (currently ending at `"RtrPutFile": "rtr_put_file",`):

```python
KIND_TO_TYPE: Dict[str, str] = {
    "Detection": "detection",
    "SavedSearch": "saved_search",
    "LookupFile": "lookup_file",
    "Workflow": "workflow",
    "Dashboard": "dashboard",
    "RtrScript": "rtr_script",
    "RtrPutFile": "rtr_put_file",
    "CaseNotificationGroup": "case_notification_group",
    "CaseSla": "case_sla",
    "CaseTemplate": "case_template",
}
```

(`TYPE_TO_KIND` and `VALID_KINDS` derive from this automatically — no other edit in this file.)

- [ ] **Step 3b: Add types + dirs to `TemplateDiscovery`**

In `src/talonctl/core/template_discovery.py`, extend both class attributes:

```python
    VALID_RESOURCE_TYPES = [
        "detection",
        "workflow",
        "saved_search",
        "lookup_file",
        "rtr_script",
        "rtr_put_file",
        "dashboard",
        "case_notification_group",
        "case_sla",
        "case_template",
    ]

    TYPE_TO_DIR = {
        "detection": "detections",
        "workflow": "workflows",
        "saved_search": "saved_searches",
        "lookup_file": "lookup_files",
        "rtr_script": "rtr_scripts",
        "rtr_put_file": "rtr_put_files",
        "dashboard": "dashboards",
        "case_notification_group": "case_notification_groups",
        "case_sla": "case_slas",
        "case_template": "case_templates",
    }
```

- [ ] **Step 3c: Add dirs to `init` scaffolding**

In `src/talonctl/commands/init.py`, extend `RESOURCE_DIRS`:

```python
RESOURCE_DIRS = [
    "detections",
    "saved_searches",
    "dashboards",
    "workflows",
    "lookup_files",
    "rtr_scripts",
    "rtr_put_files",
    "case_notification_groups",
    "case_slas",
    "case_templates",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_case_registration.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/talonctl/core/envelope.py src/talonctl/core/template_discovery.py src/talonctl/commands/init.py tests/unit/test_case_registration.py
git commit -m "feat: register case_notification_group/case_sla/case_template kinds, types, dirs"
```

---

## Task 3: CaseNotificationGroupProvider (no refs)

**Files:**
- Create: `src/talonctl/providers/case_notification_group_provider.py`
- Test: `tests/unit/test_case_notification_group_provider.py`

API endpoints (v2 notification groups):
- create: `POST /casemgmt/entities/notification-groups/v2`
- update: `PATCH /casemgmt/entities/notification-groups/v2`
- get: `GET /casemgmt/entities/notification-groups/v2?ids=`
- delete: `DELETE /casemgmt/entities/notification-groups/v2?ids=`
- query: `GET /casemgmt/queries/notification-groups/v2`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_case_notification_group_provider.py
import pytest
from unittest.mock import MagicMock

from talonctl.core.base_provider import ResourceAction
from talonctl.providers.case_notification_group_provider import CaseNotificationGroupProvider
from tests.unit._helpers import make_envelope


def _flat(**over):
    base = {
        "resource_id": "secops_email_oncall",
        "name": "SecOps On-Call (Email)",
        "description": "Primary escalation distro",
        "channels": [{"type": "email", "recipients": ["secops@example.com"], "severity": "high"}],
    }
    base.update(over)
    return base


@pytest.fixture
def provider():
    return CaseNotificationGroupProvider(MagicMock())


def _env(flat):
    return make_envelope(flat, "case_notification_group")


def test_type(provider):
    assert provider.get_resource_type() == "case_notification_group"


def test_validate_ok(provider):
    assert provider.validate_template(_env(_flat())) == []


def test_validate_missing_name(provider):
    flat = _flat()
    del flat["name"]
    errors = provider.validate_template(_env(flat))
    assert any("name" in e for e in errors)


def test_validate_bad_channel_type(provider):
    errors = provider.validate_template(_env(_flat(channels=[{"type": "carrier_pigeon"}])))
    assert any("channel" in e.lower() for e in errors)


def test_plan_create(provider):
    change = provider.plan_create(_env(_flat()), "/p.yaml")
    assert change.action == ResourceAction.CREATE
    assert change.resource_type == "case_notification_group"
    assert change.envelope is not None


def test_apply_create(provider):
    provider.falcon.command.return_value = {
        "status_code": 201,
        "body": {"resources": [{"id": "api-ng-123"}], "errors": []},
    }
    result = provider.apply_create(_env(_flat()))
    assert result["id"] == "api-ng-123"
    assert result["resource_id"] == "secops_email_oncall"  # stamped for RefResolver
    call = provider.falcon.command.call_args
    assert "POST" in call.kwargs["override"]
    assert call.kwargs["body"]["name"] == "SecOps On-Call (Email)"
    assert "resource_id" not in call.kwargs["body"]  # stripped before API


def test_apply_delete_idempotent(provider):
    provider.falcon.command.return_value = {"status_code": 200, "body": {"resources": [], "errors": []}}
    assert provider.apply_delete("api-ng-123")["id"] == "api-ng-123"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_case_notification_group_provider.py -v`
Expected: FAIL — `ModuleNotFoundError: ... case_notification_group_provider`

- [ ] **Step 3: Write the implementation**

```python
# src/talonctl/providers/case_notification_group_provider.py
"""Provider for CrowdStrike Case Management notification groups."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from talonctl.core.base_provider import BaseResourceProvider, ResourceAction, ResourceChange
from talonctl.core.template_sanitizer import strip_for_api, strip_for_hash

if TYPE_CHECKING:
    from talonctl.core.envelope import Envelope

_VALID_CHANNEL_TYPES = {"email", "slack", "webhook"}
_BASE = "/casemgmt/entities/notification-groups/v2"
_QUERY = "/casemgmt/queries/notification-groups/v2"


class CaseNotificationGroupProvider(BaseResourceProvider):
    def get_resource_type(self) -> str:
        return "case_notification_group"

    def validate_template(self, env: "Envelope") -> List[str]:
        t = env.to_working_dict()
        errors: List[str] = []
        if not t.get("name"):
            errors.append("case_notification_group: 'name' is required")
        if not t.get("resource_id"):
            errors.append("case_notification_group: 'resource_id' is required")
        channels = t.get("channels")
        if not channels or not isinstance(channels, list):
            errors.append("case_notification_group: 'channels' must be a non-empty list")
        else:
            for i, ch in enumerate(channels):
                ctype = ch.get("type")
                if ctype not in _VALID_CHANNEL_TYPES:
                    errors.append(
                        f"case_notification_group: channels[{i}].type '{ctype}' invalid "
                        f"(expected one of {sorted(_VALID_CHANNEL_TYPES)})"
                    )
        return errors

    def compute_content_hash(self, template: Dict[str, Any]) -> str:
        content = json.dumps(strip_for_hash(template), sort_keys=True, default=str)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _build_body(self, template: Dict[str, Any]) -> Dict[str, Any]:
        return strip_for_api(template)

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
            resource_type="case_notification_group",
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
                resource_type="case_notification_group",
                resource_id=current_state.get("id"),
                resource_name=t.get("name", ""),
                envelope=env,
            )
        return ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type="case_notification_group",
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
            resource_type="case_notification_group",
            resource_id=resource_id,
            resource_name=resource_name,
        )

    def apply_create(self, env: "Envelope") -> Dict[str, Any]:
        t = env.to_working_dict()
        body = self._build_body(t)
        resp = self.falcon.command(override=f"POST,{_BASE}", body=body)
        return self._result_from_response(resp, t["resource_id"])

    def apply_update(self, resource_id: str, env: "Envelope", current_state: Dict[str, Any]) -> Dict[str, Any]:
        t = env.to_working_dict()
        body = self._build_body(t)
        body["id"] = resource_id
        resp = self.falcon.command(override=f"PATCH,{_BASE}", body=body)
        return self._result_from_response(resp, t["resource_id"], fallback_id=resource_id)

    def apply_delete(self, resource_id: str) -> Optional[Dict[str, Any]]:
        self.falcon.command(override=f"DELETE,{_BASE}", parameters={"ids": [resource_id]})
        return {"id": resource_id}

    def _result_from_response(
        self, resp: Dict[str, Any], resource_id: str, fallback_id: Optional[str] = None
    ) -> Dict[str, Any]:
        body = resp.get("body") or {}
        errors = body.get("errors") or []
        if errors:
            raise RuntimeError(f"Case notification group API error: {errors}")
        resources = body.get("resources") or []
        api_id = (resources[0].get("id") if resources else None) or fallback_id
        if not api_id:
            raise RuntimeError("Case notification group API returned no id")
        result = dict(resources[0]) if resources else {}
        result["id"] = api_id
        result["resource_id"] = resource_id  # stamped for RefResolver matching
        return result

    def to_template(self, remote_resource: dict) -> dict:
        data = dict(remote_resource)
        name = data.get("name", "")
        return {
            "resource_id": self._name_to_resource_id(name),
            "name": name,
            "type": "case_notification_group",
            "description": data.get("description", ""),
            "channels": data.get("channels", []),
        }

    def suggest_path(self, template: dict) -> str:
        return f"resources/case_notification_groups/{template.get('resource_id', 'unknown')}.yaml"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_case_notification_group_provider.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add src/talonctl/providers/case_notification_group_provider.py tests/unit/test_case_notification_group_provider.py
git commit -m "feat(providers): add CaseNotificationGroupProvider"
```

---

## Task 4: Wire providers into the adapter + inject RefResolver

**Files:**
- Modify: `src/talonctl/providers/__init__.py`
- Modify: `src/talonctl/core/provider_adapter.py` (imports ~51-59; instantiation ~62-66; registry ~75-83)
- Test: `tests/unit/test_case_provider_adapter.py`

> NOTE: Tasks 5 and 6 add `CaseSlaProvider` and `CaseTemplateProvider`. This task imports all three so the wiring is done once. Implement Task 4's import lines for all three, but the two not-yet-created modules will be created in Tasks 5-6. To keep each task green, do the `__init__.py` + adapter edits for `CaseNotificationGroupProvider` now, and add the SLA/template lines in their own tasks. The test below only asserts the notification-group registration plus that a `RefResolver` is attached.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_case_provider_adapter.py
from pathlib import Path
from unittest.mock import MagicMock

from talonctl.core.provider_adapter import ProviderAdapter
from talonctl.core.ref_resolver import RefResolver


def _adapter(tmp_path: Path) -> ProviderAdapter:
    return ProviderAdapter(MagicMock(), state_file_path=tmp_path / "state.json", auto_save=False)


def test_notification_group_registered(tmp_path):
    adapter = _adapter(tmp_path)
    assert "case_notification_group" in adapter.providers
    assert adapter.providers["case_notification_group"].get_resource_type() == "case_notification_group"


def test_ref_resolver_attached_to_case_providers(tmp_path):
    adapter = _adapter(tmp_path)
    provider = adapter.providers["case_notification_group"]
    assert isinstance(getattr(provider, "ref_resolver", None), RefResolver)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_case_provider_adapter.py -v`
Expected: FAIL — `KeyError: 'case_notification_group'`

- [ ] **Step 3a: Export from `providers/__init__.py`**

Add the import + `__all__` entries (add SLA/template imports here too — they exist by the time the full suite runs, but if running this task in isolation before Tasks 5-6, add only `CaseNotificationGroupProvider` and append the other two in Tasks 5-6):

```python
from .case_notification_group_provider import CaseNotificationGroupProvider
from .case_sla_provider import CaseSlaProvider
from .case_template_provider import CaseTemplateProvider
```

```python
__all__ = [
    "DetectionProvider",
    "WorkflowProvider",
    "SavedSearchProvider",
    "LookupFileProvider",
    "RTRScriptProvider",
    "RTRPutFileProvider",
    "DashboardProvider",
    "CaseNotificationGroupProvider",
    "CaseSlaProvider",
    "CaseTemplateProvider",
]
```

- [ ] **Step 3b: Add a `ref_resolver` setter to `BaseResourceProvider`**

In `src/talonctl/core/base_provider.py`, add to `__init__` (after `self.config = config or {}`):

```python
        self.ref_resolver = None  # set by ProviderAdapter for case-management providers
```

- [ ] **Step 3c: Instantiate + register in `provider_adapter.py`**

After the existing provider instantiations and BEFORE the `self.providers = {...}` dict, add:

```python
        from talonctl.providers import (
            CaseNotificationGroupProvider,
            CaseSlaProvider,
            CaseTemplateProvider,
        )
        from talonctl.core.ref_resolver import RefResolver

        ref_resolver = RefResolver(self.state_manager)
        self.case_notification_group_provider = CaseNotificationGroupProvider(falcon_client)
        self.case_sla_provider = CaseSlaProvider(falcon_client)
        self.case_template_provider = CaseTemplateProvider(falcon_client)
        for _p in (
            self.case_notification_group_provider,
            self.case_sla_provider,
            self.case_template_provider,
        ):
            _p.ref_resolver = ref_resolver
```

Then add the three entries to the `self.providers` dict:

```python
            "case_notification_group": self.case_notification_group_provider,
            "case_sla": self.case_sla_provider,
            "case_template": self.case_template_provider,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_case_provider_adapter.py -v`
Expected: PASS (2 passed)

(If Tasks 5-6 are not yet done, temporarily comment the SLA/template imports + instantiations to keep this green, then uncomment in those tasks. Prefer doing Tasks 5-6 immediately after.)

- [ ] **Step 5: Commit**

```bash
git add src/talonctl/providers/__init__.py src/talonctl/core/provider_adapter.py src/talonctl/core/base_provider.py tests/unit/test_case_provider_adapter.py
git commit -m "feat(core): register case providers in adapter and inject RefResolver"
```

---

## Task 5: CaseSlaProvider (refs notification groups)

**Files:**
- Create: `src/talonctl/providers/case_sla_provider.py`
- Test: `tests/unit/test_case_sla_provider.py`

API endpoints: create `POST /casemgmt/entities/slas/v1`, update `PATCH /casemgmt/entities/slas/v1`, get `GET /casemgmt/entities/slas/v1?ids=`, delete `DELETE /casemgmt/entities/slas/v1?ids=`, query `GET /casemgmt/queries/slas/v1`.

The SLA references notification groups inside `goals[].escalation_policy.steps[].notification_group_ref`. `extract_dependencies` derives `case_notification_group.<ref>` deps; `apply_*` replaces each `notification_group_ref` with the resolved `notification_group_id`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_case_sla_provider.py
import pytest
from unittest.mock import MagicMock

from talonctl.core.base_provider import ResourceAction
from talonctl.core.ref_resolver import RefResolver, UnresolvedRefError
from talonctl.providers.case_sla_provider import CaseSlaProvider
from tests.unit._helpers import make_envelope


def _flat(**over):
    base = {
        "resource_id": "standard_sla",
        "name": "Standard Response SLA",
        "description": "24h resolution",
        "goals": [
            {
                "type": "time_to_resolution",
                "duration_seconds": 86400,
                "escalation_policy": {
                    "steps": [{"escalate_after_seconds": 3600, "notification_group_ref": "secops_email_oncall"}]
                },
            }
        ],
    }
    base.update(over)
    return base


def _env(flat):
    return make_envelope(flat, "case_sla")


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve(self, resource_type, resource_id):
        try:
            return self._m[(resource_type, resource_id)]
        except KeyError:
            raise UnresolvedRefError(f"{resource_type} {resource_id}")


@pytest.fixture
def provider():
    p = CaseSlaProvider(MagicMock())
    p.ref_resolver = _Resolver({("case_notification_group", "secops_email_oncall"): "api-ng-123"})
    return p


def test_type(provider):
    assert provider.get_resource_type() == "case_sla"


def test_validate_ok(provider):
    assert provider.validate_template(_env(_flat())) == []


def test_validate_missing_goals(provider):
    flat = _flat()
    del flat["goals"]
    assert any("goals" in e for e in provider.validate_template(_env(flat)))


def test_extract_dependencies(provider):
    deps = provider.extract_dependencies(_env(_flat()).to_working_dict())
    assert "case_notification_group.secops_email_oncall" in deps


def test_apply_create_resolves_ref(provider):
    provider.falcon.command.return_value = {
        "status_code": 201,
        "body": {"resources": [{"id": "api-sla-1"}], "errors": []},
    }
    result = provider.apply_create(_env(_flat()))
    assert result["id"] == "api-sla-1"
    assert result["resource_id"] == "standard_sla"
    body = provider.falcon.command.call_args.kwargs["body"]
    step = body["goals"][0]["escalation_policy"]["steps"][0]
    assert step["notification_group_id"] == "api-ng-123"
    assert "notification_group_ref" not in step


def test_apply_create_unresolved_ref_raises(provider):
    provider.ref_resolver = _Resolver({})
    with pytest.raises(UnresolvedRefError):
        provider.apply_create(_env(_flat()))


def test_hash_stable_regardless_of_resolved_id(provider):
    # The ref (resource_id) is hashed, not the resolved api id.
    h1 = provider.compute_content_hash(_env(_flat()).to_working_dict())
    provider.ref_resolver = _Resolver({("case_notification_group", "secops_email_oncall"): "DIFFERENT-API-ID"})
    h2 = provider.compute_content_hash(_env(_flat()).to_working_dict())
    assert h1 == h2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_case_sla_provider.py -v`
Expected: FAIL — `ModuleNotFoundError: ... case_sla_provider`

- [ ] **Step 3: Write the implementation**

```python
# src/talonctl/providers/case_sla_provider.py
"""Provider for CrowdStrike Case Management SLAs."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from talonctl.core.base_provider import BaseResourceProvider, ResourceAction, ResourceChange
from talonctl.core.template_sanitizer import strip_for_api, strip_for_hash

if TYPE_CHECKING:
    from talonctl.core.envelope import Envelope

_BASE = "/casemgmt/entities/slas/v1"


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
        self.falcon.command(override=f"DELETE,{_BASE}", parameters={"ids": [resource_id]})
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

    def to_template(self, remote_resource: dict) -> dict:
        data = dict(remote_resource)
        name = data.get("name", "")
        return {
            "resource_id": self._name_to_resource_id(name),
            "name": name,
            "type": "case_sla",
            "description": data.get("description", ""),
            "goals": data.get("goals", []),
        }

    def suggest_path(self, template: dict) -> str:
        return f"resources/case_slas/{template.get('resource_id', 'unknown')}.yaml"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_case_sla_provider.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Ensure adapter import (Task 4) is uncommented; run adapter test**

Run: `pytest tests/unit/test_case_provider_adapter.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/talonctl/providers/case_sla_provider.py tests/unit/test_case_sla_provider.py
git commit -m "feat(providers): add CaseSlaProvider with notification-group ref resolution"
```

---

## Task 6: CaseTemplateProvider (refs SLA, inline fields)

**Files:**
- Create: `src/talonctl/providers/case_template_provider.py`
- Test: `tests/unit/test_case_template_provider.py`

API endpoints: create `POST /casemgmt/entities/templates/v1`, update `PATCH /casemgmt/entities/templates/v1`, get `GET /casemgmt/entities/templates/v1?ids=`, delete `DELETE /casemgmt/entities/templates/v1?ids=`, query `GET /casemgmt/queries/templates/v1`.

The template references one SLA via `sla_ref` → `sla_id`. Inline `fields[]` are authored by name; valid `data_type` and `input_type` are enum-checked.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_case_template_provider.py
import pytest
from unittest.mock import MagicMock

from talonctl.core.base_provider import ResourceAction
from talonctl.core.ref_resolver import UnresolvedRefError
from talonctl.providers.case_template_provider import CaseTemplateProvider
from tests.unit._helpers import make_envelope


def _flat(**over):
    base = {
        "resource_id": "phishing_investigation",
        "name": "Phishing Investigation",
        "description": "Standard intake",
        "sla_ref": "standard_sla",
        "fields": [
            {"name": "Reported By", "data_type": "string", "input_type": "text", "required": True, "multivalued": False}
        ],
    }
    base.update(over)
    return base


def _env(flat):
    return make_envelope(flat, "case_template")


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve(self, resource_type, resource_id):
        try:
            return self._m[(resource_type, resource_id)]
        except KeyError:
            raise UnresolvedRefError(f"{resource_type} {resource_id}")


@pytest.fixture
def provider():
    p = CaseTemplateProvider(MagicMock())
    p.ref_resolver = _Resolver({("case_sla", "standard_sla"): "api-sla-1"})
    return p


def test_type(provider):
    assert provider.get_resource_type() == "case_template"


def test_validate_ok(provider):
    assert provider.validate_template(_env(_flat())) == []


def test_validate_bad_field_input_type(provider):
    flat = _flat(fields=[{"name": "X", "data_type": "string", "input_type": "telepathy"}])
    assert any("input_type" in e for e in provider.validate_template(_env(flat)))


def test_extract_dependencies(provider):
    deps = provider.extract_dependencies(_env(_flat()).to_working_dict())
    assert deps == ["case_sla.standard_sla"]


def test_plan_create(provider):
    change = provider.plan_create(_env(_flat()), "/p.yaml")
    assert change.action == ResourceAction.CREATE
    assert change.resource_type == "case_template"


def test_apply_create_resolves_sla(provider):
    provider.falcon.command.return_value = {
        "status_code": 201,
        "body": {"resources": [{"id": "api-tmpl-1"}], "errors": []},
    }
    result = provider.apply_create(_env(_flat()))
    assert result["id"] == "api-tmpl-1"
    assert result["resource_id"] == "phishing_investigation"
    body = provider.falcon.command.call_args.kwargs["body"]
    assert body["sla_id"] == "api-sla-1"
    assert "sla_ref" not in body


def test_apply_create_unresolved_sla_raises(provider):
    provider.ref_resolver = _Resolver({})
    with pytest.raises(UnresolvedRefError):
        provider.apply_create(_env(_flat()))


def test_hash_excludes_resolved_id(provider):
    h1 = provider.compute_content_hash(_env(_flat()).to_working_dict())
    provider.ref_resolver = _Resolver({("case_sla", "standard_sla"): "DIFFERENT"})
    h2 = provider.compute_content_hash(_env(_flat()).to_working_dict())
    assert h1 == h2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_case_template_provider.py -v`
Expected: FAIL — `ModuleNotFoundError: ... case_template_provider`

- [ ] **Step 3: Write the implementation**

```python
# src/talonctl/providers/case_template_provider.py
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
        for i, f in enumerate(t.get("fields", []) or []):
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
        if self.compute_content_hash(t) == current_state.get("content_hash", ""):
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
        self.falcon.command(override=f"DELETE,{_BASE}", parameters={"ids": [resource_id]})
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
        result["resource_id"] = resource_id
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
        # Reverse-map sla_id -> sla_ref is left to import post-processing (sibling state lookup).
        if data.get("sla_id"):
            template["sla_id"] = data["sla_id"]
        return template

    def suggest_path(self, template: dict) -> str:
        return f"resources/case_templates/{template.get('resource_id', 'unknown')}.yaml"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_case_template_provider.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add src/talonctl/providers/case_template_provider.py tests/unit/test_case_template_provider.py
git commit -m "feat(providers): add CaseTemplateProvider with SLA ref resolution"
```

---

## Task 7: Reference templates + init scaffolding

**Files:**
- Create: `examples/resources/case_notification_group.yaml`
- Create: `examples/resources/case_sla.yaml`
- Create: `examples/resources/case_template.yaml`
- Test: `tests/unit/test_case_examples_valid.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_case_examples_valid.py
from pathlib import Path
from unittest.mock import MagicMock

from talonctl.core.envelope_loader import load_envelopes
from talonctl.providers.case_notification_group_provider import CaseNotificationGroupProvider
from talonctl.providers.case_sla_provider import CaseSlaProvider
from talonctl.providers.case_template_provider import CaseTemplateProvider

EXAMPLES = Path("examples/resources")


def _only_env(path):
    envs = load_envelopes(path)
    assert len(envs) == 1
    return envs[0]


def test_notification_group_example_valid():
    env = _only_env(EXAMPLES / "case_notification_group.yaml")
    assert CaseNotificationGroupProvider(MagicMock()).validate_template(env) == []


def test_sla_example_valid():
    env = _only_env(EXAMPLES / "case_sla.yaml")
    assert CaseSlaProvider(MagicMock()).validate_template(env) == []


def test_template_example_valid():
    env = _only_env(EXAMPLES / "case_template.yaml")
    assert CaseTemplateProvider(MagicMock()).validate_template(env) == []
```

> NOTE: `load_envelopes` signature — confirm whether it takes a file path or directory. If it loads a directory, point the test at a temp dir containing one file, or use the project's existing single-file loader helper used by other example tests (grep `tests/` for how `examples/resources/*.yaml` are loaded in existing tests and mirror it).

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_case_examples_valid.py -v`
Expected: FAIL — file not found

- [ ] **Step 3: Create the example files**

`examples/resources/case_notification_group.yaml`:
```yaml
# Case Management — Notification Group (reference template)
# Escalation recipients referenced by case SLAs.
apiVersion: talon/v2
kind: CaseNotificationGroup
metadata:
  resource_id: secops_email_oncall      # stable state key — never change after deploy
  name: SecOps On-Call (Email)
spec:
  description: Primary escalation distro for SecOps cases
  channels:
    - type: email                        # one of: email, slack, webhook
      recipients: [secops-oncall@example.com]
      severity: high
```

`examples/resources/case_sla.yaml`:
```yaml
# Case Management — SLA (reference template)
# References a notification group by resource_id via notification_group_ref.
apiVersion: talon/v2
kind: CaseSla
metadata:
  resource_id: standard_sla
  name: Standard Response SLA
spec:
  description: Default time-to-resolution targets
  goals:
    - type: time_to_resolution
      duration_seconds: 86400            # 24h
      escalation_policy:
        steps:
          - escalate_after_seconds: 3600
            notification_group_ref: secops_email_oncall   # -> notification_group_id at apply
```

`examples/resources/case_template.yaml`:
```yaml
# Case Management — Case Template (reference template)
# References an SLA by resource_id via sla_ref. Custom fields are authored inline.
apiVersion: talon/v2
kind: CaseTemplate
metadata:
  resource_id: phishing_investigation
  name: Phishing Investigation
spec:
  sla_ref: standard_sla                  # -> sla_id at apply
  description: Standard intake for reported phishing
  fields:
    - name: Reported By
      data_type: string                  # one of: string, number, boolean, datetime
      input_type: text                   # one of: text, textarea, select, multiselect, checkbox, date
      required: true
      multivalued: false
    - name: Phishing Category
      data_type: string
      input_type: select
      multivalued: false
      required: false
      options:
        - value: Credential Harvesting
        - value: Malware Delivery
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_case_examples_valid.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add examples/resources/case_notification_group.yaml examples/resources/case_sla.yaml examples/resources/case_template.yaml tests/unit/test_case_examples_valid.py
git commit -m "docs(examples): add case management reference templates"
```

---

## Task 8: Integration — deploy order + hash stability + full suite

**Files:**
- Test: `tests/unit/test_case_management_integration.py`

- [ ] **Step 1: Write the test**

```python
# tests/unit/test_case_management_integration.py
"""End-to-end-ish wiring: dependency order is derived correctly and a sibling's
API-id change never drifts a dependent (hash uses the stable ref)."""
from unittest.mock import MagicMock

from talonctl.providers.case_sla_provider import CaseSlaProvider
from talonctl.providers.case_template_provider import CaseTemplateProvider
from tests.unit._helpers import make_envelope


def test_dependency_chain_order():
    sla = CaseSlaProvider(MagicMock())
    tmpl = CaseTemplateProvider(MagicMock())

    sla_flat = {
        "resource_id": "standard_sla",
        "name": "Standard SLA",
        "goals": [
            {
                "type": "time_to_resolution",
                "duration_seconds": 86400,
                "escalation_policy": {"steps": [{"escalate_after_seconds": 3600, "notification_group_ref": "ng_a"}]},
            }
        ],
    }
    tmpl_flat = {
        "resource_id": "phishing",
        "name": "Phishing",
        "sla_ref": "standard_sla",
        "fields": [{"name": "F", "data_type": "string", "input_type": "text"}],
    }

    # SLA depends on the notification group; template depends on the SLA.
    assert sla.extract_dependencies(make_envelope(sla_flat, "case_sla").to_working_dict()) == [
        "case_notification_group.ng_a"
    ]
    assert tmpl.extract_dependencies(make_envelope(tmpl_flat, "case_template").to_working_dict()) == [
        "case_sla.standard_sla"
    ]


def test_template_hash_unaffected_by_sla_api_id_change():
    class _R:
        def __init__(self, v):
            self.v = v

        def resolve(self, *_):
            return self.v

    tmpl = CaseTemplateProvider(MagicMock())
    flat = {
        "resource_id": "phishing",
        "name": "Phishing",
        "sla_ref": "standard_sla",
        "fields": [{"name": "F", "data_type": "string", "input_type": "text"}],
    }
    working = make_envelope(flat, "case_template").to_working_dict()

    tmpl.ref_resolver = _R("api-1")
    h1 = tmpl.compute_content_hash(working)
    tmpl.ref_resolver = _R("api-2-different")
    h2 = tmpl.compute_content_hash(working)
    assert h1 == h2  # resolved id is not part of the hash
```

- [ ] **Step 2: Run the integration test**

Run: `pytest tests/unit/test_case_management_integration.py -v`
Expected: PASS (2 passed)

- [ ] **Step 3: Run the FULL suite**

Run: `pytest tests/ -q`
Expected: all green (baseline was 800 passed; expect ~800 + the new tests).
If any prior test enumerates resource types / kinds and now fails on count, update that test to include the three new types (search: `grep -rn "VALID_RESOURCE_TYPES\|KIND_TO_TYPE\|len(.*providers" tests/`).

- [ ] **Step 4: Lint**

Run: `ruff format src/talonctl tests && ruff check src/talonctl tests`
Expected: no errors (fix any reported).

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_case_management_integration.py
git commit -m "test: case management deploy-order + hash-stability integration"
```

---

## Post-implementation verification (manual, optional — requires live tenant write)

The body schemas came from FalconPy docstrings (tenant had zero entities). To confirm exact
field names before real use, in a throwaway check: create one of each entity via the CLI
against the US2 tenant, `talonctl import --plan`, then `talonctl destroy`. Reconcile any field
name discrepancies (e.g. `duration_seconds` vs `duration`) into the providers + examples. Track
under the spec's "Open questions."

## Self-review notes

- Spec coverage: all three types, `RefResolver`, derived `depends_on`, hash-on-ref rule, lifecycle
  methods, registration touchpoints, examples, and tests are each covered by a task.
- Deviation logged: no separate `CaseManagement` client (uses shared uber client) — recorded in
  "Implementation notes" and to be synced into the spec's component list.
- Type consistency: `RefResolver.resolve(resource_type, resource_id)`, `*_ref` fields, and
  `provider_metadata["resource_id"]` stamping are used identically across Tasks 1, 5, 6.
