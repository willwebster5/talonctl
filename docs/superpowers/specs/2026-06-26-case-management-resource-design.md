# Case Management Resources — Design (RFC)

**Date:** 2026-06-26
**Status:** Draft — pending implementation plan
**Branch:** `worktree-case-management-rfc`

## Summary

Add three new talonctl resource types for CrowdStrike Falcon **Case Management**, managed
as infrastructure-as-code through the existing terraform-like lifecycle (validate / plan /
apply / import / drift / destroy):

| Type ID | Kind (v2) | Directory | API entity | Depends on |
|---|---|---|---|---|
| `case_notification_group` | `CaseNotificationGroup` | `resources/case_notification_groups/` | notification group | — |
| `case_sla` | `CaseSla` | `resources/case_slas/` | SLA policy | notification groups |
| `case_template` | `CaseTemplate` | `resources/case_templates/` | case template | SLAs |

These are reusable **case templates** (predefined fields + SLA for opening investigations)
plus the two adjacent config entities a template depends on. Live cases (operational case
records) are explicitly **out of scope** — they are transient operational data, not config.

## Goals

- Author case templates, SLAs, and notification groups as version-controlled v2 YAML.
- Full lifecycle parity with the existing seven resource types (no special-casing in CLI
  commands — everything flows through the shared orchestrator/state/plan machinery).
- Cross-resource references authored by stable `resource_id`, never by raw API id.
- Correct deploy/destroy ordering derived automatically from references.

## Non-Goals

- Managing live case records, case activity, attachments, or evidence.
- Custom **fields** as a standalone managed resource type (fields are authored inline on a
  template's `spec.fields`). Access tags are also out of scope for this RFC.
- A new authoring format — these types are native **talon/v2** envelopes.

## Background: API surface (verified)

The CrowdStrike `CaseManagement` service class (FalconPy 1.6.3) exposes a complete REST
surface for all three entities. Endpoints confirmed against the live tenant (US2); the
tenant currently has **zero** templates / SLAs / notification groups, so no live body
sample was captured — body schemas below are taken from FalconPy's payload-helper
docstrings (`falconpy/_payload/_case_management.py`) and are marked **to confirm on first
real apply**.

### Templates
- `POST /casemgmt/entities/templates/v1` — create (JSON body)
- `PATCH /casemgmt/entities/templates/v1` — update (JSON body)
- `GET /casemgmt/entities/templates/v1?ids=` — get by id
- `DELETE /casemgmt/entities/templates/v1?ids=` — delete
- `GET /casemgmt/queries/templates/v1` — query (FQL filter/sort/paging)
- `GET /casemgmt/entities/templates/export/v1?ids=&format=yaml|json` — export
- `POST /casemgmt/entities/templates/import/v1` — import (file, `dry_run` flag)

### SLAs
- `create_sla` / `update_sla` / `delete_sla` / `get_slas` / `query_slas`

### Notification groups
- `create_notification_group_v2` / `update_notification_group_v2` /
  `delete_notification_group_v2` / `get_notification_groups_v2` /
  `query_notification_groups_v2` (prefer the **v2** variants over v1)

### Body schemas (from FalconPy payload helpers — to confirm)

Notification group:
```json
{
  "name": "string",
  "description": "string",
  "channels": [
    {"type": "email", "config_id": "string", "config_name": "string",
     "recipients": ["string"], "severity": "string"}
  ]
}
```

SLA — note `goals[].escalation_policy.steps[].notification_group_id` (→ depends on a
notification group):
```json
{
  "name": "string",
  "description": "string",
  "goals": [
    {"type": "string", "duration_seconds": 0,
     "escalation_policy": {"steps": [
        {"escalate_after_seconds": 0, "notification_group_id": "string"}]}}
  ]
}
```

Template — note `sla_id` (→ depends on an SLA) and inline `fields[]`:
```json
{
  "name": "string",
  "description": "string",
  "sla_id": "string",
  "fields": [
    {"name": "string", "data_type": "string", "input_type": "string",
     "default_value": "string", "multivalued": true, "required": true,
     "options": [{"id": "string", "value": "string"}]}
  ]
}
```

**Dependency chain:** `case_notification_group` → `case_sla` → `case_template`.

## Architecture

Approach: **native providers** — each type is a `BaseResourceProvider` exactly like the
existing seven, with the optional enhancement that `import` may seed from the native
`export` endpoint (Approach "A + optional C"). Rationale: keeps all three new types
behaving identically to existing resource types under plan/drift/sync/destroy, gives full
control over field-level diffs and `resource_id` stability, and avoids coupling drift
detection to CrowdStrike's export format (which we do not control). Native YAML import is
used only as a convenience for `import` scaffolding, not as the source of truth.

### Components

- **`utils/case_management_client.py`** — factory that builds a single `CaseManagement`
  FalconPy client from `~/.config/falcon/credentials.json` (`base_url` honored), mirroring
  `utils/ngsiem_client.py`. Shared by all three providers.
- **`providers/case_notification_group_provider.py`**
- **`providers/case_sla_provider.py`**
- **`providers/case_template_provider.py`**
- **`core/ref_resolver.py`** — shared, reusable cross-resource API-id resolver (see below).

### v2 integration

These are native `talon/v2` envelopes. Integration points in the v2 layer:

1. Register three kinds in `core/envelope.py` `KIND_TO_TYPE`:
   `CaseNotificationGroup → case_notification_group`, `CaseSla → case_sla`,
   `CaseTemplate → case_template`. The loader, validator, and discovery all key off this
   map.
2. Providers consume the flat `Envelope.to_working_dict()` form internally (unchanged
   provider pattern); authored files are envelopes.
3. `depends_on` is **derived**, not hand-authored — see Ref resolution.

### Ref resolution (new shared mechanism)

No existing provider substitutes a referenced resource's **API id** into a payload — every
current cross-ref (e.g. dashboard → lookup) is by name/content. Case templates are the
first type needing a real API id (`sla_id`, `notification_group_id`) resolved from a
sibling resource. This RFC adds one small, reusable mechanism:

```python
# core/ref_resolver.py
class UnresolvedRefError(Exception): ...

class RefResolver:
    def __init__(self, state_manager): ...
    def resolve(self, resource_type: str, resource_id: str) -> str:
        """resource_id of a deployed sibling -> its live API id (from state).
        Raises UnresolvedRefError if not deployed or not in state."""
```

- The orchestrator constructs one `RefResolver` over the live `StateManager` and passes it
  to providers at **apply** time only.
- Authors write only the `*_ref` field (the sibling's `resource_id`). The provider's
  `extract_dependencies` **derives** the `depends_on` edge from it (e.g.
  `case_sla.standard_sla`), exactly as `dashboard_provider` derives lookup deps. Authors
  never hand-write `depends_on` for these refs, so it cannot drift from the actual ref.
- **Hashing rule (critical):** `compute_content_hash` hashes the authored spec containing
  `*_ref` (a stable `resource_id`), **not** the resolved API id. API-id substitution
  happens after hashing, at the API boundary, in `apply_create`/`apply_update` only. If we
  hashed the resolved id, redeploying an SLA (new API id) would spuriously mark every
  referencing template as drifted.
- `*_ref` is a talonctl-only field: stripped before hashing-for-API and replaced by the
  resolved API id (`sla_id` / `notification_group_id`) in the outgoing body.

## Template schemas (authored v2 YAML)

```yaml
apiVersion: talon/v2
kind: CaseNotificationGroup
metadata:
  resource_id: secops_email_oncall          # stable state key — never change
  name: SecOps On-Call (Email)
spec:
  description: Primary escalation distro for SecOps cases
  channels:
    - type: email
      recipients: [secops-oncall@example.com]
      severity: high
      # config_id / config_name: optional connector ref for non-email channel types
---
apiVersion: talon/v2
kind: CaseSla
metadata:
  resource_id: standard_sla
  name: Standard Response SLA
spec:
  description: Default time-to-resolution targets
  goals:
    - type: time_to_resolution
      duration_seconds: 86400               # 24h
      escalation_policy:
        steps:
          - escalate_after_seconds: 3600
            notification_group_ref: secops_email_oncall   # -> notification_group_id
---
apiVersion: talon/v2
kind: CaseTemplate
metadata:
  resource_id: phishing_investigation
  name: Phishing Investigation
spec:
  sla_ref: standard_sla                                   # -> sla_id
  description: Standard intake for reported phishing
  fields:
    - {name: Reported By, data_type: string, input_type: text, required: true, multivalued: false}
    - name: Phishing Category
      data_type: string
      input_type: select
      multivalued: false
      required: false
      options:
        - {value: Credential Harvesting}
        - {value: Malware Delivery}
```

**Author-facing vs captured fields:**
- API-assigned ids (`id` on the template/group, `options[].id`, server-side field ids) are
  **never authored**. They are captured into `provider_metadata` on apply/import and merged
  back into the body on update so PATCH edits in place rather than recreating.
- `*_ref` fields are talonctl-only (resolved at apply, stripped from the hashed-for-API
  body).
- Everything else in `spec` passes through to the API body.

## Lifecycle behavior

| Phase | Behavior |
|---|---|
| `validate` | required fields; enum checks (`channel.type`, `goal.type`, field `data_type`/`input_type`); every `*_ref` resolves to a declared sibling `resource_id` of the correct kind |
| `plan` | content-hash diff of the authored spec (refs by `resource_id`) → create / update / no-change |
| `apply` | resolve `*_ref` → API id via `RefResolver`; build body; `create_*` (or PATCH on update); capture API `id` + server-assigned field/option ids into `provider_metadata` |
| `import` | `query_*` + `get_*` → `to_template()`; optionally seed from `export` YAML when cleaner; reverse-map API ids back to `*_ref` by matching sibling state |
| `drift` | compare live `get_*` against last-applied content hash (shared machinery) |
| `destroy` | `delete_*` by id in reverse dependency order (templates → SLAs → notification groups) |

### State & dependency ordering

- Standard `ResourceState` entries; `provider_metadata` holds the API `id` plus captured
  `field_ids` / `option_ids` for in-place PATCH updates.
- `extract_dependencies` derives the graph from `*_ref` fields. Deploy order: notification
  groups → SLAs → templates; destroy reverses. The existing orchestrator `resource_graph`
  handles ordering — no new ordering code.
- **ID-change on update:** the create/patch endpoints are expected to update in place (no
  new id, unlike saved-search PATCH). **To confirm on first real apply**; if any endpoint
  mints a new id, reuse the saved-search `old_id`-tracking pattern.

## Error handling & edge cases

- **Unresolved ref** (sibling not deployed / missing) → `UnresolvedRefError`; apply aborts
  that resource with a clear message before any API call. Orchestrator ordering normally
  prevents this.
- **Empty-tenant reads** (verified: zero entities today) → `query_*` returns `[]`;
  `fetch_remote_state` returns `None` → treated as "needs create."
- **Dangling reference on destroy** → block destroying a notification group / SLA still
  referenced by a live sibling, surfacing the dependent (consistent with talonctl
  dependency safety).
- **API id vs `resource_id`** invariant preserved: templates never contain raw API ids;
  those live only in state.
- **Partial id capture:** if create succeeds but the response omits option/field ids,
  re-fetch via `get_*` to populate `provider_metadata`.

## Testing strategy

Mirror the existing provider unit tests (`tests/unit/test_*_provider.py`), with FalconPy
mocked — no live API calls:

- **Per provider:** validate (happy path + each failure), plan create/update/no-change,
  apply create/update/delete body assertions, `to_template` round-trip.
- **`RefResolver`:** resolves a deployed sibling, raises `UnresolvedRefError` on missing,
  enforces correct resource type.
- **`extract_dependencies`:** derives correct `depends_on` edges from `*_ref`.
- **Integration:** three-resource fixture (group → SLA → template) plans and applies in
  correct order; **hash-stability** test — changing a referenced SLA's API id must **not**
  mark the template drifted.
- **Discovery / init:** the three new directories scaffold; `KIND_TO_TYPE` round-trips for
  all three kinds.

## Registration touchpoints (implementation checklist)

1. `providers/case_notification_group_provider.py`, `case_sla_provider.py`,
   `case_template_provider.py` — new `BaseResourceProvider` implementations.
2. `providers/__init__.py` — export the three providers.
3. `core/provider_adapter.py` — instantiate + register the three under their type IDs.
4. `core/template_discovery.py` — add three type IDs to `VALID_RESOURCE_TYPES` and
   `TYPE_TO_DIR`.
5. `core/envelope.py` — add three kinds to `KIND_TO_TYPE`.
6. `commands/init.py` — add the three directories to `RESOURCE_DIRS`.
7. `utils/case_management_client.py` — shared `CaseManagement` client factory.
8. `core/ref_resolver.py` — shared `RefResolver` + `UnresolvedRefError`; wire into the
   orchestrator apply path.
9. `examples/resources/case_notification_group.yaml`, `case_sla.yaml`,
   `case_template.yaml` — annotated reference templates.
10. `src/talonctl/templates/init/` — scaffold the three directories for new projects.

## Open questions (confirm during implementation)

1. Exact create/patch body field names and required-vs-optional split (verify by creating
   one sample of each entity and exporting it).
2. Whether PATCH updates preserve the entity id (expected yes) or mint a new id.
3. Notification-group channel schema for non-email channel types (`config_id` semantics).
4. Whether `export` YAML is close enough to the authored envelope to power `import`
   directly, or whether `to_template()` from `get_*` is cleaner.
