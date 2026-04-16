# Changelog

## v0.3.0 — Metadata Namespace Redesign (BREAKING)

### Breaking changes

- Top-level `ads:` block is removed. Move it under `metadata.ads:`.
- Top-level flat `metadata:` with maturity fields at root is removed. Nest
  fields under `metadata.maturity:`.
- All seven resource types now share a reserved top-level `metadata:`
  namespace that is stripped from API payloads and content hashes. Third-party
  frameworks can add sub-namespaces (e.g. `metadata.<team_name>:`) with a
  guarantee they will never leak to the CrowdStrike/Humio API.

### Migration (before → after)

Before:

```yaml
resource_id: my_detection
name: "My Detection"
ads:
  goal: "Detect something"
  mitre_attack: ["TA0011:T1090.003"]
metadata:
  created: "2026-04-14"
  last_tuned: "2026-04-16"
  tune_count: 2
  confidence: high
severity: 50
search: { ... }
```

After:

```yaml
resource_id: my_detection
name: "My Detection"
metadata:
  maturity:
    created: "2026-04-14"
    last_tuned: "2026-04-16"
    tune_count: 2
    confidence: high
  ads:
    goal: "Detect something"
    mitre_attack: ["TA0011:T1090.003"]
severity: 50
search: { ... }
```

Migration rules (mechanical):

- Top-level `ads:` → `metadata.ads:`.
- Top-level flat `metadata:` with `created` / `last_tuned` / `tune_count` /
  `confidence` at root → `metadata.maturity:` with the same fields inside.
- If both were present, merge into a single `metadata:` with `maturity:` and
  `ads:` sub-namespaces.

No `talonctl migrate` command ships — the corpus is small enough to hand-edit
or rewrite with an editor or assistant.

### Fixed

- Dashboard apply no longer leaks `_template_path` into the Humio schema
  validation payload (closes issue #7). The stripping fix is shared across
  all resource types via `core/template_sanitizer` (shipped in v0.2.1) and
  is now exercised by every provider's payload/hash path.
- Reference templates `examples/resources/lookup_file.yaml`,
  `rtr_put_file.yaml`, and `workflow.yaml` had pre-existing schema bugs
  (missing required fields, wrong field names, broken file paths). These
  are fixed and now exercised by a new parity test.

### Added

- `metadata.maturity:` validation now runs on every resource type, not just
  detections. Schema: `created` (YYYY-MM-DD), `last_tuned` (YYYY-MM-DD or
  null), `tune_count` (non-negative int), `confidence` (low/medium/high/
  validated). All four fields optional.
- `metadata.ads:` remains detection-only. Non-detection providers reject it
  with a clear error pointing at the resource type.
- Third-party frameworks may add arbitrary sub-namespaces under `metadata.`
  (e.g. `metadata.acme_corp:`). These are stripped from API payloads and
  ignored by talonctl; users supply their own validators if needed.
- `tests/unit/test_examples.py` parity test ensures reference YAMLs under
  `examples/resources/` do not drift out of spec.
- `tests/unit/test_old_shape_rejection.py` locks every provider's migration
  pointer error string so a silent refactor can never drop it.

## v0.2.1 — 2026-04-16

### Fixed

- Dashboard apply no longer leaks `_template_path` into the Humio schema
  validation payload (closes #7). `DashboardProvider._prepare_yaml_payload`
  and `_normalize_for_hash` now route through a new
  `core/template_sanitizer` helper that strips `_`-prefixed tool-internal
  keys and the universally-IaC field set `{resource_id, type, dependencies,
  metadata}`. Dashboard-specific transforms (`tags → labels`, `description`
  strip) are preserved unchanged.

### Chore

- Added `.pre-commit-config.yaml` with ruff hooks mirroring the CI lint
  gate. Install with `pre-commit install` after `pip install -e .[dev]`.

### Skipped

- **v0.2.0** was never released to PyPI. Its git tag was pushed malformed
  (`v.0.2.0` with an extra dot) and the release job's VCS-versioning could
  not parse it. The malformed tag remains on the remote — a GitHub
  repository rule blocks tag deletion — but it is orphaned: hatchling's
  VCS versioning cannot parse it, so no release will ever be cut from
  it. v0.2.1 is the first working 0.2.x release.
