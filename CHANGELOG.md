# Changelog

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
