# talonctl -- Project Instructions

Pip-installable CLI tool for CrowdStrike NGSIEM infrastructure as code. Terraform-like plan/apply for detection rules, saved searches, dashboards, workflows, lookup files, and RTR resources.

## Project Overview

This repo is the **tool** -- a pip-installable Python package. It does not contain detection templates, knowledge bases, or project-specific content. Those live in user projects (e.g., [talonctl-demo](https://github.com/willwebster5/talonctl-demo)).

- **Six resource types** -- detections, saved searches, dashboards, lookup files, RTR scripts, RTR put files (workflows temporarily deprecated — see issue #23)
- **Terraform-like lifecycle** -- validate, plan, apply, import, sync, drift
- **State management** -- tracks deployed resources and their CrowdStrike API IDs
- **Scaffolding** -- `talonctl init` creates new projects with the correct directory structure

## Package Structure

```
talonctl/
├── pyproject.toml              # Package configuration (pip install -e .[dev])
├── src/talonctl/               # Package source
│   ├── __init__.py             # Version
│   ├── cli.py                  # Click CLI entry point
│   ├── project.py              # Project root finder
│   ├── commands/               # CLI command modules
│   │   ├── auth.py             # talonctl auth (setup + check)
│   │   ├── health.py           # talonctl health (detection health check)
│   │   ├── metrics.py          # talonctl metrics (update-detections + update-kpis)
│   │   ├── backup.py           # talonctl backup (create, list, restore)
│   │   ├── validate.py         # talonctl validate
│   │   ├── plan.py             # talonctl plan
│   │   ├── apply.py            # talonctl apply
│   │   ├── show.py             # talonctl show
│   │   ├── sync.py             # talonctl sync
│   │   ├── drift.py            # talonctl drift
│   │   ├── destroy.py          # talonctl destroy
│   │   ├── import_cmd.py       # talonctl import
│   │   ├── publish.py          # talonctl publish
│   │   ├── validate_query.py   # talonctl validate-query
│   │   ├── init.py             # talonctl init
│   │   ├── discover.py         # talonctl discover
│   │   └── _common.py          # Shared CLI helpers
│   ├── core/                   # Orchestrator, state, plan, drift, template discovery
│   ├── providers/              # Per-resource-type API adapters
│   ├── utils/                  # Auth, NGSIEM client, MITRE processor
│   └── templates/              # Scaffolding templates for `talonctl init`
├── .crowdstrike/               # Empty state placeholder (for development)
├── examples/resources/         # Format reference templates (7 YAML + README)
└── tests/                      # Unit tests (pytest)
```

## CLI Command Reference

```bash
# IaC lifecycle
talonctl validate                    # Validate all templates (no API calls)
talonctl plan                        # Preview what would change
talonctl apply                       # Deploy changes
talonctl import --plan               # Preview importing existing resources
talonctl sync                        # Reconcile state with live tenant
talonctl drift                       # Detect manual console changes
talonctl show                        # Show current state
talonctl destroy                     # Destroy managed resources
talonctl migrate                     # Dry-run: preview v1->v2 template + v3->v4 state migration
talonctl migrate --write             # Apply migration in place (git is the rollback)
talonctl migrate --templates-only    # Rewrap templates only
talonctl migrate --state-only        # Reconcile state only
talonctl migrate --format json -o m.json  # Machine-readable report (orphans/unmanaged/conflicts)

# Credential management
talonctl auth setup                  # Interactive credential setup wizard
talonctl auth check                  # Verify stored credentials

# Operational
talonctl health                      # Detection health check
talonctl health --format json -o r.json  # Export health report
talonctl metrics update-detections --report r.json  # Update detection metrics CSV
talonctl metrics update-kpis --report r.json        # Update KPI CSV
talonctl backup create               # Create state backup (GitHub Release)
talonctl backup list                 # List available backups
talonctl backup restore <tag>        # Restore from backup

# Scaffolding
talonctl init myproject              # Create a new project
talonctl discover                    # Find new detection templates
```

## Development

### Running Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest tests/ -v
```

### Installing pre-commit hooks

Once, after `pip install -e .[dev]`:

```bash
pre-commit install
```

After that, `git commit` auto-runs `ruff format` and `ruff check`. The config in `.pre-commit-config.yaml` mirrors the CI lint gate — keeping both green locally means CI stays green.

### Adding a New CLI Command

1. Create `src/talonctl/commands/mycommand.py` with a Click command or group
2. Import the shared `console` from `talonctl.commands._common`
3. Register in `src/talonctl/cli.py`: import and `cli.add_command()`
4. Add tests in `tests/unit/test_mycommand.py` using `click.testing.CliRunner`
5. Run `pytest tests/unit/test_mycommand.py -v`

### Adding a New Resource Type

1. Create a provider in `src/talonctl/providers/` implementing the `ProviderAdapter` interface
2. Register the provider in `src/talonctl/core/__init__.py`
3. Add a format reference template in `examples/resources/`
4. Add the resource type to `talonctl init` scaffolding templates

### Format Reference Templates

`examples/resources/` contains annotated YAML examples for every resource type. These serve as documentation for template authors -- they are NOT deployed. Each example shows all supported fields with comments.

### Init Template Scaffolding

`src/talonctl/templates/init/` contains the directory structure and files created by `talonctl init`. Changes here affect all new projects.

## Critical Concepts

### resource_id vs name

- **`resource_id`** -- stable key in the state file. Once deployed, **never change this**. Changing it = destroy + recreate.
- **`name`** -- display name in the Falcon console. Can be updated freely.

### State File

- Location: `.crowdstrike/deployed_state.json` (in user projects)
- Format version: v3.0
- Do not edit manually -- use `sync` to reconcile

## Credentials

- **Location:** `~/.config/falcon/credentials.json`
- **Setup:** `talonctl auth setup`
- **Never commit credentials.**

## Production Rules

1. **Always plan before apply.** Never blind-deploy.
2. **Never change `resource_id` after deploy.**
3. **Saved search description limit: 2000 characters.** The API silently truncates.
4. **Validate CQL syntax** before committing: `talonctl validate-query --template <path>`
