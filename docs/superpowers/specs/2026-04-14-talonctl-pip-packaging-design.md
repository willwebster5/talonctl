# talonctl — Pip-Installable CLI Packaging

> **Status:** Approved
> **Date:** 2026-04-14
> **Scope:** talonctl repo only

## Goal

Transform talonctl from a directory of scripts into a pip-installable Python CLI tool. After this work, `pip install talonctl` gives users the `talonctl` command, and `talonctl init` scaffolds a new project — cleanly separating the *tool* from the *project that uses it*.

## Current State

- CLI entry point: `python scripts/resource_deploy.py <command>`
- No `pyproject.toml` or packaging metadata
- `scripts/common.py` manages `sys.path` for imports
- 36 Python files (~15.6K lines) across `scripts/core/`, `scripts/providers/`, `scripts/utils/`
- Tests reference `scripts.*` import paths
- CI runs `python scripts/resource_deploy.py` directly
- Dependencies in `requirements.txt` with minimum version pins

## Target State

```
talonctl/                          # repo root
├── src/talonctl/                  # the pip package
│   ├── __init__.py                # __version__ = "1.0.0"
│   ├── cli.py                     # Click group — top-level entry point
│   ├── commands/                  # One module per subcommand
│   │   ├── __init__.py
│   │   ├── validate.py
│   │   ├── plan.py
│   │   ├── apply.py
│   │   ├── import_cmd.py          # "import" is a Python keyword
│   │   ├── sync.py
│   │   ├── drift.py
│   │   ├── show.py
│   │   ├── init.py                # NEW — scaffold a talonctl project
│   │   ├── discover.py            # from template_discovery.py
│   │   └── backup.py              # from create_backup.py
│   ├── core/                      # moved from scripts/core/
│   │   ├── __init__.py
│   │   ├── deployment_orchestrator.py
│   │   ├── state_manager.py
│   │   ├── plan_formatter.py
│   │   ├── provider_adapter.py
│   │   ├── drift_detector.py
│   │   ├── deployment_strategies.py
│   │   ├── state_synchronizer.py
│   │   ├── resource_graph.py
│   │   ├── provider_registry.py
│   │   ├── base_provider.py
│   │   ├── dependency_validator.py
│   │   ├── deploy_lock.py
│   │   └── template_discovery.py
│   ├── providers/                 # moved from scripts/providers/
│   │   ├── __init__.py
│   │   ├── detection_provider.py
│   │   ├── saved_search_provider.py
│   │   ├── dashboard_provider.py
│   │   ├── workflow_provider.py
│   │   ├── lookup_file_provider.py
│   │   ├── rtr_script_provider.py
│   │   └── rtr_put_file_provider.py
│   └── utils/                     # moved from scripts/utils/
│       ├── __init__.py
│       ├── auth.py
│       ├── ngsiem_client.py
│       ├── ngsiem_files.py
│       ├── mitre_processor.py
│       ├── template_matcher.py
│       └── find_duplicate_rules.py
├── tests/                         # updated imports (talonctl.* not scripts.*)
│   ├── conftest.py
│   └── unit/
├── examples/                      # stays — example templates
├── knowledge/                     # stays — dev/example project content
├── resources/                     # stays — dev/example project content
├── .crowdstrike/                  # stays — dev state file
├── .github/workflows/             # updated for pip install
├── pyproject.toml                 # package metadata, deps, entry points
├── README.md                      # rewritten for pip install audience
├── CLAUDE.md                      # updated paths
├── CLAUDE.integrated.md           # updated paths
├── GETTING_STARTED.md             # updated for talonctl CLI
├── LICENSE                        # stays (MIT)
└── pytest.ini                     # updated test paths if needed
```

## Package Metadata (pyproject.toml)

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "talonctl"
version = "1.0.0"
description = "Infrastructure as code for CrowdStrike NGSIEM"
readme = "README.md"
license = "MIT"
requires-python = ">=3.11"
authors = [{ name = "Will Webster" }]
keywords = ["crowdstrike", "ngsiem", "detection-as-code", "security"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Information Technology",
    "Topic :: Security",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
dependencies = [
    "crowdstrike-falconpy>=1.6.1",
    "pyyaml>=6.0",
    "rich>=13.0.0",
    "requests>=2.28.0",
    "click>=8.0.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0.0", "ruff>=0.8.0"]

[project.scripts]
talonctl = "talonctl.cli:cli"

[tool.hatch.build.targets.wheel]
packages = ["src/talonctl"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ruff]
target-version = "py311"
line-length = 120
```

## CLI Design

Click group with subcommands. Each subcommand is a module in `talonctl/commands/`.

```
talonctl validate [--template PATH]       # Validate templates
talonctl plan                              # Preview changes
talonctl apply [--auto-approve]            # Deploy changes
talonctl import [--plan] [--resources TYPE]# Import from tenant
talonctl sync                              # Reconcile state with tenant
talonctl drift                             # Detect manual console changes
talonctl show                              # Show current state
talonctl init [PATH]                       # NEW: scaffold a project
talonctl discover [--vendors ...] [--max N]# From template_discovery.py
talonctl backup                            # From create_backup.py
```

### `talonctl init`

Scaffolds a new talonctl project directory:

```
my-project/
├── resources/
│   ├── detections/
│   ├── saved_searches/
│   ├── dashboards/
│   ├── workflows/
│   ├── lookup_files/
│   ├── rtr_scripts/
│   └── rtr_put_files/
├── knowledge/
│   ├── INDEX.md
│   ├── context/
│   │   └── environmental-context.md
│   ├── patterns/
│   ├── techniques/
│   │   └── investigation-techniques.md
│   ├── tuning/
│   │   ├── tuning-backlog.md
│   │   └── tuning-log.md
│   ├── metrics/
│   │   └── detection-metrics.jsonl
│   ├── hunts/
│   └── ideas/
│       └── detection-ideas.md
├── .crowdstrike/
│   └── deployed_state.json
├── .gitignore
└── CLAUDE.md
```

The templates for `init` are bundled inside the package at `src/talonctl/templates/init/`. These are copies of the knowledge base scaffold files (INDEX.md, environmental-context.md, etc.) already created in the talonctl repo's `knowledge/` directory — the same files, packaged so `talonctl init` can create them in a new project without the user cloning the repo.

## Migration Details

### Import Path Changes

All internal imports change from `scripts.*` to `talonctl.*`:

| Before | After |
|--------|-------|
| `from scripts.core.state_manager import StateManager` | `from talonctl.core.state_manager import StateManager` |
| `from scripts.providers.detection_provider import DetectionProvider` | `from talonctl.providers.detection_provider import DetectionProvider` |
| `from scripts.utils.auth import load_credentials` | `from talonctl.utils.auth import load_credentials` |

### `scripts/common.py` Elimination

This file currently does `sys.path` manipulation so scripts can import each other. With proper packaging, it's unnecessary. All files that `import common` or use `common.get_project_root()` need updating:

- Replace `common.get_project_root()` with a function that finds the project root by walking up from CWD looking for `.crowdstrike/` (the definitive marker, like `.git/`). Stop at the first directory containing `.crowdstrike/`. If not found, fall back to CWD and let the command fail gracefully if required state files are missing.
- The CLI commands operate on the *current working directory* as the project root (or accept `--project-dir`).

### Utility Scripts

| Script | Disposition |
|--------|------------|
| `resource_deploy.py` | Decomposed into `cli.py` + `commands/` modules |
| `common.py` | Eliminated — proper package imports |
| `setup.py` | Stays as `scripts/setup.py` (interactive credential wizard, not part of the package) or becomes `talonctl setup` |
| `template_discovery.py` | Becomes `talonctl discover` subcommand |
| `create_backup.py` | Becomes `talonctl backup` subcommand |
| `detection_health.py` | Stays as utility script in `scripts/` (SOC-specific, not core tool) |
| `soc_metrics.py` | Stays as utility script in `scripts/` (SOC-specific, not core tool) |

### Test Updates

- All test imports updated from `scripts.*` to `talonctl.*`
- `conftest.py` fixtures updated for new paths
- Tests run via `pytest` after `pip install -e .[dev]`

### CI Updates

- `pip install -e .[dev]` replaces `pip install -r requirements.txt`
- `talonctl validate` replaces `python scripts/resource_deploy.py validate`
- `talonctl plan` replaces `python scripts/resource_deploy.py plan`
- Same for apply, sync, drift

### Documentation Updates

- `README.md`: Rewritten for `pip install talonctl` audience. Quick start uses `talonctl` commands. Links to demo repo for a complete example.
- `GETTING_STARTED.md`: Updated for `pip install` and `talonctl init` workflow.
- `CLAUDE.md` / `CLAUDE.integrated.md`: Updated command references and project structure.

## What Does NOT Change

- Provider architecture (BaseProvider, per-resource-type providers)
- State file format (v3.0, `.crowdstrike/deployed_state.json`)
- Template YAML schema (resource_id, name, search, operation, ads, etc.)
- Knowledge base structure and loading tiers
- ADS validation logic
- GitHub Actions workflow structure (just updated commands)
- Test logic (just updated imports)

## Out of Scope

- PyPI publishing (future work — for now it's `pip install git+https://...` or local install)
- Plugin/extension system for custom providers
- Config file for talonctl settings (project-level `.talonctl.yaml` or similar)
