# talonctl — Pip-Installable CLI Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform talonctl from `python scripts/resource_deploy.py` into `pip install talonctl && talonctl plan` — a proper Python package with CLI entry point.

**Architecture:** Move all source code from `scripts/` to `src/talonctl/`, replace argparse CLI with Click, add `pyproject.toml` with hatchling, create `talonctl init` command for scaffolding new projects. All internal imports change from bare `core.*` / `providers.*` / `utils.*` to `talonctl.*`.

**Tech Stack:** Python 3.11+, hatchling, Click, Rich (existing), FalconPy (existing)

---

### File Map

**Create:**
- `pyproject.toml`
- `src/talonctl/__init__.py`
- `src/talonctl/cli.py` — Click group entry point
- `src/talonctl/commands/__init__.py`
- `src/talonctl/commands/validate.py`
- `src/talonctl/commands/plan.py`
- `src/talonctl/commands/apply.py`
- `src/talonctl/commands/import_cmd.py`
- `src/talonctl/commands/sync.py`
- `src/talonctl/commands/drift.py`
- `src/talonctl/commands/show.py`
- `src/talonctl/commands/destroy.py`
- `src/talonctl/commands/publish.py`
- `src/talonctl/commands/validate_query.py`
- `src/talonctl/commands/init.py`
- `src/talonctl/commands/discover.py`
- `src/talonctl/commands/backup.py`
- `src/talonctl/commands/_common.py` — shared CLI helpers (console, filters, orchestrator init)
- `src/talonctl/project.py` — project root finder
- `src/talonctl/templates/init/` — scaffold templates for `talonctl init`
- `tests/unit/test_project.py` — tests for project root finder
- `tests/unit/test_init_command.py` — tests for init scaffolding

**Move (git mv):**
- `scripts/core/` → `src/talonctl/core/`
- `scripts/providers/` → `src/talonctl/providers/`
- `scripts/utils/` → `src/talonctl/utils/`

**Delete:**
- `scripts/resource_deploy.py` — replaced by cli.py + commands/
- `scripts/common.py` — replaced by proper package imports + project.py
- `requirements.txt` — replaced by pyproject.toml

**Keep as-is:**
- `scripts/setup.py` — interactive credential wizard (not part of package)
- `scripts/detection_health.py` — SOC-specific utility
- `scripts/soc_metrics.py` — SOC-specific utility

**Modify:**
- All `*.py` under `src/talonctl/` — import path updates
- All `tests/**/*.py` — import path updates
- `tests/conftest.py` — remove sys.path manipulation
- `.github/workflows/plan-and-deploy.yml` — pip install
- `.github/workflows/weekly-template-discovery.yml` — pip install
- `README.md`, `CLAUDE.md`, `CLAUDE.integrated.md`, `GETTING_STARTED.md`

---

### Task 1: Create package skeleton and pyproject.toml

**Files:**
- Create: `pyproject.toml`
- Create: `src/talonctl/__init__.py`
- Create: `src/talonctl/commands/__init__.py`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p src/talonctl/commands
mkdir -p src/talonctl/templates/init
```

- [ ] **Step 2: Create `src/talonctl/__init__.py`**

```python
"""talonctl — Infrastructure as code for CrowdStrike NGSIEM."""

__version__ = "1.0.0"
```

- [ ] **Step 3: Create `src/talonctl/commands/__init__.py`**

```python
"""CLI command modules for talonctl."""
```

- [ ] **Step 4: Create `pyproject.toml`**

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
python_files = "test_*.py"
python_classes = "Test*"
python_functions = "test_*"
markers = [
    "integration: marks tests as integration tests",
    "live_api: marks tests that hit real API",
    "slow: marks slow tests",
    "unit: marks unit tests",
]

[tool.ruff]
target-version = "py311"
line-length = 120
```

- [ ] **Step 5: Verify skeleton installs**

Run: `pip install -e . 2>&1 | tail -5`
Expected: `Successfully installed talonctl-1.0.0`

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/talonctl/__init__.py src/talonctl/commands/__init__.py
git commit -m "feat: add pyproject.toml and package skeleton"
```

---

### Task 2: Move core/, providers/, utils/ into package

**Files:**
- Move: `scripts/core/` → `src/talonctl/core/`
- Move: `scripts/providers/` → `src/talonctl/providers/`
- Move: `scripts/utils/` → `src/talonctl/utils/`

- [ ] **Step 1: Move directories**

```bash
git mv scripts/core/ src/talonctl/core/
git mv scripts/providers/ src/talonctl/providers/
git mv scripts/utils/ src/talonctl/utils/
```

- [ ] **Step 2: Commit the move (before import changes)**

Commit the raw move separately so git tracks the file rename history:

```bash
git commit -m "refactor: move core/, providers/, utils/ into src/talonctl/"
```

---

### Task 3: Update imports in core/

**Files:**
- Modify: `src/talonctl/core/__init__.py`
- Modify: All `.py` files in `src/talonctl/core/`

The core `__init__.py` currently uses bare `from core.X import Y` imports. All need the `talonctl.` prefix. Internal cross-references within core use `from core.X import Y` as well.

- [ ] **Step 1: Update `core/__init__.py`**

Replace all `from core.` with `from talonctl.core.`:

```python
# Before:
from core.base_provider import (BaseResourceProvider, ResourceAction, ResourceChange)
from core.resource_graph import (ResourceGraph, DependencyCycle)
from core.state_manager import (StateManager, ResourceState)
# ... etc

# After:
from talonctl.core.base_provider import (BaseResourceProvider, ResourceAction, ResourceChange)
from talonctl.core.resource_graph import (ResourceGraph, DependencyCycle)
from talonctl.core.state_manager import (StateManager, ResourceState)
# ... etc for all imports
```

- [ ] **Step 2: Update cross-module imports within core/**

Search each `.py` file in `src/talonctl/core/` for imports from `core.` or `utils.` and prefix with `talonctl.`:

Pattern — apply to each file:
```python
# Before:
from core.resource_graph import ResourceGraph
from core.state_manager import StateManager, ResourceState
from utils.mitre_processor import MitreProcessor

# After:
from talonctl.core.resource_graph import ResourceGraph
from talonctl.core.state_manager import StateManager, ResourceState
from talonctl.utils.mitre_processor import MitreProcessor
```

Files to update (check each, apply pattern to any `from core.` or `from utils.` imports found):
- `deployment_orchestrator.py` — imports from core (multiple) and utils
- `state_manager.py` — imports from core.resource_graph
- `provider_adapter.py` — imports from core.state_manager, core.base_provider
- `drift_detector.py` — imports from core modules
- `deployment_strategies.py` — imports from core modules
- `state_synchronizer.py` — imports from core and utils
- `plan_formatter.py` — imports from core
- `template_discovery.py` — imports from core and utils
- `base_provider.py` — may import from utils
- `provider_registry.py` — imports from core.base_provider
- `dependency_validator.py` — imports from core
- `deploy_lock.py` — likely stdlib only
- `resource_graph.py` — likely stdlib only

- [ ] **Step 3: Commit**

```bash
git commit -am "refactor: update imports in talonctl.core"
```

---

### Task 4: Update imports in providers/

**Files:**
- Modify: `src/talonctl/providers/__init__.py`
- Modify: All provider `.py` files

- [ ] **Step 1: Update `providers/__init__.py`**

The current `__init__.py` uses relative imports (`.detection_provider`), which will continue to work. Verify and leave as-is if using relative imports.

- [ ] **Step 2: Update provider files**

Each provider imports from `core` and `utils`. Apply the pattern:

```python
# Before:
from core.base_provider import BaseResourceProvider, ResourceChange, ResourceAction
from core.deployment_strategies import DeploymentStrategyFactory
from utils.mitre_processor import MitreProcessor
from utils.auth import load_credentials

# After:
from talonctl.core.base_provider import BaseResourceProvider, ResourceChange, ResourceAction
from talonctl.core.deployment_strategies import DeploymentStrategyFactory
from talonctl.utils.mitre_processor import MitreProcessor
from talonctl.utils.auth import load_credentials
```

Files to update:
- `detection_provider.py` — imports from core.base_provider, core.deployment_strategies, utils.mitre_processor
- `saved_search_provider.py` — imports from core.base_provider
- `dashboard_provider.py` — imports from core.base_provider
- `workflow_provider.py` — imports from core.base_provider
- `lookup_file_provider.py` — imports from core.base_provider, utils
- `rtr_script_provider.py` — imports from core.base_provider, utils
- `rtr_put_file_provider.py` — imports from core.base_provider, utils

- [ ] **Step 3: Commit**

```bash
git commit -am "refactor: update imports in talonctl.providers"
```

---

### Task 5: Update imports in utils/

**Files:**
- Modify: All `.py` files in `src/talonctl/utils/`

- [ ] **Step 1: Update utils files**

Check each file for imports from `core.`, `utils.`, or `common`:

```python
# Before:
from common import PATHS, load_auth

# After:
# This import goes away entirely — common.py is being eliminated.
# Replace with direct imports from the modules that PATHS wrapped.
```

For `utils/ngsiem_client.py` (imports from common):
- Replace `from common import PATHS, load_auth, setup_imports` with direct credential loading via `from talonctl.utils.auth import load_credentials`
- Replace `PATHS.PROJECT_ROOT` references with the new project root finder

For other utils files: check and update any `from core.` or `from utils.` cross-references to use `talonctl.` prefix.

- [ ] **Step 2: Commit**

```bash
git commit -am "refactor: update imports in talonctl.utils"
```

---

### Task 6: Create project root finder

**Files:**
- Create: `src/talonctl/project.py`
- Create: `tests/unit/test_project.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_project.py`:
```python
"""Tests for talonctl project root detection."""

import os
import tempfile
from pathlib import Path

import pytest

from talonctl.project import find_project_root


class TestFindProjectRoot:
    def test_finds_root_by_crowdstrike_dir(self, tmp_path):
        """Should find root when .crowdstrike/ exists."""
        (tmp_path / ".crowdstrike").mkdir()
        result = find_project_root(start=tmp_path)
        assert result == tmp_path

    def test_finds_root_from_subdirectory(self, tmp_path):
        """Should walk up and find root from a nested directory."""
        (tmp_path / ".crowdstrike").mkdir()
        nested = tmp_path / "resources" / "detections"
        nested.mkdir(parents=True)
        result = find_project_root(start=nested)
        assert result == tmp_path

    def test_returns_cwd_when_no_marker(self, tmp_path):
        """Should return start directory when no .crowdstrike/ found."""
        result = find_project_root(start=tmp_path)
        assert result == tmp_path

    def test_stops_at_filesystem_root(self, tmp_path):
        """Should not infinite-loop when no marker exists."""
        deeply_nested = tmp_path / "a" / "b" / "c" / "d"
        deeply_nested.mkdir(parents=True)
        result = find_project_root(start=deeply_nested)
        assert result == deeply_nested
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_project.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'talonctl.project'`

- [ ] **Step 3: Implement project root finder**

`src/talonctl/project.py`:
```python
"""Project root detection for talonctl projects."""

from pathlib import Path


def find_project_root(start: Path | None = None) -> Path:
    """Find the talonctl project root by walking up from start looking for .crowdstrike/.

    Similar to how git finds .git/. If not found, returns start directory.

    Args:
        start: Directory to start searching from. Defaults to CWD.

    Returns:
        Path to the project root directory.
    """
    if start is None:
        start = Path.cwd()
    start = start.resolve()

    current = start
    while True:
        if (current / ".crowdstrike").is_dir():
            return current
        parent = current.parent
        if parent == current:
            # Hit filesystem root without finding marker
            return start
        current = parent
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/unit/test_project.py -v
```
Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/talonctl/project.py tests/unit/test_project.py
git commit -m "feat: add project root finder"
```

---

### Task 7: Create Click CLI and command modules

**Files:**
- Create: `src/talonctl/cli.py`
- Create: `src/talonctl/commands/_common.py`
- Create: All command modules in `src/talonctl/commands/`

This task decomposes the monolithic `resource_deploy.py` (909 lines) into focused Click command modules.

- [ ] **Step 1: Create `commands/_common.py` — shared CLI helpers**

This extracts the common patterns used by all commands: console setup, filter parsing, orchestrator initialization.

```python
"""Shared CLI helpers for talonctl commands."""

import os
import logging
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from talonctl.project import find_project_root

# Rich console — shared by all commands
disable_color = os.getenv('NO_COLOR') is not None or os.getenv('CI') is not None
console = Console(
    width=200 if os.getenv('CI') else None,
    force_terminal=not disable_color,
    no_color=disable_color,
    force_jupyter=False,
)

logger = logging.getLogger("talonctl")


def parse_filters(
    resources: Optional[str] = None,
    tags: Optional[str] = None,
    names: Optional[str] = None,
) -> dict:
    """Parse comma-separated filter strings into lists."""
    filters = {}
    if resources:
        filters['resource_types'] = [r.strip() for r in resources.split(',')]
    if tags:
        filters['tags'] = [t.strip() for t in tags.split(',')]
    if names:
        filters['names'] = [n.strip() for n in names.split(',')]
    return filters


def get_state_file_path(state_file: Optional[str] = None) -> Path:
    """Determine state file path."""
    if state_file:
        return Path(state_file)
    project_root = find_project_root()
    return project_root / '.crowdstrike' / 'deployed_state.json'


def init_orchestrator(
    state_file: Optional[str] = None,
    require_credentials: bool = True,
    remote_state: bool = False,
    remote_state_search_domain: str = 'falcon',
    remote_state_filename: str = 'unified_deployment_state.json',
):
    """Initialize deployment orchestrator."""
    from falconpy import APIHarnessV2
    from talonctl.utils.auth import load_credentials
    from talonctl.core import DeploymentOrchestrator

    state_file_path = get_state_file_path(state_file)

    creds = None
    falcon = None
    if require_credentials:
        creds = load_credentials()
        falcon = APIHarnessV2(
            client_id=creds['falcon_client_id'],
            client_secret=creds['falcon_client_secret'],
            base_url=creds.get('base_url', 'US1'),
        )

    return DeploymentOrchestrator(
        falcon_client=falcon,
        state_file_path=state_file_path,
        remote_state_enabled=remote_state,
        remote_state_search_domain=remote_state_search_domain,
        remote_state_filename=remote_state_filename,
        credentials=creds,
    )


# Common Click options used by multiple commands
def filter_options(f):
    """Decorator adding --resources, --tags, --names options."""
    f = click.option('--resources', type=str, help='Filter by resource types (comma-separated)')(f)
    f = click.option('--tags', type=str, help='Filter by tags (comma-separated)')(f)
    f = click.option('--names', type=str, help='Filter by resource names (glob patterns, comma-separated)')(f)
    return f


def state_options(f):
    """Decorator adding --state-file option."""
    f = click.option('--state-file', type=str, help='Custom state file location')(f)
    return f


def remote_state_options(f):
    """Decorator adding remote state options."""
    f = click.option('--remote-state', is_flag=True, help='Enable remote state sync')(f)
    f = click.option('--remote-state-search-domain', type=click.Choice(['falcon', 'all', 'third-party', 'dashboards', 'parsers-repository']), default='falcon')(f)
    f = click.option('--remote-state-filename', type=str, default='unified_deployment_state.json')(f)
    return f
```

- [ ] **Step 2: Create `cli.py` — Click group entry point**

```python
"""talonctl CLI — Infrastructure as code for CrowdStrike NGSIEM."""

import logging
from datetime import datetime

import click

from talonctl import __version__
from talonctl.commands._common import console


@click.group()
@click.version_option(version=__version__, prog_name="talonctl")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, verbose):
    """Infrastructure as code for CrowdStrike NGSIEM."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )

    console.print(f"\n[bold cyan]talonctl[/bold cyan] [dim]v{__version__}[/dim]")
    console.print(f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")


# Import and register command modules
from talonctl.commands.validate import validate  # noqa: E402
from talonctl.commands.plan import plan  # noqa: E402
from talonctl.commands.apply import apply  # noqa: E402
from talonctl.commands.show import show  # noqa: E402
from talonctl.commands.sync import sync  # noqa: E402
from talonctl.commands.drift import drift  # noqa: E402
from talonctl.commands.destroy import destroy  # noqa: E402
from talonctl.commands.import_cmd import import_cmd  # noqa: E402
from talonctl.commands.publish import publish  # noqa: E402
from talonctl.commands.validate_query import validate_query  # noqa: E402
from talonctl.commands.init import init  # noqa: E402
from talonctl.commands.discover import discover  # noqa: E402
from talonctl.commands.backup import backup  # noqa: E402

cli.add_command(validate)
cli.add_command(plan)
cli.add_command(apply)
cli.add_command(show)
cli.add_command(sync)
cli.add_command(drift)
cli.add_command(destroy)
cli.add_command(import_cmd, name='import')
cli.add_command(publish)
cli.add_command(validate_query, name='validate-query')
cli.add_command(init)
cli.add_command(discover)
cli.add_command(backup)
```

- [ ] **Step 3: Create command modules**

Each command module is a Click command extracted from `resource_deploy.py`. The logic stays the same — only the CLI framework changes from argparse to Click.

**`commands/validate.py`** (from `command_validate`, lines 468-491):
```python
"""talonctl validate — validate all templates."""

import click

from talonctl.commands._common import (
    console, filter_options, state_options, parse_filters, init_orchestrator,
)


@click.command()
@filter_options
@state_options
@click.pass_context
def validate(ctx, resources, tags, names, state_file):
    """Validate all templates without deploying."""
    console.print("[bold blue]Validating templates...[/bold blue]\n")
    verbose = ctx.obj.get('verbose', False)

    orchestrator = init_orchestrator(state_file=state_file, require_credentials=False)
    filters = parse_filters(resources, tags, names)

    try:
        from talonctl.core import PlanFormatter
        results = orchestrator.validate(**filters)
        formatter = PlanFormatter(console, verbose=verbose)
        formatter.format_validation_results(results)
        has_errors = any(errors for errors in results.values() if errors)
        ctx.exit(1 if has_errors else 0)
    except Exception as e:
        console.print(f"[red]✗ Error during validation: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        ctx.exit(1)
```

**`commands/plan.py`** (from `command_plan`, lines 349-383):
```python
"""talonctl plan — show what changes would be made."""

import click

from talonctl.commands._common import (
    console, filter_options, state_options, remote_state_options,
    parse_filters, init_orchestrator,
)


@click.command()
@filter_options
@state_options
@remote_state_options
@click.option('--skip-query-validation', is_flag=True, help='Skip CQL query validation')
@click.option('--validation-workers', type=int, default=20, help='Parallel validation workers')
@click.pass_context
def plan(ctx, resources, tags, names, state_file, remote_state,
         remote_state_search_domain, remote_state_filename,
         skip_query_validation, validation_workers):
    """Show what changes would be made."""
    console.print("[bold blue]Generating deployment plan...[/bold blue]\n")
    verbose = ctx.obj.get('verbose', False)

    orchestrator = init_orchestrator(
        state_file=state_file,
        remote_state=remote_state,
        remote_state_search_domain=remote_state_search_domain,
        remote_state_filename=remote_state_filename,
    )
    filters = parse_filters(resources, tags, names)
    filters['skip_query_validation'] = skip_query_validation
    filters['validation_workers'] = validation_workers

    try:
        from talonctl.core import PlanFormatter
        result = orchestrator.plan(**filters)
        formatter = PlanFormatter(console, verbose=verbose)
        formatter.format_plan(result)

        if result.query_validation_results:
            invalid = sum(1 for r in result.query_validation_results if not r.is_valid)
            if invalid > 0:
                console.print("[red]✗ Plan blocked due to invalid queries[/red]\n")
                ctx.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Error generating plan: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        ctx.exit(1)
```

**`commands/apply.py`** (from `command_apply`, lines 386-465):
```python
"""talonctl apply — execute planned changes."""

import click
from rich.prompt import Confirm

from talonctl.commands._common import (
    console, filter_options, state_options, remote_state_options,
    parse_filters, init_orchestrator,
)


@click.command()
@filter_options
@state_options
@remote_state_options
@click.option('--auto-approve', is_flag=True, help='Skip confirmation prompts')
@click.option('--parallel', type=int, default=10, help='Max parallel operations')
@click.option('--skip-query-validation', is_flag=True, help='Skip CQL query validation')
@click.option('--validation-workers', type=int, default=20, help='Parallel validation workers')
@click.pass_context
def apply(ctx, resources, tags, names, state_file, remote_state,
          remote_state_search_domain, remote_state_filename,
          auto_approve, parallel, skip_query_validation, validation_workers):
    """Execute planned changes."""
    console.print("[bold blue]Applying changes...[/bold blue]\n")
    verbose = ctx.obj.get('verbose', False)

    orchestrator = init_orchestrator(
        state_file=state_file,
        remote_state=remote_state,
        remote_state_search_domain=remote_state_search_domain,
        remote_state_filename=remote_state_filename,
    )
    filters = parse_filters(resources, tags, names)
    filters['skip_query_validation'] = skip_query_validation
    filters['validation_workers'] = validation_workers

    try:
        from talonctl.core import PlanFormatter, ResourceAction
        plan_result = orchestrator.plan(**filters)
        formatter = PlanFormatter(console, verbose=verbose)
        formatter.format_plan(plan_result)

        if plan_result.query_validation_results:
            invalid = sum(1 for r in plan_result.query_validation_results if not r.is_valid)
            if invalid > 0:
                console.print("[red]✗ Apply blocked due to invalid queries[/red]\n")
                ctx.exit(1)
                return

        changes_to_apply = [c for c in plan_result.changes if c.action != ResourceAction.NO_CHANGE]
        if not changes_to_apply:
            console.print("[dim]No changes to apply.[/dim]\n")
            return

        if not auto_approve:
            if not Confirm.ask("\n[yellow]Do you want to apply these changes?[/yellow]"):
                console.print("[dim]Apply cancelled.[/dim]\n")
                return

        console.print("\n[bold blue]Deploying resources...[/bold blue]\n")
        result = orchestrator.apply(plan=plan_result, parallel=parallel, auto_approve=auto_approve)

        if result.success:
            console.print(
                f"\n[green]✓ Deployment successful![/green] "
                f"Deployed {len(result.deployed)} resources in {result.duration:.1f}s\n"
            )
        else:
            console.print(
                f"\n[red]✗ Deployment failed.[/red] "
                f"{len(result.deployed)} deployed, {len(result.failed)} failed, "
                f"{len(result.skipped)} skipped\n"
            )
            if result.failed:
                console.print("[bold red]Failed resources:[/bold red]")
                for resource_id, error in result.failed:
                    console.print(f"  • {resource_id}: {error}")
                console.print()
            ctx.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Error during apply: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        ctx.exit(1)
```

For the remaining commands, follow the same pattern. Read `resource_deploy.py` for each handler and translate to a Click command:

**`commands/show.py`** — from `command_show` (lines 494+)
**`commands/sync.py`** — from `command_sync`
**`commands/drift.py`** — from `command_drift`
**`commands/destroy.py`** — from `command_destroy`
**`commands/import_cmd.py`** — from `command_import` (note: the Click command name is `import_cmd` but registered as `import`)
**`commands/publish.py`** — from `command_publish`
**`commands/validate_query.py`** — from `command_validate_query` (lines 721-778)

Each follows the same structure:
1. Click command decorator with appropriate options
2. Pass `ctx` for verbose flag and exit codes
3. Call `init_orchestrator()` and `parse_filters()` from `_common`
4. Core logic copied from the original handler

**`commands/discover.py`** — thin wrapper around `scripts/template_discovery.py`:
```python
"""talonctl discover — find new detection templates."""

import click

from talonctl.commands._common import console


@click.command()
@click.option('--vendors', type=str, help='Vendor filter (comma-separated)')
@click.option('--max-templates', type=int, default=100, help='Max templates to discover')
@click.pass_context
def discover(ctx, vendors, max_templates):
    """Discover new detection templates from the CrowdStrike template library."""
    console.print("[bold blue]Discovering templates...[/bold blue]\n")
    # Import and delegate to existing template_discovery module
    from talonctl.core.template_discovery import TemplateDiscovery
    # ... delegate to existing discovery logic
    console.print("[dim]Template discovery not yet migrated to CLI.[/dim]")
```

**`commands/backup.py`** — thin wrapper:
```python
"""talonctl backup — create a state backup."""

import click

from talonctl.commands._common import console


@click.command()
@click.pass_context
def backup(ctx):
    """Create a backup of the current state file."""
    console.print("[bold blue]Creating backup...[/bold blue]\n")
    console.print("[dim]Backup not yet migrated to CLI.[/dim]")
```

Note: `discover` and `backup` are secondary commands. If the migration of their full logic is too complex for this task, leave them as stubs with a "not yet migrated" message and a TODO comment. The primary commands (validate, plan, apply, import, sync, drift, show, destroy, publish, validate-query) must be fully implemented.

- [ ] **Step 4: Verify CLI starts**

```bash
pip install -e .
talonctl --help
talonctl validate --help
```

Expected: Help output listing all commands and options.

- [ ] **Step 5: Commit**

```bash
git add src/talonctl/cli.py src/talonctl/commands/
git commit -m "feat: add Click CLI with command modules"
```

---

### Task 8: Create talonctl init command

**Files:**
- Create: `src/talonctl/commands/init.py`
- Create: `src/talonctl/templates/init/` (template files)
- Create: `tests/unit/test_init_command.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/test_init_command.py`:
```python
"""Tests for talonctl init command."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from talonctl.cli import cli


class TestInitCommand:
    def test_creates_project_structure(self, tmp_path):
        """talonctl init should create the full project directory structure."""
        runner = CliRunner()
        result = runner.invoke(cli, ['init', str(tmp_path / 'myproject')])
        assert result.exit_code == 0

        project = tmp_path / 'myproject'
        assert (project / 'resources' / 'detections').is_dir()
        assert (project / 'resources' / 'saved_searches').is_dir()
        assert (project / 'resources' / 'dashboards').is_dir()
        assert (project / 'resources' / 'workflows').is_dir()
        assert (project / 'resources' / 'lookup_files').is_dir()
        assert (project / 'resources' / 'rtr_scripts').is_dir()
        assert (project / 'resources' / 'rtr_put_files').is_dir()
        assert (project / 'knowledge' / 'INDEX.md').is_file()
        assert (project / 'knowledge' / 'context' / 'environmental-context.md').is_file()
        assert (project / 'knowledge' / 'techniques' / 'investigation-techniques.md').is_file()
        assert (project / 'knowledge' / 'tuning' / 'tuning-backlog.md').is_file()
        assert (project / 'knowledge' / 'tuning' / 'tuning-log.md').is_file()
        assert (project / 'knowledge' / 'metrics' / 'detection-metrics.jsonl').is_file()
        assert (project / 'knowledge' / 'ideas' / 'detection-ideas.md').is_file()
        assert (project / '.crowdstrike' / 'deployed_state.json').is_file()
        assert (project / '.gitignore').is_file()

    def test_creates_valid_state_file(self, tmp_path):
        """State file should be valid JSON with correct format version."""
        import json
        runner = CliRunner()
        runner.invoke(cli, ['init', str(tmp_path / 'myproject')])
        state = json.loads((tmp_path / 'myproject' / '.crowdstrike' / 'deployed_state.json').read_text())
        assert state['format_version'] == '3.0'
        assert state['resources'] == {}

    def test_refuses_existing_directory_with_crowdstrike(self, tmp_path):
        """Should refuse to init if .crowdstrike/ already exists."""
        project = tmp_path / 'existing'
        project.mkdir()
        (project / '.crowdstrike').mkdir()
        runner = CliRunner()
        result = runner.invoke(cli, ['init', str(project)])
        assert result.exit_code != 0
        assert 'already' in result.output.lower()

    def test_init_current_directory(self, tmp_path):
        """talonctl init with no path should use current directory."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            result = runner.invoke(cli, ['init'])
            assert result.exit_code == 0
            assert (Path(td) / '.crowdstrike' / 'deployed_state.json').is_file()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/unit/test_init_command.py -v
```
Expected: FAIL

- [ ] **Step 3: Create init template files**

Copy the knowledge base templates from `knowledge/` into `src/talonctl/templates/init/`. These are the files `talonctl init` will create. Use simplified versions (just headers and format documentation, no environment-specific content):

Create each template file under `src/talonctl/templates/init/knowledge/`:
- `INDEX.md` — empty routing table template
- `context/environmental-context.md` — placeholder prompting user to fill in
- `techniques/investigation-techniques.md` — generic template
- `tuning/tuning-backlog.md` — empty with format docs
- `tuning/tuning-log.md` — empty with format docs
- `metrics/detection-metrics.jsonl` — empty file
- `ideas/detection-ideas.md` — empty with format docs

Also create:
- `src/talonctl/templates/init/state.json` — `{"format_version": "3.0", "resources": {}}`
- `src/talonctl/templates/init/gitignore` — standard .gitignore content

- [ ] **Step 4: Implement init command**

`src/talonctl/commands/init.py`:
```python
"""talonctl init — scaffold a new talonctl project."""

import json
import shutil
from importlib import resources as pkg_resources
from pathlib import Path

import click

from talonctl.commands._common import console


RESOURCE_DIRS = [
    'detections', 'saved_searches', 'dashboards', 'workflows',
    'lookup_files', 'rtr_scripts', 'rtr_put_files',
]


@click.command()
@click.argument('path', required=False, type=click.Path())
@click.pass_context
def init(ctx, path):
    """Scaffold a new talonctl project."""
    project_dir = Path(path) if path else Path.cwd()
    project_dir = project_dir.resolve()

    # Refuse if already initialized
    if (project_dir / '.crowdstrike').exists():
        console.print(f"[red]✗ Directory already contains a talonctl project (.crowdstrike/ exists)[/red]")
        ctx.exit(1)
        return

    project_dir.mkdir(parents=True, exist_ok=True)

    # Create resource directories
    for resource_type in RESOURCE_DIRS:
        (project_dir / 'resources' / resource_type).mkdir(parents=True, exist_ok=True)

    # Create knowledge directories
    for subdir in ['context', 'patterns', 'techniques', 'tuning', 'metrics', 'hunts', 'ideas']:
        (project_dir / 'knowledge' / subdir).mkdir(parents=True, exist_ok=True)

    # Copy template files from bundled templates
    templates_dir = Path(__file__).parent.parent / 'templates' / 'init'
    _copy_templates(templates_dir, project_dir)

    # Create state file
    (project_dir / '.crowdstrike').mkdir(exist_ok=True)
    state = {"format_version": "3.0", "resources": {}}
    (project_dir / '.crowdstrike' / 'deployed_state.json').write_text(
        json.dumps(state, indent=2) + '\n'
    )

    # Create .gitignore
    gitignore_template = templates_dir / 'gitignore'
    if gitignore_template.exists():
        shutil.copy2(gitignore_template, project_dir / '.gitignore')

    console.print(f"[green]✓ Initialized talonctl project at {project_dir}[/green]\n")
    console.print("Next steps:")
    console.print("  1. Edit knowledge/context/environmental-context.md with your environment details")
    console.print("  2. Add detection templates to resources/detections/")
    console.print("  3. Run [bold]talonctl validate[/bold] to check your templates")
    console.print("  4. Run [bold]talonctl plan[/bold] to preview changes\n")


def _copy_templates(templates_dir: Path, project_dir: Path):
    """Copy template files from bundled templates to project directory."""
    if not templates_dir.exists():
        return
    for template_file in templates_dir.rglob('*'):
        if template_file.is_file() and template_file.name != 'gitignore' and template_file.name != 'state.json':
            relative = template_file.relative_to(templates_dir)
            target = project_dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(template_file, target)
```

- [ ] **Step 5: Run tests**

```bash
pytest tests/unit/test_init_command.py -v
```
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/talonctl/commands/init.py src/talonctl/templates/ tests/unit/test_init_command.py
git commit -m "feat: add talonctl init command for project scaffolding"
```

---

### Task 9: Update existing tests

**Files:**
- Modify: `tests/conftest.py`
- Modify: All test files in `tests/unit/`

- [ ] **Step 1: Update `tests/conftest.py`**

Remove the sys.path manipulation:

```python
# Remove these lines:
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../scripts'))
```

If conftest.py has other fixtures, keep those but update any imports from `scripts.*` to `talonctl.*`.

- [ ] **Step 2: Update test imports — pattern**

Every test file has imports like:
```python
# Before:
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from providers.detection_provider import DetectionProvider
from core import ResourceAction

# After:
from talonctl.providers.detection_provider import DetectionProvider
from talonctl.core import ResourceAction
```

Remove all `sys.path` manipulation and `SCRIPTS_DIR` definitions.

Apply to each test file in `tests/unit/`:
- `test_detection_provider.py`
- `test_deployment_orchestrator.py`
- `test_state_manager.py`
- `test_provider_adapter.py`
- `test_state_synchronizer.py`
- `test_deploy_lock.py`
- `test_dependency_validator.py`
- `test_saved_search_provider.py`
- `test_lookup_file_provider.py`
- `test_workflow_provider.py`
- `test_rtr_script_provider.py`
- `test_rtr_put_file_provider.py`
- `test_resource_graph.py`
- `test_template_discovery.py`
- `test_soc_metrics.py`
- `test_detection_health.py`

Also `tests/test_dashboard_provider.py` (in tests/ root).

- [ ] **Step 3: Run full test suite**

```bash
pip install -e .[dev]
pytest tests/ -v --tb=short
```

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git commit -am "refactor: update test imports for package structure"
```

---

### Task 10: Remove old scripts and requirements.txt

**Files:**
- Delete: `scripts/resource_deploy.py`
- Delete: `scripts/common.py`
- Delete: `requirements.txt`
- Delete: `pytest.ini` (config now in pyproject.toml)

- [ ] **Step 1: Delete files replaced by the package**

```bash
git rm scripts/resource_deploy.py
git rm scripts/common.py
git rm requirements.txt
git rm pytest.ini
```

- [ ] **Step 2: Verify remaining scripts/ files still work**

`scripts/setup.py`, `scripts/detection_health.py`, `scripts/soc_metrics.py` stay — verify they don't import from deleted files. If they import from `common`, update them to use `talonctl.utils.auth` etc., or leave them as standalone scripts that users run after `pip install talonctl`.

- [ ] **Step 3: Commit**

```bash
git commit -m "chore: remove old entry points replaced by talonctl CLI"
```

---

### Task 11: Update CI workflows

**Files:**
- Modify: `.github/workflows/plan-and-deploy.yml`
- Modify: `.github/workflows/weekly-template-discovery.yml`

- [ ] **Step 1: Update plan-and-deploy.yml**

Replace dependency installation:
```yaml
# Before:
- name: Install dependencies
  run: pip install -r requirements.txt

# After:
- name: Install dependencies
  run: pip install -e .[dev]
```

Replace command invocations:
```yaml
# Before:
- name: Run unit tests
  run: pytest tests/unit/ -v --tb=short

# After (same — pytest still works):
- name: Run unit tests
  run: pytest tests/unit/ -v --tb=short

# Before:
- name: Plan
  run: python scripts/resource_deploy.py plan ...

# After:
- name: Plan
  run: talonctl plan ...

# Before:
- name: Apply
  run: python scripts/resource_deploy.py apply --auto-approve ...

# After:
- name: Apply
  run: talonctl apply --auto-approve ...
```

- [ ] **Step 2: Update weekly-template-discovery.yml**

Same pattern — replace `pip install -r requirements.txt` with `pip install -e .` and `python scripts/template_discovery.py` with `talonctl discover` (if migrated) or adjust the path.

- [ ] **Step 3: Commit**

```bash
git commit -am "ci: update workflows for talonctl CLI"
```

---

### Task 12: Update documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `CLAUDE.integrated.md`
- Modify: `GETTING_STARTED.md`

- [ ] **Step 1: Update README.md**

Rewrite for pip install audience:
- Installation: `pip install git+https://github.com/willwebster5/talonctl.git`
- Quick start: `talonctl init`, `talonctl validate`, `talonctl plan`
- Remove references to `python scripts/resource_deploy.py`
- Update project structure diagram to show `src/talonctl/` layout
- Add link to talonctl-demo for a complete example

- [ ] **Step 2: Update CLAUDE.md**

Replace all `python scripts/resource_deploy.py` references with `talonctl` commands. Update project structure section.

- [ ] **Step 3: Update CLAUDE.integrated.md**

Same changes as CLAUDE.md, plus update any skill references to match new paths.

- [ ] **Step 4: Update GETTING_STARTED.md**

Replace virtual environment / requirements.txt setup with `pip install talonctl`. Update command examples.

- [ ] **Step 5: Commit**

```bash
git commit -am "docs: update documentation for pip-installable CLI"
```

---

### Task 13: Final verification

- [ ] **Step 1: Clean install test**

```bash
pip uninstall talonctl -y
pip install -e .[dev]
talonctl --help
talonctl --version
```

Expected: Shows version 1.0.0 and all commands.

- [ ] **Step 2: Run full test suite**

```bash
pytest tests/ -v --tb=short
```

Expected: All tests pass.

- [ ] **Step 3: Test init command end-to-end**

```bash
cd /tmp
talonctl init test-project
ls -la test-project/
talonctl validate  # should work from the new project
rm -rf test-project
```

- [ ] **Step 4: Verify no stale imports**

```bash
grep -r "from scripts\.\|from core\.\|from providers\.\|from utils\.\|from common " src/ tests/ --include="*.py" | grep -v "talonctl\." | grep -v "__pycache__"
```

Expected: No output (all bare imports should be gone).

- [ ] **Step 5: Lint check**

```bash
ruff check src/ tests/ || true
```

Fix any import ordering issues.

- [ ] **Step 6: Final commit if needed**

Only if fixes were required during verification.
