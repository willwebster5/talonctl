# Scripts Directory

This directory contains the core deployment infrastructure for managing CrowdStrike NGSIEM resources through Infrastructure as Code (IaC).

## Directory Structure

```
scripts/
├── resource_deploy.py         # Unified CLI for all resource types
├── template_discovery.py      # CrowdStrike template discovery tool
├── create_backup.py           # State backup utility
├── common.py                  # Centralized path management and imports
├── core/                      # Core infrastructure components
│   ├── base_provider.py       # BaseResourceProvider interface
│   ├── state_manager.py       # State management (v3.0)
│   ├── resource_graph.py      # Dependency resolution
│   ├── deployment_orchestrator.py  # Deployment coordination
│   ├── plan_formatter.py      # Terraform-style output formatting
│   ├── provider_adapter.py    # Provider adapters
│   ├── provider_registry.py   # Provider registration
│   └── template_discovery.py  # Template discovery engine
├── providers/                 # Resource provider implementations
│   ├── detection_provider.py  # Detection rule management
│   ├── workflow_provider.py   # SOAR workflow management
│   ├── saved_search_provider.py    # Saved search management
│   ├── lookup_file_provider.py     # Lookup file management
│   ├── rtr_script_provider.py      # RTR script management
│   └── rtr_put_file_provider.py    # RTR put file management
└── utils/                     # Utility scripts
    ├── auth.py                # API authentication
    ├── create_detection.py    # Manual detection creation
    ├── workflow_generator.py  # Workflow generation
    ├── fql_helper.py          # FQL query utilities
    ├── ngsiem_files.py        # NGSIEM file operations
    ├── metrics_collector.py   # Deployment metrics
    └── deployment_utils.py    # General utilities
```

## Main Scripts

### resource_deploy.py
**Unified CLI for all resource management** - Terraform-like deployment workflow for all 6 resource types.

```bash
# Validate all templates (no API calls)
python scripts/resource_deploy.py validate

# Preview changes
python scripts/resource_deploy.py plan

# Apply changes
python scripts/resource_deploy.py apply

# Show current state
python scripts/resource_deploy.py show

# Sync with CrowdStrike
python scripts/resource_deploy.py sync

# Detect configuration drift
python scripts/resource_deploy.py drift
```

**Filtering options:**
```bash
# Deploy specific resource types
python scripts/resource_deploy.py apply --resources=detection,saved_search

# Deploy resources with specific tags
python scripts/resource_deploy.py apply --tags=aws,authentication

# Deploy resources matching name patterns
python scripts/resource_deploy.py apply --names=aws_*,*_login
```

See [Main README](../README.md#-quick-start) for complete usage guide.

### template_discovery.py
**Automated CrowdStrike template discovery** - Discovers and exports existing templates from CrowdStrike.

```bash
# Discover all templates
python scripts/template_discovery.py

# Filter by vendor
python scripts/template_discovery.py --vendors aws microsoft

# Export to directory
python scripts/template_discovery.py --output templates_review/
```

See [Template Discovery Guide](../documentation/advanced/template-discovery.md) for details.

### create_backup.py
**State backup utility** - Creates backups of deployment state before production deployments.

```bash
# Create state backup
python scripts/create_backup.py create

# List backups
python scripts/create_backup.py list

# Restore from backup
python scripts/create_backup.py restore --backup-id <id>
```

## Core Infrastructure (`core/`)

The `core/` directory contains the foundational infrastructure that powers the unified IaC system:

- **BaseResourceProvider** - Abstract interface all providers implement
- **StateManager** - Manages v3.0 state file with multi-resource support
- **ResourceGraph** - Dependency resolution and topological sorting
- **DeploymentOrchestrator** - Coordinates deployment across providers
- **PlanFormatter** - Terraform-style plan output

See [Core Infrastructure README](core/README.md) for architecture details.

## Resource Providers (`providers/`)

Each provider implements the `BaseResourceProvider` interface and manages a specific resource type:

| Provider | Resource Type | CrowdStrike API |
|----------|---------------|-----------------|
| DetectionProvider | Detection rules | Custom IOA API |
| WorkflowProvider | SOAR workflows | Workflows API |
| SavedSearchProvider | Saved searches | Saved Searches API |
| LookupFileProvider | Lookup files | Lookup Tables API |
| RTRScriptProvider | RTR scripts | RTR Admin API |
| RTRPutFileProvider | RTR put files | RTR Admin API |

See [Provider Development Guide](providers/README.md) for creating new providers.

## Utility Scripts (`utils/`)

### auth.py
API authentication and FalconPy client management:
```python
from scripts.utils.auth import get_falcon_client

falcon_client = get_falcon_client()
```

### create_detection.py
Create individual detection rules manually (bypasses IaC workflow):
```bash
python scripts/utils/create_detection.py --template resources/detections/aws/example.yaml
```

**Note:** Prefer using `resource_deploy.py` for production deployments.

### workflow_generator.py
Generate SOAR workflow configurations from detection templates:
```bash
python scripts/utils/workflow_generator.py --detection resources/detections/aws/example.yaml
```

### fql_helper.py
FQL query utilities and validation:
```python
from scripts.utils.fql_helper import validate_fql_query

errors = validate_fql_query(query_string)
```

## CI/CD Integration

The scripts are designed for GitHub Actions automation:

```yaml
# .github/workflows/deploy.yml
- name: Validate Templates
  run: python scripts/resource_deploy.py validate

- name: Plan Deployment
  run: python scripts/resource_deploy.py plan

- name: Apply Changes
  run: python scripts/resource_deploy.py apply --auto-approve
```

See [GitHub Setup Guide](../documentation/deployment/github-setup.md) for CI/CD configuration.

## Development

### Running Tests

```bash
# Unit tests (fast, no API required)
pytest tests/unit/ -v

# Integration tests (slow, requires API credentials)
pytest tests/integration/ --integration -v

# With coverage
pytest tests/unit/ --cov=scripts --cov-report=html
```

### Adding New Providers

1. Create provider class in `providers/` inheriting from `BaseResourceProvider`
2. Implement all abstract methods
3. Register in `resource_deploy.py`
4. Write unit and integration tests
5. Create resource template README

See [Provider Development Guide](providers/README.md) for step-by-step instructions.

## Important Notes

1. **DO NOT** move core scripts from `scripts/` directory - they are referenced by GitHub workflows
2. All scripts use centralized import system in `common.py` for reliable path management
3. Providers are registered dynamically - new providers are automatically discovered
4. State file is managed centrally by StateManager - do not manually edit `.crowdstrike/deployed_state.json`

## Path Management

The `common.py` module provides standardized path definitions:

```python
from scripts.common import (
    REPO_ROOT,
    RESOURCES_DIR,
    STATE_FILE,
    DETECTIONS_DIR,
    WORKFLOWS_DIR
)
```

Use these constants instead of hardcoded paths for portability.

---

**Last Updated:** 2025-10-27
