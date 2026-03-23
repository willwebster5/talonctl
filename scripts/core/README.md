# Core Infrastructure for Unified IaC System

This package provides the foundational components for the unified CrowdStrike resource management system.

## Components

### BaseResourceProvider

Abstract base class that all resource providers must implement. Defines the interface for:
- Template validation
- Remote state fetching
- Change planning (create/update/delete)
- Change application
- Dependency extraction
- Content hashing

**Usage:**
```python
from core import BaseResourceProvider, ResourceAction, ResourceChange

class MyProvider(BaseResourceProvider):
    def get_resource_type(self) -> str:
        return "my_resource"

    def validate_template(self, template: Dict) -> List[str]:
        # Validation logic
        return []  # Empty list = valid

    # Implement other abstract methods...
```

### ResourceGraph

Manages dependency relationships between resources using a directed acyclic graph (DAG).

**Features:**
- Dependency tracking (resource A depends on resource B)
- Cycle detection (prevents circular dependencies)
- Topological sorting (determines safe deployment order)
- Deployment wave calculation (groups resources that can deploy in parallel)

**Usage:**
```python
from core import ResourceGraph

graph = ResourceGraph()
graph.add_dependency("workflow.notify", "detection.alert")
graph.add_dependency("detection.alert", "saved_search.find")

# Get deployment waves (parallel deployment groups)
waves = graph.get_deployment_waves()
# [[saved_search.find], [detection.alert], [workflow.notify]]

# Detect cycles
cycles = graph.detect_cycles()
if cycles:
    print(f"Circular dependency: {cycles[0]}")
```

### StateManager

Manages the unified state file for all deployed resources across all providers.

**Features:**
- v3.0 state format supporting multiple resource types
- Automatic migration from v2.0 (detection-only) to v3.0
- CRUD operations for resources
- Resource graph persistence
- Deployment metadata tracking

**State Format:**
```json
{
  "version": "3.0",
  "last_updated": "ISO8601",
  "metadata": {
    "deployed_by": "user@example.com",
    "environment": "production"
  },
  "resources": {
    "detection": {
      "aws_root_login": { ... }
    },
    "workflow": {
      "aws_root_login_notify": { ... }
    }
  },
  "resource_graph": {
    "nodes": [...],
    "edges": [...]
  }
}
```

**Usage:**
```python
from core import StateManager, ResourceState
from pathlib import Path

manager = StateManager(Path(".crowdstrike/deployed_state.json"))

# Add a resource
resource = ResourceState(
    type="detection",
    id="rule123",
    content_hash="abc123",
    template_path="resources/detections/aws/test.yaml",
    deployed_at=datetime.now().isoformat(),
    last_modified=datetime.now().isoformat(),
    provider_metadata={"rule_id": "rule123"},
    dependencies=["saved_search.aws_accounts"]
)

manager.set_resource("detection", "test_rule", resource)
manager.save()

# Retrieve a resource
resource = manager.get_resource("detection", "test_rule")

# Get resource graph
graph = manager.get_resource_graph()
```

### ProviderRegistry

Manages registration and retrieval of resource providers.

**Features:**
- Dynamic provider registration
- Provider configuration management
- Provider instance creation with dependency injection

**Usage:**
```python
from core import ProviderRegistry, BaseResourceProvider

registry = ProviderRegistry()

# Register a provider
registry.register("detection", DetectionProvider, config={"timeout": 30})

# Create provider instance
provider = registry.create_provider("detection", falcon_client)

# Check registration
if "detection" in registry:
    print(f"Detection provider available")
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  DeploymentOrchestrator                 │
│  (Coordinates deployment across all resource types)     │
└────────────┬────────────────────────────────────────────┘
             │
    ┌────────┼─────────────────────┐
    │        │                     │
    ▼        ▼                     ▼
┌────────┐ ┌──────────┐    ┌──────────────┐
│ State  │ │ Resource │    │   Provider   │
│Manager │ │  Graph   │    │   Registry   │
└────────┘ └──────────┘    └──────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             ┌────────────┐ ┌──────────┐ ┌──────────┐
             │ Detection  │ │ Workflow │ │  Saved   │
             │ Provider   │ │ Provider │ │  Search  │
             └────────────┘ └──────────┘ └──────────┘
```

## Testing

Unit tests are provided in `tests/unit/`:
- `test_resource_graph.py` - Tests for dependency graph
- `test_state_manager.py` - Tests for state management
- `test_provider_registry.py` - Tests for provider registry

Run tests:
```bash
pytest tests/unit/ -v
```

## Migration from v2.0

StateManager automatically migrates v2.0 state files to v3.0 format:

**v2.0 format** (detection-only):
```json
{
  "last_updated": "...",
  "rules": {
    "rule_name": {
      "rule_id": "...",
      "content_hash": "...",
      "workflow_created": true,
      "workflow_id": "..."
    }
  }
}
```

**v3.0 format** (multi-resource):
- Detections moved to `resources.detection`
- Workflows moved to `resources.workflow`
- Dependencies tracked in resource graph
- Backward compatible - no user action required

## Development Guidelines

### Adding a New Provider

1. Create provider class inheriting from `BaseResourceProvider`
2. Implement all abstract methods
3. Register provider with `ProviderRegistry`
4. Write unit tests
5. Add integration tests

Example:
```python
from core import BaseResourceProvider, register_provider

class MyResourceProvider(BaseResourceProvider):
    def get_resource_type(self) -> str:
        return "my_resource"

    # Implement all abstract methods...

# Register with global registry
register_provider("my_resource", MyResourceProvider)
```

### Dependency Format

Dependencies are referenced as `"type.name"`:
- `"detection.aws_root_login"`
- `"saved_search.aws_service_accounts"`
- `"lookup_file.trusted_ips"`
- `"workflow.incident_response"`

This allows cross-resource-type dependencies while maintaining uniqueness.

## Version History

- **v3.0.0** (2025-10-03): Initial release of unified IaC system
  - Multi-resource state management
  - Dependency graph with cycle detection
  - Provider registry system
  - Automatic v2→v3 migration
