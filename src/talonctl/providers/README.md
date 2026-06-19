# Resource Providers

This directory contains provider implementations for managing different CrowdStrike resource types through a unified Infrastructure as Code (IaC) interface.

## Overview

Providers are the bridge between YAML templates and CrowdStrike APIs. Each provider implements the `BaseResourceProvider` interface and handles:

- **Template Validation**: Ensuring templates are correctly formatted
- **Remote State Fetching**: Retrieving current state from CrowdStrike
- **Change Planning**: Determining what needs to be created, updated, or deleted
- **Change Application**: Executing planned changes via CrowdStrike APIs
- **Dependency Management**: Identifying resource dependencies
- **Content Hashing**: Detecting template changes

## Available Providers

| Provider | Resource Type | CrowdStrike API | Template Location |
|----------|---------------|-----------------|-------------------|
| **DetectionProvider** | NGSIEM detection rules | Custom IOA API | `resources/detections/` |
| **WorkflowProvider** | SOAR automation workflows _(temporarily deprecated — #23)_ | Workflows API | `resources/workflows/` |
| **SavedSearchProvider** | Reusable FQL query functions | Saved Searches API | `resources/saved_searches/` |
| **LookupFileProvider** | CSV/JSON correlation data | Lookup Tables API | `resources/lookup_files/` |
| **RTRScriptProvider** | Real-Time Response scripts | RTR Admin API | `resources/rtr_scripts/` |
| **RTRPutFileProvider** | RTR binary files | RTR Admin API | `resources/rtr_put_files/` |

## Provider Architecture

```
┌──────────────────────────────────────────────────────────┐
│              BaseResourceProvider (Abstract)             │
│                                                          │
│  + get_resource_type() -> str                           │
│  + validate_template(template) -> List[str]             │
│  + get_remote_resources() -> Dict[str, ResourceState]   │
│  + plan_changes(...) -> List[ResourceChange]            │
│  + apply_change(change) -> ResourceState                │
│  + extract_dependencies(template) -> List[str]          │
│  + compute_content_hash(template) -> str                │
└──────────────────────────────────────────────────────────┘
                          ▲
                          │ inherits
          ┌───────────────┼───────────────┐
          │               │               │
    ┌─────┴─────┐   ┌─────┴─────┐   ┌────┴────┐
    │ Detection │   │ Workflow  │   │  Saved  │
    │ Provider  │   │ Provider  │   │  Search │
    └───────────┘   └───────────┘   └─────────┘
```

## Creating a New Provider

### Step 1: Identify Requirements

Before creating a new provider, determine:

1. **What CrowdStrike API** will you use?
   - Check [CrowdStrike Swagger Docs](https://assets.falcon.us-2.crowdstrike.com/support/api/swagger-us2.html)
   - Identify available endpoints (list, create, update, delete)

2. **What template format** will you support?
   - Define required fields
   - Define optional fields
   - Create YAML schema

3. **What dependencies** might exist?
   - Does this resource type depend on others?
   - Can other resource types depend on this?

4. **What unique identifier** will you use?
   - CrowdStrike APIs use different ID schemes
   - Some use `id`, some use `rule_id`, some use `name`
   - Choose a consistent identifier for state tracking

### Step 2: Create Provider Skeleton

Create a new file in `scripts/providers/` (e.g., `my_resource_provider.py`):

```python
"""Provider for managing MyResource resources."""

from typing import Dict, List, Optional, Any
from datetime import datetime
import hashlib
import json

from scripts.core.base_provider import (
    BaseResourceProvider,
    ResourceState,
    ResourceChange,
    ResourceAction
)


class MyResourceProvider(BaseResourceProvider):
    """
    Provider for CrowdStrike MyResource management.

    Manages MyResource resources through the CrowdStrike API,
    supporting create, update, and delete operations.
    """

    def __init__(self, falcon_client):
        """
        Initialize the provider.

        Args:
            falcon_client: Authenticated FalconPy client instance
        """
        self.falcon = falcon_client
        self.logger = self._setup_logger()

    def get_resource_type(self) -> str:
        """Return the resource type identifier."""
        return "my_resource"

    def validate_template(self, template: Dict) -> List[str]:
        """
        Validate a resource template.

        Args:
            template: Template dictionary from YAML file

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Validate required fields
        required_fields = ["type", "name", "description"]
        for field in required_fields:
            if field not in template:
                errors.append(f"Missing required field: {field}")

        # Validate type matches
        if template.get("type") != "my_resource":
            errors.append(f"Invalid type: {template.get('type')}, expected 'my_resource'")

        # Add resource-specific validations
        # Example: validate severity is in range
        if "severity" in template:
            severity = template["severity"]
            if severity not in [10, 30, 50, 70, 90]:
                errors.append(f"Invalid severity: {severity}, must be one of [10, 30, 50, 70, 90]")

        return errors

    def get_remote_resources(self) -> Dict[str, ResourceState]:
        """
        Fetch all deployed resources from CrowdStrike.

        Returns:
            Dictionary mapping resource names to ResourceState objects
        """
        resources = {}

        try:
            # Call CrowdStrike API to list resources
            # Example: response = self.falcon.query_my_resources()

            # Parse response and create ResourceState objects
            # for item in response.get("resources", []):
            #     resource_state = ResourceState(
            #         type=self.get_resource_type(),
            #         id=item["id"],
            #         content_hash="",  # Not computed from API
            #         template_path="",  # Unknown from API
            #         deployed_at=item.get("created_timestamp", ""),
            #         last_modified=item.get("modified_timestamp", ""),
            #         provider_metadata={
            #             "name": item["name"],
            #             "description": item.get("description", ""),
            #         },
            #         dependencies=[]
            #     )
            #     resources[item["name"]] = resource_state

            pass

        except Exception as e:
            self.logger.error(f"Failed to fetch remote resources: {e}")
            raise

        return resources

    def plan_changes(
        self,
        templates: Dict[str, Dict],
        current_state: Dict[str, ResourceState]
    ) -> List[ResourceChange]:
        """
        Plan what changes need to be made.

        Args:
            templates: Dictionary of template name -> template data
            current_state: Dictionary of resource name -> current ResourceState

        Returns:
            List of ResourceChange objects describing planned changes
        """
        changes = []

        # Determine creates and updates
        for name, template in templates.items():
            content_hash = self.compute_content_hash(template)

            if name not in current_state:
                # Resource doesn't exist - CREATE
                changes.append(ResourceChange(
                    action=ResourceAction.CREATE,
                    resource_type=self.get_resource_type(),
                    resource_name=name,
                    current_state=None,
                    desired_template=template,
                    reason="Resource does not exist remotely"
                ))
            else:
                # Resource exists - check if UPDATE needed
                if current_state[name].content_hash != content_hash:
                    changes.append(ResourceChange(
                        action=ResourceAction.UPDATE,
                        resource_type=self.get_resource_type(),
                        resource_name=name,
                        current_state=current_state[name],
                        desired_template=template,
                        reason="Template content has changed"
                    ))

        # Determine deletes (resources in state but not in templates)
        for name in current_state:
            if name not in templates:
                changes.append(ResourceChange(
                    action=ResourceAction.DELETE,
                    resource_type=self.get_resource_type(),
                    resource_name=name,
                    current_state=current_state[name],
                    desired_template=None,
                    reason="Resource no longer in templates"
                ))

        return changes

    def apply_change(self, change: ResourceChange) -> ResourceState:
        """
        Apply a planned change via CrowdStrike API.

        Args:
            change: ResourceChange object describing the change to apply

        Returns:
            ResourceState object representing the new state after change
        """
        if change.action == ResourceAction.CREATE:
            return self._create_resource(change.desired_template)
        elif change.action == ResourceAction.UPDATE:
            return self._update_resource(change.current_state, change.desired_template)
        elif change.action == ResourceAction.DELETE:
            return self._delete_resource(change.current_state)
        else:
            raise ValueError(f"Unknown action: {change.action}")

    def _create_resource(self, template: Dict) -> ResourceState:
        """Create a new resource via API."""
        try:
            # Build API request payload
            payload = {
                "name": template["name"],
                "description": template["description"],
                # Add other fields from template
            }

            # Call CrowdStrike API
            # response = self.falcon.create_my_resource(body=payload)
            # resource_id = response["resources"][0]["id"]

            resource_id = "placeholder-id"  # Replace with actual API call

            # Return new ResourceState
            return ResourceState(
                type=self.get_resource_type(),
                id=resource_id,
                content_hash=self.compute_content_hash(template),
                template_path=template.get("_template_path", ""),
                deployed_at=datetime.now().isoformat(),
                last_modified=datetime.now().isoformat(),
                provider_metadata={
                    "name": template["name"],
                },
                dependencies=self.extract_dependencies(template)
            )

        except Exception as e:
            self.logger.error(f"Failed to create resource {template['name']}: {e}")
            raise

    def _update_resource(self, current: ResourceState, template: Dict) -> ResourceState:
        """Update an existing resource via API."""
        try:
            # Build API request payload
            payload = {
                "id": current.id,
                "name": template["name"],
                "description": template["description"],
                # Add other fields from template
            }

            # Call CrowdStrike API
            # response = self.falcon.update_my_resource(body=payload)

            # Return updated ResourceState
            return ResourceState(
                type=self.get_resource_type(),
                id=current.id,
                content_hash=self.compute_content_hash(template),
                template_path=template.get("_template_path", current.template_path),
                deployed_at=current.deployed_at,
                last_modified=datetime.now().isoformat(),
                provider_metadata={
                    "name": template["name"],
                },
                dependencies=self.extract_dependencies(template)
            )

        except Exception as e:
            self.logger.error(f"Failed to update resource {template['name']}: {e}")
            raise

    def _delete_resource(self, current: ResourceState) -> ResourceState:
        """Delete a resource via API."""
        try:
            # Call CrowdStrike API
            # response = self.falcon.delete_my_resource(ids=[current.id])

            self.logger.info(f"Deleted resource: {current.provider_metadata.get('name')}")

            # Return final state (will be removed from state file)
            return current

        except Exception as e:
            self.logger.error(f"Failed to delete resource {current.id}: {e}")
            raise

    def extract_dependencies(self, template: Dict) -> List[str]:
        """
        Extract resource dependencies from template.

        Dependencies are referenced as "type.name", for example:
        - "detection.aws_root_login"
        - "saved_search.aws_service_accounts"

        Args:
            template: Template dictionary

        Returns:
            List of dependency strings in "type.name" format
        """
        dependencies = []

        # Example: extract from dependencies field
        if "dependencies" in template:
            dependencies.extend(template["dependencies"])

        # Example: parse query for function calls
        # if "query" in template:
        #     query = template["query"]
        #     # Find $function_name() patterns
        #     import re
        #     matches = re.findall(r'\$(\w+)\(\)', query)
        #     for match in matches:
        #         dependencies.append(f"saved_search.{match}")

        return dependencies

    def compute_content_hash(self, template: Dict) -> str:
        """
        Compute a hash of the template content.

        Used to detect if template has changed since last deployment.

        Args:
            template: Template dictionary

        Returns:
            SHA256 hash of normalized template content
        """
        # Remove metadata fields that shouldn't affect hash
        hashable = {
            k: v for k, v in template.items()
            if not k.startswith("_")  # Ignore _template_path, etc.
        }

        # Normalize and hash
        content_str = json.dumps(hashable, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def _setup_logger(self):
        """Setup logging for this provider."""
        import logging
        logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        return logger
```

### Step 3: Register Provider

Update `scripts/providers/__init__.py` to register your provider:

```python
from .my_resource_provider import MyResourceProvider

__all__ = [
    "DetectionProvider",
    "WorkflowProvider",
    "SavedSearchProvider",
    "LookupFileProvider",
    "RTRScriptProvider",
    "RTRPutFileProvider",
    "MyResourceProvider",  # Add new provider
]
```

Update `scripts/resource_deploy.py` to instantiate your provider:

```python
# Add to initialize_providers() function
providers["my_resource"] = MyResourceProvider(falcon_client)
```

### Step 4: Create Template Directory and README

Create directory structure:
```bash
mkdir -p resources/my_resources
```

Create `resources/my_resources/README.md` with:
- Template format documentation
- Required and optional fields
- Usage examples
- Deployment instructions

### Step 5: Write Tests

Create unit tests in `tests/unit/providers/test_my_resource_provider.py`:

```python
import pytest
from scripts.providers.my_resource_provider import MyResourceProvider
from scripts.core.base_provider import ResourceState, ResourceChange, ResourceAction


class TestMyResourceProvider:
    @pytest.fixture
    def provider(self):
        """Create provider instance with mock client."""
        mock_client = MockFalconClient()
        return MyResourceProvider(mock_client)

    def test_get_resource_type(self, provider):
        """Test resource type identifier."""
        assert provider.get_resource_type() == "my_resource"

    def test_validate_template_valid(self, provider):
        """Test validation passes for valid template."""
        template = {
            "type": "my_resource",
            "name": "test_resource",
            "description": "Test description"
        }
        errors = provider.validate_template(template)
        assert errors == []

    def test_validate_template_missing_field(self, provider):
        """Test validation fails when required field missing."""
        template = {
            "type": "my_resource",
            "name": "test_resource"
            # Missing description
        }
        errors = provider.validate_template(template)
        assert len(errors) > 0
        assert any("description" in err for err in errors)

    def test_compute_content_hash(self, provider):
        """Test content hashing is consistent."""
        template1 = {"name": "test", "description": "desc"}
        template2 = {"description": "desc", "name": "test"}  # Different order

        hash1 = provider.compute_content_hash(template1)
        hash2 = provider.compute_content_hash(template2)

        assert hash1 == hash2  # Should be identical
        assert len(hash1) == 64  # SHA256 = 64 hex chars

    def test_extract_dependencies(self, provider):
        """Test dependency extraction."""
        template = {
            "name": "test",
            "dependencies": ["saved_search.aws_accounts", "lookup_file.users"]
        }
        deps = provider.extract_dependencies(template)
        assert "saved_search.aws_accounts" in deps
        assert "lookup_file.users" in deps
```

Create integration tests in `tests/integration/providers/test_my_resource_provider_integration.py`:

```python
import pytest
from scripts.providers.my_resource_provider import MyResourceProvider
from scripts.utils.auth import get_falcon_client


@pytest.mark.integration
class TestMyResourceProviderIntegration:
    @pytest.fixture
    def provider(self):
        """Create provider with real Falcon client."""
        falcon_client = get_falcon_client()
        return MyResourceProvider(falcon_client)

    @pytest.fixture
    def test_template(self):
        """Sample template for testing."""
        return {
            "type": "my_resource",
            "name": "test_resource_integration",
            "description": "Integration test resource",
        }

    def test_create_and_delete_resource(self, provider, test_template):
        """Test creating and deleting a resource."""
        # Create resource
        state = provider._create_resource(test_template)
        assert state.id is not None
        assert state.provider_metadata["name"] == test_template["name"]

        # Delete resource
        provider._delete_resource(state)

        # Verify deleted
        remote_resources = provider.get_remote_resources()
        assert test_template["name"] not in remote_resources
```

## Provider Development Guidelines

### Required Methods

All providers MUST implement these abstract methods from `BaseResourceProvider`:

| Method | Purpose | Return Type |
|--------|---------|-------------|
| `get_resource_type()` | Return resource type identifier | `str` |
| `validate_template(template)` | Validate template structure | `List[str]` (errors) |
| `get_remote_resources()` | Fetch current state from API | `Dict[str, ResourceState]` |
| `plan_changes(templates, state)` | Determine needed changes | `List[ResourceChange]` |
| `apply_change(change)` | Execute a change via API | `ResourceState` |
| `extract_dependencies(template)` | Find resource dependencies | `List[str]` |
| `compute_content_hash(template)` | Hash template for change detection | `str` |

### Best Practices

#### 1. Error Handling
```python
try:
    response = self.falcon.create_resource(body=payload)
    if response["status_code"] != 200:
        raise Exception(f"API error: {response['errors']}")
except Exception as e:
    self.logger.error(f"Failed to create resource: {e}")
    raise  # Re-raise to let orchestrator handle
```

#### 2. Logging
```python
self.logger.info(f"Creating resource: {template['name']}")
self.logger.debug(f"API payload: {json.dumps(payload, indent=2)}")
self.logger.error(f"Failed to update resource: {e}")
```

#### 3. Metadata Preservation
```python
# Store important metadata for troubleshooting
provider_metadata = {
    "name": template["name"],
    "api_id": resource_id,
    "created_by": template.get("metadata", {}).get("created_by"),
    "version": response.get("version"),
}
```

#### 4. Idempotency
```python
# Ensure updates are idempotent - safe to run multiple times
def _update_resource(self, current: ResourceState, template: Dict):
    # Check if update is actually needed
    if self._resources_match(current, template):
        self.logger.info(f"Resource {template['name']} unchanged, skipping update")
        return current

    # Proceed with update
    # ...
```

#### 5. Dependency Format
```python
# Always use "type.name" format for dependencies
dependencies = [
    "saved_search.aws_service_accounts",
    "lookup_file.entraid_users",
    "detection.aws_root_login"
]
```

### Testing Guidelines

#### Unit Tests (Fast, No API)
- Test validation logic
- Test content hashing
- Test dependency extraction
- Test change planning logic
- Use mock Falcon clients

#### Integration Tests (Slow, Requires API)
- Test actual API calls
- Test create/update/delete operations
- Test error handling with real API responses
- Use `@pytest.mark.integration` decorator
- Clean up test resources in teardown

Run tests:
```bash
# Unit tests only (fast)
pytest tests/unit/providers/test_my_resource_provider.py -v

# Integration tests (slow, requires API credentials)
pytest tests/integration/providers/ --integration -v
```

## Example: Examining Existing Providers

### Simple Provider: WorkflowProvider

The `workflow_provider.py` is a good starting point for learning:
- Simple template structure
- Straightforward API (create, delete only - no updates)
- Handles trigger dependencies (workflows depend on detections)

### Complex Provider: DetectionProvider

The `detection_provider.py` demonstrates advanced features:
- Complex validation (MITRE ATT&CK, severity levels, FQL queries)
- Multi-field identity (`rule_id` vs `id`)
- Real-time query validation against NGSIEM
- Workflow auto-generation integration

### File-Based Provider: RTRScriptProvider

The `rtr_script_provider.py` shows file handling:
- External file references (`file_path` in templates)
- Binary file uploads
- Platform-specific validation (Windows vs Linux)

## Common Patterns

### Pattern 1: External File References

Many resources reference external files (scripts, binaries, data files):

```python
def _load_file_content(self, template: Dict) -> bytes:
    """Load content from external file."""
    if "file_path" in template:
        file_path = Path(template["_template_path"]).parent / template["file_path"]
        return file_path.read_bytes()
    elif "content" in template:
        return template["content"].encode()
    else:
        raise ValueError("Template must have 'file_path' or 'content'")
```

### Pattern 2: Extracting Dependencies from Query Text

Saved searches and detections often reference other resources in FQL queries:

```python
def extract_dependencies(self, template: Dict) -> List[str]:
    """Extract dependencies from FQL query."""
    dependencies = []

    if "search" in template and "filter" in template["search"]:
        query = template["search"]["filter"]

        # Find $function_name() patterns (saved searches)
        import re
        matches = re.findall(r'\$(\w+)\(\)', query)
        for match in matches:
            dependencies.append(f"saved_search.{match}")

        # Find match(table="filename") patterns (lookup files)
        matches = re.findall(r'table="([^"]+)"', query)
        for match in matches:
            # Remove .csv extension
            name = match.replace(".csv", "").replace(".json", "")
            dependencies.append(f"lookup_file.{name}")

    return dependencies
```

### Pattern 3: Immutable Resources

Some CrowdStrike APIs don't support updates - only create/delete:

```python
def plan_changes(self, templates, current_state):
    """Plan changes for immutable resources."""
    changes = []

    for name, template in templates.items():
        content_hash = self.compute_content_hash(template)

        if name not in current_state:
            # CREATE
            changes.append(ResourceChange(
                action=ResourceAction.CREATE,
                resource_type=self.get_resource_type(),
                resource_name=name,
                current_state=None,
                desired_template=template,
                reason="Resource does not exist"
            ))
        else:
            # For immutable resources, content change = DELETE + CREATE
            if current_state[name].content_hash != content_hash:
                # DELETE old version
                changes.append(ResourceChange(
                    action=ResourceAction.DELETE,
                    resource_type=self.get_resource_type(),
                    resource_name=name,
                    current_state=current_state[name],
                    desired_template=None,
                    reason="Immutable resource changed - will recreate"
                ))
                # CREATE new version
                changes.append(ResourceChange(
                    action=ResourceAction.CREATE,
                    resource_type=self.get_resource_type(),
                    resource_name=name,
                    current_state=None,
                    desired_template=template,
                    reason="Recreating changed immutable resource"
                ))

    return changes
```

## Troubleshooting

### Provider Not Found
- Check provider is imported in `__init__.py`
- Verify provider is instantiated in `resource_deploy.py`
- Ensure `get_resource_type()` returns correct identifier

### Validation Failures
- Add detailed error messages in `validate_template()`
- Check template YAML syntax
- Verify required fields are present

### API Errors
- Enable debug logging: `--log-level DEBUG`
- Check FalconPy documentation for correct API usage
- Verify API credentials have required permissions
- Review CrowdStrike Swagger docs for payload format

### State Drift
- Verify `compute_content_hash()` excludes metadata fields
- Ensure hash computation is deterministic (use `sort_keys=True`)
- Check that `get_remote_resources()` fetches complete data

## Additional Resources

- **BaseProvider Interface**: See `scripts/core/base_provider.py`
- **State Management**: See `scripts/core/state_manager.py`
- **Dependency Graphs**: See `scripts/core/resource_graph.py`
- **FalconPy Documentation**: [https://falconpy.io](https://falconpy.io)
- **CrowdStrike API Docs**: [Swagger UI](https://assets.falcon.us-2.crowdstrike.com/support/api/swagger-us2.html)

---

**Last Updated:** 2025-10-27
