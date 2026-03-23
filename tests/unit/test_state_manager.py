"""
Unit tests for StateManager v3.0
"""

import pytest
import json
import tempfile
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from core.state_manager import StateManager, ResourceState


class TestStateManager:
    """Test suite for StateManager"""

    @pytest.fixture
    def temp_state_file(self):
        """Create a temporary state file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)
        yield temp_path
        if temp_path.exists():
            temp_path.unlink()

    def test_initialize_new_state(self, temp_state_file):
        """Test initialization of new state file"""
        manager = StateManager(temp_state_file)

        assert temp_state_file.exists()
        assert manager.get_resource_count() == 0

        state = manager.export_to_dict()
        assert state["version"] == "3.0"
        assert "resources" in state
        assert "resource_graph" in state

    def test_add_and_get_resource(self, temp_state_file):
        """Test adding and retrieving resources"""
        manager = StateManager(temp_state_file)

        resource = ResourceState(
            type="detection",
            id="rule123",
            content_hash="abc123",
            template_path="rules/test.yaml",
            deployed_at=datetime.now(timezone.utc).isoformat(),
            last_modified=datetime.now(timezone.utc).isoformat(),
            provider_metadata={"rule_id": "rule123"},
            dependencies=[]
        )

        manager.set_resource("detection", "test_rule", resource)

        retrieved = manager.get_resource("detection", "test_rule")
        assert retrieved is not None
        assert retrieved.id == "rule123"
        assert retrieved.content_hash == "abc123"

    def test_delete_resource(self, temp_state_file):
        """Test deleting resources"""
        manager = StateManager(temp_state_file)

        resource = ResourceState(
            type="detection",
            id="rule123",
            content_hash="abc123",
            template_path="rules/test.yaml",
            deployed_at=datetime.now(timezone.utc).isoformat(),
            last_modified=datetime.now(timezone.utc).isoformat(),
            provider_metadata={},
            dependencies=[]
        )

        manager.set_resource("detection", "test_rule", resource)
        assert manager.get_resource_count("detection") == 1

        deleted = manager.delete_resource("detection", "test_rule")
        assert deleted is True
        assert manager.get_resource_count("detection") == 0

        deleted_again = manager.delete_resource("detection", "test_rule")
        assert deleted_again is False

    def test_get_all_resources(self, temp_state_file):
        """Test retrieving all resources"""
        manager = StateManager(temp_state_file)

        # Add multiple resources of different types
        for i in range(3):
            resource = ResourceState(
                type="detection",
                id=f"rule{i}",
                content_hash=f"hash{i}",
                template_path=f"rules/test{i}.yaml",
                deployed_at=datetime.now(timezone.utc).isoformat(),
                last_modified=datetime.now(timezone.utc).isoformat(),
                provider_metadata={},
                dependencies=[]
            )
            manager.set_resource("detection", f"test_rule_{i}", resource)

        for i in range(2):
            resource = ResourceState(
                type="workflow",
                id=f"wf{i}",
                content_hash=f"hash{i}",
                template_path=f"workflows/test{i}.yaml",
                deployed_at=datetime.now(timezone.utc).isoformat(),
                last_modified=datetime.now(timezone.utc).isoformat(),
                provider_metadata={},
                dependencies=[]
            )
            manager.set_resource("workflow", f"test_workflow_{i}", resource)

        # Get all resources
        all_resources = manager.get_all_resources()
        assert len(all_resources) == 5

        # Get resources by type
        detections = manager.get_all_resources("detection")
        assert len(detections) == 3

        workflows = manager.get_all_resources("workflow")
        assert len(workflows) == 2

    def test_save_and_reload(self, temp_state_file):
        """Test saving state and reloading it"""
        manager = StateManager(temp_state_file)

        resource = ResourceState(
            type="detection",
            id="rule123",
            content_hash="abc123",
            template_path="rules/test.yaml",
            deployed_at=datetime.now(timezone.utc).isoformat(),
            last_modified=datetime.now(timezone.utc).isoformat(),
            provider_metadata={"rule_id": "rule123"},
            dependencies=[]
        )

        manager.set_resource("detection", "test_rule", resource)
        manager.save()

        # Create new manager instance pointing to same file
        manager2 = StateManager(temp_state_file)
        retrieved = manager2.get_resource("detection", "test_rule")

        assert retrieved is not None
        assert retrieved.id == "rule123"
        assert retrieved.content_hash == "abc123"

    def test_migrate_v2_to_v3(self, temp_state_file):
        """Test migration from v2.0 state format to v3.0"""
        # Create a v2.0 state file
        v2_state = {
            "last_updated": "2025-10-01T12:00:00Z",
            "rules": {
                "AWS - Root Login": {
                    "rule_id": "abc123",
                    "content_hash": "hash123",
                    "template_path": "rules/aws/root_login.yaml",
                    "deployed_at": "2025-10-01T12:00:00Z",
                    "last_modified": "2025-10-01T12:00:00Z",
                    "workflow_created": True,
                    "workflow_id": "wf123",
                    "workflow_name": "AWS Root Login Notify",
                    "workflow_enabled": True
                },
                "Another Detection": {
                    "rule_id": "def456",
                    "content_hash": "hash456",
                    "template_path": "rules/test.yaml",
                    "deployed_at": "2025-10-01T12:00:00Z",
                    "last_modified": "2025-10-01T12:00:00Z",
                    "workflow_created": False
                }
            },
            "workflow_last_synced": "2025-10-01T12:00:00Z"
        }

        # Write v2 state to file
        with open(temp_state_file, 'w') as f:
            json.dump(v2_state, f)

        # Load with StateManager (should auto-migrate)
        manager = StateManager(temp_state_file)

        # Verify migration
        state = manager.export_to_dict()
        assert state["version"] == "3.0"

        # Check detection was migrated
        detection = manager.get_resource("detection", "aws___root_login")
        assert detection is not None
        assert detection.id == "abc123"

        # Check workflow was migrated
        workflow = manager.get_resource("workflow", "aws___root_login_notify")
        assert workflow is not None
        assert workflow.id == "wf123"
        assert workflow.provider_metadata["workflow_name"] == "AWS Root Login Notify"
        assert workflow.provider_metadata["enabled"] is True

        # Check detection without workflow
        detection2 = manager.get_resource("detection", "another_detection")
        assert detection2 is not None
        assert detection2.id == "def456"

        # Check resource graph was created
        graph = manager.get_resource_graph()
        assert len(graph) > 0

    def test_resource_graph_management(self, temp_state_file):
        """Test managing resource dependency graph"""
        manager = StateManager(temp_state_file)

        from core.resource_graph import ResourceGraph

        graph = ResourceGraph()
        graph.add_dependency("workflow.notify", "detection.alert")
        graph.add_dependency("detection.alert", "saved_search.find")

        manager.set_resource_graph(graph)
        manager.save()

        # Reload and verify
        manager2 = StateManager(temp_state_file)
        retrieved_graph = manager2.get_resource_graph()

        assert len(retrieved_graph) == 3
        assert "workflow.notify" in retrieved_graph
        assert "detection.alert" in retrieved_graph
        assert "saved_search.find" in retrieved_graph

        deps = retrieved_graph.get_dependencies("workflow.notify")
        assert "detection.alert" in deps

    def test_metadata_management(self, temp_state_file):
        """Test deployment metadata management"""
        manager = StateManager(temp_state_file)

        metadata = {
            "deployed_by": "test@example.com",
            "deployment_id": "deploy123",
            "environment": "test"
        }

        manager.set_metadata(metadata)
        manager.save()

        # Reload and verify
        manager2 = StateManager(temp_state_file)
        retrieved_metadata = manager2.get_metadata()

        assert retrieved_metadata["deployed_by"] == "test@example.com"
        assert retrieved_metadata["deployment_id"] == "deploy123"
        assert retrieved_metadata["environment"] == "test"

    def test_sanitize_resource_name(self, temp_state_file):
        """Test resource name sanitization"""
        manager = StateManager(temp_state_file)

        # Test various name formats
        assert manager._sanitize_resource_name("AWS - Root Login") == "aws___root_login"
        assert manager._sanitize_resource_name("Test (Experimental)") == "test_experimental"
        assert manager._sanitize_resource_name("Simple") == "simple"
        assert manager._sanitize_resource_name("Multiple   Spaces") == "multiple_spaces"

    def test_atomic_state_write(self, temp_state_file):
        """Test that state writes are atomic and durable"""
        import os

        manager = StateManager(temp_state_file)

        # Add a resource
        resource = ResourceState(
            type="detection",
            id="rule123",
            content_hash="hash123",
            template_path="rules/test.yaml",
            deployed_at=datetime.now(timezone.utc).isoformat(),
            last_modified=datetime.now(timezone.utc).isoformat(),
            provider_metadata={"rule_id": "rule123"},
            dependencies=[]
        )
        manager.set_resource("detection", "test_rule", resource)

        # Save state
        manager.save()

        # Verify no temp file left behind
        temp_path = temp_state_file.with_suffix('.tmp')
        assert not temp_path.exists(), "Temp file should be cleaned up after save"

        # Verify state file exists and is valid JSON
        assert temp_state_file.exists()
        with open(temp_state_file, 'r') as f:
            state = json.load(f)
            assert state["version"] == "3.0"
            assert "detection" in state["resources"]

        # Verify file size is non-zero (fsync guarantee)
        assert temp_state_file.stat().st_size > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
