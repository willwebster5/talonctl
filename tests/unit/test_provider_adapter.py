"""
Unit tests for ProviderAdapter
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone
import tempfile
import json

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from core.provider_adapter import ProviderAdapter
from core import ResourceState, ResourceAction


class TestProviderAdapter:
    """Test suite for ProviderAdapter"""

    @pytest.fixture
    def mock_falcon(self):
        """Create mock Falcon client"""
        return Mock()

    @pytest.fixture
    def temp_state_file(self):
        """Create temporary state file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                "version": "3.0",
                "last_updated": "2024-01-01T00:00:00Z",
                "metadata": {},
                "resources": {},
                "resource_graph": {"nodes": [], "edges": []}
            }, f)
            return Path(f.name)

    @pytest.fixture
    def adapter(self, mock_falcon, temp_state_file):
        """Create ProviderAdapter instance"""
        with patch('providers.detection_provider.DetectionProvider'):
            with patch('providers.workflow_provider.WorkflowProvider'):
                adapter = ProviderAdapter(mock_falcon, temp_state_file)
                return adapter

    def test_plan_detection_changes_create(self, adapter):
        """Test planning detection creation"""
        # Mock provider methods
        adapter.detection_provider.validate_template = Mock(return_value=[])
        adapter.detection_provider.plan_create = Mock(return_value=Mock(
            action=ResourceAction.CREATE,
            resource_name='new_rule',
            resource_id=None
        ))

        templates = {
            'new_rule': {
                'name': 'New Rule',
                'description': 'Test',
                'severity': 50,
                'search': {'query': 'test'},
                '_template_path': 'rules/new.yaml'
            }
        }

        result = adapter.plan_detection_changes(templates)

        assert len(result['create']) == 1
        assert len(result['update']) == 0
        assert len(result['delete']) == 0
        adapter.detection_provider.plan_create.assert_called_once()

    def test_plan_detection_changes_update(self, adapter):
        """Test planning detection update"""
        # Add existing rule to state
        resource_state = ResourceState(
            type='detection',
            id='rule123',
            content_hash='old_hash',
            template_path='rules/test.yaml',
            deployed_at='2024-01-01T00:00:00Z',
            last_modified='2024-01-01T00:00:00Z',
            provider_metadata={'rule_id': 'rule123'},
            dependencies=[]
        )
        adapter.state_manager.set_resource('detection', 'existing_rule', resource_state)

        # Mock provider methods
        adapter.detection_provider.validate_template = Mock(return_value=[])
        adapter.detection_provider.fetch_remote_state = Mock(return_value={
            'id': 'rule123',
            'name': 'Existing Rule',
            'description': 'Old description'
        })
        adapter.detection_provider.plan_update = Mock(return_value=Mock(
            action=ResourceAction.UPDATE,
            resource_name='existing_rule',
            resource_id='rule123'
        ))

        templates = {
            'existing_rule': {
                'name': 'Existing Rule',
                'description': 'New description',
                'severity': 50,
                'search': {'query': 'test'},
                '_template_path': 'rules/existing.yaml'
            }
        }

        result = adapter.plan_detection_changes(templates)

        assert len(result['create']) == 0
        assert len(result['update']) == 1
        assert len(result['delete']) == 0
        adapter.detection_provider.plan_update.assert_called_once()

    def test_plan_detection_changes_delete(self, adapter):
        """Test planning detection deletion"""
        # Add rule to state that's not in templates
        resource_state = ResourceState(
            type='detection',
            id='rule123',
            content_hash='hash123',
            template_path='rules/old.yaml',
            deployed_at='2024-01-01T00:00:00Z',
            last_modified='2024-01-01T00:00:00Z',
            provider_metadata={'rule_id': 'rule123'},
            dependencies=[]
        )
        adapter.state_manager.set_resource('detection', 'old_rule', resource_state)

        # Mock provider methods
        adapter.detection_provider.plan_delete = Mock(return_value=Mock(
            action=ResourceAction.DELETE,
            resource_name='old_rule',
            resource_id='rule123'
        ))

        templates = {}  # Empty - should plan delete

        result = adapter.plan_detection_changes(templates)

        assert len(result['create']) == 0
        assert len(result['update']) == 0
        assert len(result['delete']) == 1
        adapter.detection_provider.plan_delete.assert_called_once()

    def test_get_provider(self, adapter):
        """Test getting provider by type"""
        detection_provider = adapter.get_provider('detection')
        workflow_provider = adapter.get_provider('workflow')
        unknown_provider = adapter.get_provider('unknown')

        assert detection_provider is not None
        assert workflow_provider is not None
        assert unknown_provider is None

    def test_get_provider_registry_returns_all_six_types(self, adapter):
        """get_provider_registry should return all 6 resource type providers"""
        registry = adapter.get_provider_registry()
        assert isinstance(registry, dict)
        expected_types = {'detection', 'workflow', 'saved_search', 'lookup_file', 'rtr_script', 'rtr_put_file'}
        assert set(registry.keys()) == expected_types
        for provider in registry.values():
            assert provider is not None

    def test_save_state_delegates_to_state_manager(self, adapter):
        """save_state should call state_manager.save()"""
        adapter.state_manager.save = Mock()
        adapter.save_state()
        adapter.state_manager.save.assert_called_once()

    def test_plan_resource_changes_create(self, adapter):
        """plan_resource_changes should return create list for new resource"""
        adapter.detection_provider.validate_template = Mock(return_value=[])
        adapter.detection_provider.plan_create = Mock(return_value=Mock(
            action=ResourceAction.CREATE,
            resource_name='new_rule',
            resource_id=None
        ))

        templates = {
            'new_rule': {
                'name': 'New Rule',
                'description': 'Test',
                'severity': 50,
                '_template_path': 'rules/new.yaml'
            }
        }

        result = adapter.plan_resource_changes('detection', templates)

        assert len(result['create']) == 1
        assert len(result['update']) == 0
        assert len(result['delete']) == 0
        adapter.detection_provider.plan_create.assert_called_once()

    def test_apply_resource_change_create_updates_state(self, adapter):
        """apply_resource_change CREATE should persist resource id to state"""
        from core import ResourceAction, ResourceChange
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type='detection',
            resource_name='new_rule',
            new_value={'name': 'New Rule'},
            template_path='rules/new.yaml'
        )

        adapter.detection_provider.apply_create = Mock(return_value={
            'rule_id': 'abc123',
            'created_at': '2025-01-01T00:00:00Z'
        })
        adapter.detection_provider.compute_content_hash = Mock(return_value='hash123')
        adapter.detection_provider.extract_dependencies = Mock(return_value={})

        result = adapter.apply_resource_change('detection', change, {'name': 'New Rule'})

        assert result['rule_id'] == 'abc123'
        # State should be persisted
        state = adapter.state_manager.get_resource('detection', 'new_rule')
        assert state is not None
        assert state.id == 'abc123'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
