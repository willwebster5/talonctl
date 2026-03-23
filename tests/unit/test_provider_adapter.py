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

    def test_convert_legacy_to_resource_state(self, adapter):
        """Test conversion from legacy v2.0 format to v3.0 ResourceState"""
        legacy_data = {
            'rule_id': 'abc123',
            'content_hash': 'hash123',
            'template_path': 'rules/test.yaml',
            'deployed_at': '2024-01-01T00:00:00Z',
            'last_modified': '2024-01-01T00:00:00Z',
            'status': 'active',
            'workflow_created': True,
            'workflow_id': 'wf123',
            'workflow_name': 'test_workflow',
            'workflow_enabled': True
        }

        result = adapter.convert_legacy_state_to_resource_state(legacy_data, 'test_rule')

        assert result.type == 'detection'
        assert result.id == 'abc123'
        assert result.content_hash == 'hash123'
        assert result.template_path == 'rules/test.yaml'
        assert result.provider_metadata['rule_id'] == 'abc123'
        assert result.provider_metadata['status'] == 'active'
        assert result.provider_metadata['workflow_created'] is True

    def test_convert_resource_state_to_legacy(self, adapter):
        """Test conversion from v3.0 ResourceState to legacy v2.0 format"""
        resource_state = ResourceState(
            type='detection',
            id='abc123',
            content_hash='hash123',
            template_path='rules/test.yaml',
            deployed_at='2024-01-01T00:00:00Z',
            last_modified='2024-01-01T00:00:00Z',
            provider_metadata={
                'rule_id': 'abc123',
                'status': 'active',
                'workflow_created': True,
                'workflow_id': 'wf123',
                'workflow_name': 'test_workflow',
                'workflow_enabled': True
            },
            dependencies=[]
        )

        result = adapter.convert_resource_state_to_legacy(resource_state)

        assert result['rule_id'] == 'abc123'
        assert result['content_hash'] == 'hash123'
        assert result['template_path'] == 'rules/test.yaml'
        assert result['status'] == 'active'
        assert result['workflow_created'] is True
        assert result['workflow_id'] == 'wf123'

    def test_get_legacy_state_dict(self, adapter):
        """Test exporting state in legacy v2.0 format"""
        # Add a detection resource to state
        resource_state = ResourceState(
            type='detection',
            id='rule123',
            content_hash='hash123',
            template_path='rules/test.yaml',
            deployed_at='2024-01-01T00:00:00Z',
            last_modified='2024-01-01T00:00:00Z',
            provider_metadata={
                'rule_id': 'rule123',
                'status': 'active'
            },
            dependencies=[]
        )

        adapter.state_manager.set_resource('detection', 'test_rule', resource_state)

        # Get legacy format
        legacy_state = adapter.get_legacy_state_dict()

        assert legacy_state['version'] == '2.0'
        assert 'rules' in legacy_state
        assert 'test_rule' in legacy_state['rules']
        assert legacy_state['rules']['test_rule']['rule_id'] == 'rule123'

    def test_import_legacy_state(self, adapter):
        """Test importing legacy v2.0 state"""
        legacy_state = {
            'version': '2.0',
            'last_updated': '2024-01-01T00:00:00Z',
            'rules': {
                'test_rule_1': {
                    'rule_id': 'rule1',
                    'content_hash': 'hash1',
                    'template_path': 'rules/test1.yaml',
                    'deployed_at': '2024-01-01T00:00:00Z',
                    'last_modified': '2024-01-01T00:00:00Z',
                    'status': 'active'
                },
                'test_rule_2': {
                    'rule_id': 'rule2',
                    'content_hash': 'hash2',
                    'template_path': 'rules/test2.yaml',
                    'deployed_at': '2024-01-01T00:00:00Z',
                    'last_modified': '2024-01-01T00:00:00Z',
                    'status': 'inactive'
                }
            }
        }

        adapter.import_legacy_state(legacy_state)

        # Verify rules were imported
        rule1 = adapter.state_manager.get_resource('detection', 'test_rule_1')
        rule2 = adapter.state_manager.get_resource('detection', 'test_rule_2')

        assert rule1 is not None
        assert rule1.id == 'rule1'
        assert rule2 is not None
        assert rule2.id == 'rule2'

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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
