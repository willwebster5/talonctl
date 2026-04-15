"""
Unit tests for StateSynchronizer.update_after_deployment UUID fast-path.
"""

import pytest
import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import Mock
from datetime import datetime, timezone

from talonctl.core.state_synchronizer import StateSynchronizer
from talonctl.core.state_manager import StateManager
from talonctl.core import ResourceAction, ResourceChange


@pytest.fixture
def temp_state_file():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        state = {
            "version": "3.0",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "metadata": {},
            "resources": {"saved_search": {}, "detection": {}},
            "resource_graph": {"nodes": [], "edges": {}}
        }
        json.dump(state, f)
        temp_path = Path(f.name)
    yield temp_path
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def state_manager(temp_state_file):
    return StateManager(state_file_path=temp_state_file)


@pytest.fixture
def saved_search_provider():
    p = Mock()
    p.compute_content_hash.return_value = 'hash123'
    p.fetch_remote_state.return_value = None
    p._remote_searches_cache = None
    return p


@pytest.fixture
def provider_adapter(saved_search_provider):
    adapter = Mock()
    adapter.providers = {'saved_search': saved_search_provider}
    return adapter


@pytest.fixture
def synchronizer(state_manager, provider_adapter):
    return StateSynchronizer(state_manager, provider_adapter)


class TestUpdateAfterDeploymentFastPath:

    def test_uuid_written_to_state_from_deploy_results(self, synchronizer, state_manager):
        """UUID from deploy_results['id'] is stored in state, not the IaC resource key."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type='saved_search',
            resource_id='saved_search.my_search',
            resource_name='my_search',
            new_value={'name': 'My Search', 'queryString': '...', '_search_domain': 'falcon'},
            template_path='resources/saved_searches/my_search.yaml'
        )
        deploy_results = {
            'saved_search.my_search': {
                'id': 'real-uuid-abc123',
                'name': 'My Search',
                'search_domain': 'falcon'
            }
        }

        synchronizer.update_after_deployment(
            deployed=['saved_search.my_search'],
            changes=[change],
            deploy_results=deploy_results
        )

        state = state_manager.export_to_dict()
        assert state['resources']['saved_search']['my_search']['id'] == 'real-uuid-abc123'

    def test_iac_key_never_stored_as_state_id(self, synchronizer, state_manager):
        """Regression guard: IaC key 'saved_search.my_search' must not appear as state id."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type='saved_search',
            resource_id='saved_search.my_search',
            resource_name='my_search',
            new_value={'name': 'My Search', 'queryString': '...', '_search_domain': 'falcon'},
            template_path='resources/saved_searches/my_search.yaml'
        )
        deploy_results = {
            'saved_search.my_search': {'id': 'real-uuid-abc123', 'name': 'My Search'}
        }

        synchronizer.update_after_deployment(
            deployed=['saved_search.my_search'],
            changes=[change],
            deploy_results=deploy_results
        )

        state = state_manager.export_to_dict()
        stored_id = state['resources']['saved_search']['my_search']['id']
        assert stored_id != 'saved_search.my_search', (
            f"IaC key stored as id — UUID write-back is broken. Got: '{stored_id}'"
        )

    def test_rule_id_written_for_detection(self, synchronizer, state_manager, provider_adapter):
        """Fast path works for detections using the 'rule_id' key."""
        detection_provider = Mock()
        detection_provider.compute_content_hash.return_value = 'hash456'
        detection_provider.fetch_remote_state.return_value = None
        detection_provider._remote_rules_cache = None
        provider_adapter.providers['detection'] = detection_provider

        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type='detection',
            resource_id='detection.my_rule',
            resource_name='my_rule',
            new_value={'name': 'My Rule', 'severity': 50},
            template_path='resources/detections/my_rule.yaml'
        )
        deploy_results = {
            'detection.my_rule': {'rule_id': 'rule-uuid-xyz789', 'name': 'My Rule'}
        }

        synchronizer.update_after_deployment(
            deployed=['detection.my_rule'],
            changes=[change],
            deploy_results=deploy_results
        )

        state = state_manager.export_to_dict()
        assert state['resources']['detection']['my_rule']['id'] == 'rule-uuid-xyz789'

    def test_fallback_when_deploy_results_is_none(self, synchronizer, state_manager, saved_search_provider):
        """Without deploy_results, existing fetch logic runs and stores the fetched UUID."""
        saved_search_provider.fetch_remote_state.return_value = {'id': 'fetched-uuid', 'name': 'X'}

        change = ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type='saved_search',
            resource_id='saved_search.my_search',
            resource_name='my_search',
            old_value={'id': 'fetched-uuid'},
            new_value={'name': 'My Search', 'queryString': '...', '_search_domain': 'falcon'},
            template_path='resources/saved_searches/my_search.yaml'
        )

        # No deploy_results — uses fallback path
        synchronizer.update_after_deployment(
            deployed=['saved_search.my_search'],
            changes=[change]
        )

        state = state_manager.export_to_dict()
        assert 'my_search' in state['resources']['saved_search']
        # Verify the fallback path correctly resolved the UUID (not garbage or IaC key)
        stored_id = state['resources']['saved_search']['my_search']['id']
        assert stored_id == 'fetched-uuid', (
            f"Fallback path should store 'fetched-uuid', got '{stored_id}'"
        )

    def test_warning_logged_when_result_has_no_id_or_rule_id(
        self, synchronizer, state_manager, caplog
    ):
        """Warning is logged when deploy_results entry has neither 'id' nor 'rule_id'."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type='saved_search',
            resource_id='saved_search.my_search',
            resource_name='my_search',
            new_value={'name': 'My Search', 'queryString': '...'},
            template_path='resources/saved_searches/my_search.yaml'
        )
        deploy_results = {
            'saved_search.my_search': {'name': 'My Search', 'created_at': '2026-01-01'}
        }

        with caplog.at_level(logging.WARNING, logger='talonctl.core.state_synchronizer'):
            synchronizer.update_after_deployment(
                deployed=['saved_search.my_search'],
                changes=[change],
                deploy_results=deploy_results
            )

        assert any('neither' in r.message.lower() for r in caplog.records), (
            "Expected a warning about missing 'id'/'rule_id'. "
            f"Records: {[r.message for r in caplog.records]}"
        )
