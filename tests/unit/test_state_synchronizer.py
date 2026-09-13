"""
Unit tests for StateSynchronizer.update_after_deployment UUID fast-path.
"""

import pytest
import json
import logging
import tempfile
from pathlib import Path
import yaml
from unittest.mock import Mock
from datetime import datetime, timezone

from talonctl.core.state_synchronizer import StateSynchronizer
from talonctl.core.state_manager import StateManager
from talonctl.core import ResourceAction, ResourceChange


@pytest.fixture
def temp_state_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        state = {
            "version": "3.0",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "metadata": {},
            "resources": {"saved_search": {}, "detection": {}},
            "resource_graph": {"nodes": [], "edges": {}},
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
    p.compute_content_hash.return_value = "hash123"
    p.fetch_remote_state.return_value = None
    p._remote_searches_cache = None
    return p


@pytest.fixture
def provider_adapter(saved_search_provider):
    adapter = Mock()
    adapter.providers = {"saved_search": saved_search_provider}
    return adapter


@pytest.fixture
def synchronizer(state_manager, provider_adapter):
    return StateSynchronizer(state_manager, provider_adapter)


class TestUpdateAfterDeploymentFastPath:
    def test_uuid_written_to_state_from_deploy_results(self, synchronizer, state_manager):
        """UUID from deploy_results['id'] is stored in state, not the IaC resource key."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="saved_search",
            resource_id="saved_search.my_search",
            resource_name="my_search",
            new_value={"name": "My Search", "queryString": "...", "_search_domain": "falcon"},
            template_path="resources/saved_searches/my_search.yaml",
        )
        deploy_results = {
            "saved_search.my_search": {"id": "real-uuid-abc123", "name": "My Search", "search_domain": "falcon"}
        }

        synchronizer.update_after_deployment(
            deployed=["saved_search.my_search"], changes=[change], deploy_results=deploy_results
        )

        state = state_manager.export_to_dict()
        assert state["resources"]["saved_search"]["my_search"]["id"] == "real-uuid-abc123"

    def test_iac_key_never_stored_as_state_id(self, synchronizer, state_manager):
        """Regression guard: IaC key 'saved_search.my_search' must not appear as state id."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="saved_search",
            resource_id="saved_search.my_search",
            resource_name="my_search",
            new_value={"name": "My Search", "queryString": "...", "_search_domain": "falcon"},
            template_path="resources/saved_searches/my_search.yaml",
        )
        deploy_results = {"saved_search.my_search": {"id": "real-uuid-abc123", "name": "My Search"}}

        synchronizer.update_after_deployment(
            deployed=["saved_search.my_search"], changes=[change], deploy_results=deploy_results
        )

        state = state_manager.export_to_dict()
        stored_id = state["resources"]["saved_search"]["my_search"]["id"]
        assert stored_id != "saved_search.my_search", (
            f"IaC key stored as id — UUID write-back is broken. Got: '{stored_id}'"
        )

    def test_rule_id_written_for_detection(self, synchronizer, state_manager, provider_adapter):
        """Fast path works for detections using the 'rule_id' key."""
        detection_provider = Mock()
        detection_provider.compute_content_hash.return_value = "hash456"
        detection_provider.fetch_remote_state.return_value = None
        detection_provider._remote_rules_cache = None
        provider_adapter.providers["detection"] = detection_provider

        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="detection",
            resource_id="detection.my_rule",
            resource_name="my_rule",
            new_value={"name": "My Rule", "severity": 50},
            template_path="resources/detections/my_rule.yaml",
        )
        deploy_results = {"detection.my_rule": {"rule_id": "rule-uuid-xyz789", "name": "My Rule"}}

        synchronizer.update_after_deployment(
            deployed=["detection.my_rule"], changes=[change], deploy_results=deploy_results
        )

        state = state_manager.export_to_dict()
        assert state["resources"]["detection"]["my_rule"]["id"] == "rule-uuid-xyz789"

    def test_fallback_when_deploy_results_is_none(self, synchronizer, state_manager, saved_search_provider):
        """Without deploy_results, existing fetch logic runs and stores the fetched UUID."""
        saved_search_provider.fetch_remote_state.return_value = {"id": "fetched-uuid", "name": "X"}

        change = ResourceChange(
            action=ResourceAction.UPDATE,
            resource_type="saved_search",
            resource_id="saved_search.my_search",
            resource_name="my_search",
            old_value={"id": "fetched-uuid"},
            new_value={"name": "My Search", "queryString": "...", "_search_domain": "falcon"},
            template_path="resources/saved_searches/my_search.yaml",
        )

        # No deploy_results — uses fallback path
        synchronizer.update_after_deployment(deployed=["saved_search.my_search"], changes=[change])

        state = state_manager.export_to_dict()
        assert "my_search" in state["resources"]["saved_search"]
        # Verify the fallback path correctly resolved the UUID (not garbage or IaC key)
        stored_id = state["resources"]["saved_search"]["my_search"]["id"]
        assert stored_id == "fetched-uuid", f"Fallback path should store 'fetched-uuid', got '{stored_id}'"

    def test_warning_logged_when_result_has_no_id_or_rule_id(self, synchronizer, state_manager, caplog):
        """Warning is logged when deploy_results entry has neither 'id' nor 'rule_id'."""
        change = ResourceChange(
            action=ResourceAction.CREATE,
            resource_type="saved_search",
            resource_id="saved_search.my_search",
            resource_name="my_search",
            new_value={"name": "My Search", "queryString": "..."},
            template_path="resources/saved_searches/my_search.yaml",
        )
        deploy_results = {"saved_search.my_search": {"name": "My Search", "created_at": "2026-01-01"}}

        with caplog.at_level(logging.WARNING, logger="talonctl.core.state_synchronizer"):
            synchronizer.update_after_deployment(
                deployed=["saved_search.my_search"], changes=[change], deploy_results=deploy_results
            )

        assert any("neither" in r.message.lower() for r in caplog.records), (
            f"Expected a warning about missing 'id'/'rule_id'. Records: {[r.message for r in caplog.records]}"
        )


class TestWriteResourceIdToTemplate:
    """rule_id write-back must never corrupt a talon/v2 template.

    In v1 flat templates the first `name:` line is the top-level name, so a
    column-0 insert after it is valid. In v2 the first `name:` is the indented
    `metadata.name`, and a column-0 insert lands in the middle of the metadata
    mapping. v2 has no authored home for rule_id at all (the envelope schema is
    `additionalProperties: false` and `v1_compat` drops the key), so the
    write-back is skipped for v2 files.
    """

    def _write(self, synchronizer, tmp_path, text):
        path = tmp_path / "detection.yaml"
        path.write_text(text)
        synchronizer._write_resource_id_to_template(
            template_path=str(path),
            resource_id="ABC123",
            resource_type="detection",
            resource_name="Demo Rule",
        )
        return path

    def test_v1_template_gets_rule_id(self, synchronizer, tmp_path):
        path = self._write(
            synchronizer,
            tmp_path,
            "resource_id: demo_rule\nname: Demo Rule\ndescription: demo\n",
        )
        assert yaml.safe_load(path.read_text())["rule_id"] == "ABC123"

    def test_v1_existing_rule_id_is_updated_in_place(self, synchronizer, tmp_path):
        path = self._write(
            synchronizer,
            tmp_path,
            "resource_id: demo_rule\nname: Demo Rule\nrule_id: OLD\n",
        )
        assert yaml.safe_load(path.read_text())["rule_id"] == "ABC123"

    def test_v2_template_is_left_untouched(self, synchronizer, tmp_path):
        original = (
            "apiVersion: talon/v2\n"
            "kind: Detection\n"
            "metadata:\n"
            "  resource_id: demo_rule\n"
            "  name: Demo Rule\n"
            "  labels:\n"
            "    team: soc\n"
            "spec:\n"
            "  description: demo\n"
        )
        path = self._write(synchronizer, tmp_path, original)
        # Must still parse — the bug produced "mapping values are not allowed here".
        assert yaml.safe_load(path.read_text()) is not None
        assert path.read_text() == original

    def test_multi_doc_file_containing_a_v2_doc_is_left_untouched(self, synchronizer, tmp_path):
        original = (
            "resource_id: legacy\n"
            "name: Legacy Rule\n"
            "---\n"
            "apiVersion: talon/v2\n"
            "kind: Detection\n"
            "metadata:\n"
            "  resource_id: demo_rule\n"
            "  name: Demo Rule\n"
            "  labels:\n"
            "    team: soc\n"
            "spec:\n"
            "  description: demo\n"
        )
        path = self._write(synchronizer, tmp_path, original)
        assert path.read_text() == original
