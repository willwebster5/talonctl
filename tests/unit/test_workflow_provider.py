"""
Unit tests for WorkflowProvider
"""

import pytest
from unittest.mock import Mock, patch

from talonctl.providers.workflow_provider import WorkflowProvider
from talonctl.core import ResourceAction
from tests.unit._helpers import make_envelope


def _env(flat):
    """Wrap a legacy flat workflow dict as an Envelope for the provider's
    Envelope-consuming methods. Defaults a resource_id (which v1_to_v2 requires)
    from the name when the test dict omits it — these tests assert on validation
    errors / planned changes, not on resource_id, so the default is inert.
    """
    if "resource_id" not in flat:
        flat = {**flat, "resource_id": "test_resource"}
    return make_envelope(flat, "workflow")


class TestWorkflowProvider:
    """Test suite for WorkflowProvider"""

    @pytest.fixture
    def mock_falcon(self):
        """Create mock Falcon client"""
        return Mock()

    @pytest.fixture
    def mock_workflows_client(self):
        """Create mock Workflows SDK client"""
        return Mock()

    @pytest.fixture
    def provider(self, mock_falcon, mock_workflows_client):
        """Create WorkflowProvider instance"""
        with patch("talonctl.providers.workflow_provider.load_credentials") as mock_creds:
            mock_creds.return_value = {
                "falcon_client_id": "test",
                "falcon_client_secret": "test",
                "base_url": "https://api.crowdstrike.com",
            }
            with patch("talonctl.providers.workflow_provider.Workflows") as mock_wf_class:
                mock_wf_class.return_value = mock_workflows_client
                provider = WorkflowProvider(mock_falcon)
                return provider

    def test_get_resource_type(self, provider):
        """Test resource type identifier"""
        assert provider.get_resource_type() == "workflow"

    def test_validate_template_valid(self, provider):
        """Test validation of valid template"""
        template = {
            "resource_id": "test___workflow",
            "name": "test_workflow",
            "trigger": {"event": "Investigatable/NGSIEM", "type": "Signal"},
            "actions": {"send_slack": {"id": "slack_action", "properties": {"msg": "Test alert"}}},
        }

        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_missing_fields(self, provider):
        """Test validation catches missing required fields"""
        template = {
            "name": "test_workflow"
            # Missing: trigger, actions
        }

        errors = provider.validate_template(_env(template))
        assert len(errors) >= 2
        assert any("trigger" in err for err in errors)
        assert any("actions" in err for err in errors)

    def test_validate_template_missing_trigger_event(self, provider):
        """Test validation catches missing trigger event"""
        template = {
            "resource_id": "test___workflow",
            "name": "test_workflow",
            "trigger": {
                "type": "Signal"
                # Missing: event
            },
            "actions": {"action1": {}},
        }

        errors = provider.validate_template(_env(template))
        assert any("event" in err.lower() for err in errors)

    def test_validate_template_empty_actions(self, provider):
        """Test validation catches empty actions"""
        template = {
            "resource_id": "test___workflow",
            "name": "test_workflow",
            "trigger": {"event": "test", "type": "Signal"},
            "actions": {},  # Empty
        }

        errors = provider.validate_template(_env(template))
        assert any("actions" in err.lower() for err in errors)

    def test_fetch_remote_state(self, provider, mock_workflows_client):
        """Test fetching remote workflow state"""
        mock_workflows_client.get_definitions.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "wf123",
                        "name": "test_workflow",
                        "enabled": True,
                        "trigger": {"event": "test"},
                        "actions": {"action1": {}},
                    }
                ]
            },
        }

        provider._remote_workflows_cache = {
            "test_workflow": {
                "id": "wf123",
                "name": "test_workflow",
                "enabled": True,
                "trigger": {"event": "test"},
                "actions": {"action1": {}},
            }
        }

        result = provider.fetch_remote_state("wf123")

        assert result is not None
        assert result["id"] == "wf123"
        assert result["name"] == "test_workflow"
        assert result["enabled"] is True

    def test_fetch_remote_state_not_found(self, provider, mock_workflows_client):
        """Test fetching non-existent workflow"""
        provider._remote_workflows_cache = {}

        result = provider.fetch_remote_state("nonexistent")
        assert result is None

    def test_plan_create(self, provider):
        """Test planning workflow creation"""
        template = {"name": "new_workflow", "trigger": {"event": "test", "type": "Signal"}, "actions": {"action1": {}}}

        env = _env(template)
        change = provider.plan_create(env, "workflows/test.yaml")

        assert change.action == ResourceAction.CREATE
        assert change.resource_type == "workflow"
        assert change.resource_name == "new_workflow"
        assert change.resource_id is None
        assert change.new_value == env.to_working_dict()
        assert change.template_path == "workflows/test.yaml"
        assert change.envelope is env

    def test_plan_update_with_changes(self, provider):
        """Test planning workflow update when changes exist"""
        template = {
            "name": "test_workflow",
            "enabled": False,
            "trigger": {"event": "new_event", "type": "Signal"},
            "actions": {"new_action": {}},
        }

        current_state = {
            "id": "wf123",
            "name": "test_workflow",
            "enabled": True,
            "trigger": {"event": "old_event", "type": "Signal"},
            "actions": {"old_action": {}},
        }

        change = provider.plan_update(_env(template), current_state, "workflows/test.yaml")

        assert change.action == ResourceAction.UPDATE
        assert change.resource_type == "workflow"
        assert change.resource_name == "test_workflow"
        assert change.resource_id == "wf123"
        assert "enabled" in change.changes
        assert "trigger" in change.changes
        assert "actions" in change.changes

    def test_plan_update_no_changes(self, provider):
        """Test planning workflow update when no changes exist"""
        template = {
            "name": "test_workflow",
            "enabled": True,
            "trigger": {"event": "test", "type": "Signal"},
            "actions": {"action1": {}},
            "conditions": {},
        }

        current_state = template.copy()
        current_state["id"] = "wf123"

        change = provider.plan_update(_env(template), current_state, "workflows/test.yaml")

        assert change.action == ResourceAction.NO_CHANGE
        assert change.resource_id == "wf123"

    def test_plan_delete(self, provider, mock_workflows_client):
        """Test planning workflow deletion"""
        provider._remote_workflows_cache = {"test_workflow": {"id": "wf123", "name": "test_workflow", "enabled": True}}

        change = provider.plan_delete("wf123", "test_workflow")

        assert change.action == ResourceAction.DELETE
        assert change.resource_type == "workflow"
        assert change.resource_name == "test_workflow"
        assert change.resource_id == "wf123"

    def test_apply_create(self, provider, mock_workflows_client):
        """Test creating a workflow"""
        template = {"name": "new_workflow", "trigger": {"event": "test", "type": "Signal"}, "actions": {"action1": {}}}

        mock_workflows_client.import_definition.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "new123", "name": "new_workflow", "enabled": True}]},
        }

        result = provider.apply_create(_env(template))

        assert result["id"] == "new123"
        assert result["name"] == "new_workflow"
        assert result["enabled"] is True
        assert "created_at" in result
        mock_workflows_client.import_definition.assert_called_once()

    def test_apply_update_raises_not_implemented(self, provider):
        """apply_update should raise NotImplementedError since API doesn't support updates."""
        with pytest.raises(NotImplementedError):
            provider.apply_update("test_id", {}, {})

    def test_apply_delete(self, provider, mock_workflows_client):
        """apply_delete should return a dict with 'id' on success."""
        mock_workflows_client.delete_definition.return_value = {"status_code": 200}
        result = provider.apply_delete("wf123")
        assert isinstance(result, dict)
        assert result["id"] == "wf123"

    def test_compute_content_hash_identical(self, provider):
        """Test hash computation produces identical results for same content"""
        template1 = {
            "name": "test",
            "enabled": True,
            "trigger": {"event": "test", "type": "Signal"},
            "actions": {"action1": {}},
        }

        template2 = template1.copy()

        hash1 = provider.compute_content_hash(template1)
        hash2 = provider.compute_content_hash(template2)

        assert hash1 == hash2

    def test_compute_content_hash_different(self, provider):
        """Test hash computation produces different results for different content"""
        template1 = {"name": "test", "trigger": {"event": "test", "type": "Signal"}, "actions": {"action1": {}}}

        template2 = {"name": "test", "trigger": {"event": "different", "type": "Signal"}, "actions": {"action1": {}}}

        hash1 = provider.compute_content_hash(template1)
        hash2 = provider.compute_content_hash(template2)

        assert hash1 != hash2

    def test_extract_dependencies_from_workflow_name(self, provider):
        """Test extracting detection dependency from workflow name"""
        template = {"name": "abc123_response_workflow", "trigger": {"event": "test", "type": "Signal"}, "actions": {}}

        deps = provider.extract_dependencies(template)

        assert "detection.abc123" in deps

    def test_extract_dependencies_from_conditions(self, provider):
        """Test extracting detection dependency from trigger conditions"""
        template = {
            "name": "test_workflow",
            "trigger": {"event": "test", "type": "Signal"},
            "actions": {},
            "conditions": {"check_name": {"expression": "Trigger.Category.Investigatable.Name:'AWS Root Login'"}},
        }

        deps = provider.extract_dependencies(template)

        assert "detection.aws_root_login" in deps

    def test_extract_dependencies_multiple(self, provider):
        """Test extracting multiple dependencies"""
        template = {
            "name": "rule123_response_workflow",
            "trigger": {"event": "test", "type": "Signal"},
            "actions": {},
            "conditions": {"check_name": {"expression": "Trigger.Category.Investigatable.Name:'Test Detection'"}},
        }

        deps = provider.extract_dependencies(template)

        # Should have at least the one from workflow name
        assert "detection.rule123" in deps

    def test_requires_replacement_always_returns_reason(self, provider):
        """WorkflowProvider always requires replacement since API doesn't support updates."""
        template = {
            "resource_id": "test___workflow",
            "name": "test",
            "trigger": {"event": "Investigatable/NGSIEM", "type": "Signal"},
            "actions": {"A": {}},
        }
        current_state = {"name": "test"}
        reason = provider.requires_replacement(template, current_state)
        assert reason is not None
        assert "not support updates" in reason.lower() or "delete and recreate" in reason.lower()

    def test_validate_template_requires_resource_id(self, provider):
        """Templates must include resource_id for IaC tracking.

        In v2 the Envelope guarantees a resource_id (metadata.resource_id is
        mandatory); v1_to_v2 raises at load time when it is absent, so the
        provider's own resource_id check is unreachable through the Envelope
        path. Assert the v2 enforcement point instead.
        """
        template = {
            "name": "Test Workflow",
            "trigger": {"event": "Investigatable/NGSIEM", "type": "Signal"},
            "actions": {"Notify": {"id": "abc123", "name": "Notify"}},
        }
        with pytest.raises(ValueError, match="resource_id"):
            make_envelope(template, "workflow")

    # --- v0.3.0 metadata namespace redesign ---

    @pytest.fixture
    def minimal_workflow(self):
        return {
            "resource_id": "x",
            "name": "Test Workflow",
            "enabled": True,
            "trigger": {"event": "Investigatable/NGSIEM", "type": "Signal"},
            "actions": {"a": {}},
            "conditions": {},
        }

    def test_v03_metadata_maturity_validates_on_workflow(self, provider, minimal_workflow):
        minimal_workflow["metadata"] = {"maturity": {"created": "2026-04-16"}}
        assert provider.validate_template(_env(minimal_workflow)) == []

    def test_v03_metadata_ads_rejected_on_workflow(self, provider, minimal_workflow):
        minimal_workflow["metadata"] = {"ads": {"goal": "g"}}
        errors = provider.validate_template(_env(minimal_workflow))
        assert any("metadata.ads is only supported on detection resources" in e and "workflow" in e for e in errors)

    def test_v03_old_top_level_ads_rejected_on_workflow(self, provider, minimal_workflow):
        minimal_workflow["ads"] = {"goal": "g"}
        errors = provider.validate_template(_env(minimal_workflow))
        assert any("Top-level 'ads:' is removed in v0.3.0" in e for e in errors)

    def test_v03_metadata_edits_do_not_change_content_hash(self, provider, minimal_workflow):
        base_hash = provider.compute_content_hash(minimal_workflow)
        with_metadata = dict(minimal_workflow)
        with_metadata["metadata"] = {"maturity": {"tune_count": 5}, "acme": {"x": 1}}
        assert provider.compute_content_hash(with_metadata) == base_hash


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
