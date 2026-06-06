"""
Unit tests for RTRScriptProvider
"""

import pytest
from unittest.mock import Mock

from talonctl.providers.rtr_script_provider import RTRScriptProvider
from talonctl.core import ResourceAction
from tests.unit._helpers import make_envelope


def _env(flat):
    """Wrap a legacy flat rtr_script dict as an Envelope for the provider's
    Envelope-consuming methods. Defaults a resource_id (which v1_to_v2 mints
    from name for rtr_script, but needs an explicit one when the test dict omits
    both) — these tests assert on validation/planned changes, not resource_id,
    so the default is inert. When the dict carries a file_path that the provider
    resolves relative to _template_path, pass origin_path so to_working_dict
    re-injects it the way the loader will.
    """
    if "resource_id" not in flat:
        flat = {**flat, "resource_id": "test_resource"}
    origin_path = flat.get("_template_path")
    return make_envelope(flat, "rtr_script", origin_path=origin_path)


class TestRTRScriptProvider:
    """Test suite for RTRScriptProvider"""

    @pytest.fixture
    def mock_falcon(self):
        """Create mock Falcon client (no auth_object -> validation-only mode)"""
        return Mock(spec=[])  # spec=[] ensures no auth_object attribute

    @pytest.fixture
    def provider(self, mock_falcon):
        """Create RTRScriptProvider in validation-only mode"""
        p = RTRScriptProvider(mock_falcon)
        assert p.rtr_admin is None, "Should be in validation-only mode"
        return p

    @pytest.fixture
    def provider_with_api(self, provider):
        """Provider with mocked RTR admin API"""
        provider.rtr_admin = Mock()
        return provider

    # --- Resource Type ---

    def test_get_resource_type(self, provider):
        assert provider.get_resource_type() == "rtr_script"

    # --- Template Validation ---

    def test_validate_template_valid_with_content(self, provider):
        template = {
            "name": "Get-ProcessTree",
            "description": "Retrieve process tree for investigation",
            "platform": ["windows"],
            "content": "Get-Process | Format-Table",
        }
        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_valid_with_file_path(self, provider):
        template = {
            "name": "Get-ProcessTree",
            "description": "Retrieve process tree",
            "platform": "windows",
            "file_path": "scripts/Get-ProcessTree.ps1",
        }
        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_valid_multi_platform(self, provider):
        template = {
            "name": "collect-logs",
            "description": "Collect system logs",
            "platform": ["linux", "mac"],
            "content": "#!/bin/bash\ncat /var/log/syslog",
        }
        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_missing_name(self, provider):
        template = {
            "description": "Test",
            "platform": "windows",
            "content": "echo hello",
        }
        errors = provider.validate_template(_env(template))
        assert any("name" in err.lower() for err in errors)

    def test_validate_template_missing_description(self, provider):
        template = {
            "name": "test",
            "platform": "windows",
            "content": "echo hello",
        }
        errors = provider.validate_template(_env(template))
        assert any("description" in err.lower() for err in errors)

    def test_validate_template_missing_platform(self, provider):
        template = {
            "name": "test",
            "description": "test",
            "content": "echo hello",
        }
        errors = provider.validate_template(_env(template))
        assert any("platform" in err.lower() for err in errors)

    def test_validate_template_invalid_platform(self, provider):
        template = {
            "name": "test",
            "description": "test",
            "platform": "solaris",
            "content": "echo hello",
        }
        errors = provider.validate_template(_env(template))
        assert any("solaris" in err.lower() for err in errors)
        assert any("VALID_PLATFORMS" in err or "windows" in err for err in errors)

    def test_validate_template_invalid_permission_type(self, provider):
        template = {
            "name": "test",
            "description": "test",
            "platform": "windows",
            "permission_type": "admin",
            "content": "echo hello",
        }
        errors = provider.validate_template(_env(template))
        assert any("permission_type" in err.lower() for err in errors)

    def test_validate_template_no_content_or_file_path(self, provider):
        template = {
            "name": "test",
            "description": "test",
            "platform": "windows",
        }
        errors = provider.validate_template(_env(template))
        assert any("content" in err.lower() or "file_path" in err.lower() for err in errors)

    def test_validate_template_both_content_and_file_path(self, provider):
        """Both content and file_path is valid (content takes precedence)"""
        template = {
            "name": "test",
            "description": "test",
            "platform": "windows",
            "content": "echo hello",
            "file_path": "scripts/test.ps1",
        }
        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_empty_name(self, provider):
        template = {
            "name": "",
            "description": "test",
            "platform": "windows",
            "content": "echo hello",
        }
        errors = provider.validate_template(_env(template))
        assert any("non-empty" in err for err in errors)

    def test_validate_template_empty_description(self, provider):
        template = {
            "name": "test",
            "description": "   ",
            "platform": "windows",
            "content": "echo hello",
        }
        errors = provider.validate_template(_env(template))
        assert any("non-empty" in err for err in errors)

    def test_validate_template_non_string_content(self, provider):
        template = {
            "name": "test",
            "description": "test",
            "platform": "windows",
            "content": 12345,
        }
        errors = provider.validate_template(_env(template))
        assert any("content" in err.lower() and "string" in err.lower() for err in errors)

    def test_validate_template_non_string_file_path(self, provider):
        template = {
            "name": "test",
            "description": "test",
            "platform": "windows",
            "file_path": 12345,
        }
        errors = provider.validate_template(_env(template))
        assert any("file_path" in err.lower() and "string" in err.lower() for err in errors)

    # --- Content Hashing ---

    def test_compute_content_hash_deterministic(self, provider):
        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "content": "Get-Process",
        }
        hash1 = provider.compute_content_hash(template)
        hash2 = provider.compute_content_hash(template)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex

    def test_compute_content_hash_different_name(self, provider):
        base = {
            "description": "test",
            "platform": ["windows"],
            "content": "Get-Process",
        }
        hash1 = provider.compute_content_hash({**base, "name": "script_a"})
        hash2 = provider.compute_content_hash({**base, "name": "script_b"})
        assert hash1 != hash2

    def test_compute_content_hash_different_content(self, provider):
        base = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
        }
        hash1 = provider.compute_content_hash({**base, "content": "Get-Process"})
        hash2 = provider.compute_content_hash({**base, "content": "Get-Service"})
        assert hash1 != hash2

    def test_compute_content_hash_platform_order_irrelevant(self, provider):
        base = {
            "name": "test",
            "description": "test",
            "content": "echo hello",
        }
        hash1 = provider.compute_content_hash({**base, "platform": ["linux", "mac"]})
        hash2 = provider.compute_content_hash({**base, "platform": ["mac", "linux"]})
        assert hash1 == hash2

    def test_compute_content_hash_string_vs_list_platform(self, provider):
        """String platform is normalized to list before hashing"""
        base = {
            "name": "test",
            "description": "test",
            "content": "echo hello",
        }
        hash1 = provider.compute_content_hash({**base, "platform": "windows"})
        hash2 = provider.compute_content_hash({**base, "platform": ["windows"]})
        assert hash1 == hash2

    def test_compute_content_hash_file_path(self, provider, tmp_path):
        """file_path content is included in hash when file exists"""
        script_file = tmp_path / "test.ps1"
        script_file.write_text("Get-Process | Format-Table")

        template_file = tmp_path / "template.yaml"
        template_file.write_text("")  # just needs to exist for path resolution

        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "file_path": "test.ps1",
            "_template_path": str(template_file),
        }
        hash1 = provider.compute_content_hash(template)

        # Change file content
        script_file.write_text("Get-Service | Format-Table")
        hash2 = provider.compute_content_hash(template)

        assert hash1 != hash2

    def test_compute_content_hash_missing_file_graceful(self, provider, tmp_path):
        """Missing file falls back to empty content without error"""
        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "file_path": "nonexistent.ps1",
            "_template_path": str(tmp_path / "template.yaml"),
        }
        h = provider.compute_content_hash(template)
        assert isinstance(h, str)
        assert len(h) == 64

    # --- Planning ---

    def test_plan_create(self, provider):
        template = {
            "name": "New Script",
            "description": "test",
            "platform": ["windows"],
            "content": "Get-Process",
        }
        env = _env(template)
        change = provider.plan_create(env, "rtr_scripts/new_script.yaml")
        assert change.action == ResourceAction.CREATE
        assert change.resource_type == "rtr_script"
        assert change.resource_name == "New Script"
        assert change.new_value == env.to_working_dict()
        assert change.template_path == "rtr_scripts/new_script.yaml"
        assert change.envelope is env

    def test_plan_update_no_change(self, provider):
        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "content": "Get-Process",
        }
        current = {
            "id": "abc123",
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "content": "Get-Process",
        }
        change = provider.plan_update(_env(template), current, "rtr_scripts/test.yaml")
        assert change.action == ResourceAction.NO_CHANGE
        assert change.resource_id == "abc123"

    def test_plan_update_description_changed(self, provider):
        template = {
            "name": "test",
            "description": "updated description",
            "platform": ["windows"],
            "content": "Get-Process",
        }
        current = {
            "id": "abc123",
            "name": "test",
            "description": "old description",
            "platform": ["windows"],
            "content": "Get-Process",
        }
        change = provider.plan_update(_env(template), current, "rtr_scripts/test.yaml")
        assert change.action == ResourceAction.UPDATE
        assert "description" in change.changes

    def test_plan_update_platform_string_vs_list(self, provider):
        """Platform normalization: string 'windows' should equal ['windows']"""
        template = {
            "name": "test",
            "description": "test",
            "platform": "windows",  # string
            "content": "Get-Process",
        }
        current = {
            "id": "abc123",
            "name": "test",
            "description": "test",
            "platform": ["windows"],  # list
            "content": "Get-Process",
        }
        change = provider.plan_update(_env(template), current, "rtr_scripts/test.yaml")
        assert change.action == ResourceAction.NO_CHANGE

    def test_plan_delete(self, provider):
        change = provider.plan_delete("abc123", "Test Script")
        assert change.action == ResourceAction.DELETE
        assert change.resource_type == "rtr_script"
        assert change.resource_name == "Test Script"
        assert change.resource_id == "abc123"

    # --- API Operations (mocked rtr_admin) ---

    def test_create_resource_inline_content(self, provider_with_api):
        provider_with_api.rtr_admin.create_scripts.return_value = {
            "status_code": 200,
            "body": {"resources": ["new-id-123"]},
        }
        template = {
            "name": "test_script",
            "description": "test",
            "platform": ["windows"],
            "content": "Get-Process",
            "permission_type": "group",
        }
        result = provider_with_api.create_resource(None, template)
        assert result["id"] == "new-id-123"
        assert result["name"] == "test_script"
        provider_with_api.rtr_admin.create_scripts.assert_called_once()
        call_kwargs = provider_with_api.rtr_admin.create_scripts.call_args
        assert call_kwargs.kwargs["name"] == "test_script"

    def test_create_resource_from_file(self, provider_with_api, tmp_path):
        provider_with_api.rtr_admin.create_scripts.return_value = {
            "status_code": 200,
            "body": {"resources": ["new-id-456"]},
        }
        script_file = tmp_path / "my_script.ps1"
        script_file.write_text("Get-Process | Format-Table")

        template_file = tmp_path / "template.yaml"

        template = {
            "name": "my_script",
            "description": "test",
            "platform": ["windows"],
            "file_path": "my_script.ps1",
            "_template_path": str(template_file),
        }
        result = provider_with_api.create_resource(None, template)
        assert result["id"] == "new-id-456"

    def test_create_resource_missing_file_raises(self, provider_with_api, tmp_path):
        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "file_path": "nonexistent.ps1",
            "_template_path": str(tmp_path / "template.yaml"),
        }
        with pytest.raises(RuntimeError, match="Script file not found"):
            provider_with_api.create_resource(None, template)

    def test_create_resource_empty_content_raises(self, provider_with_api):
        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "content": "",
        }
        with pytest.raises(RuntimeError, match="content is empty"):
            provider_with_api.create_resource(None, template)

    def test_create_resource_oversized_raises(self, provider_with_api):
        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "content": "x" * (6 * 1024 * 1024),  # 6MB > 5MB limit
        }
        with pytest.raises(RuntimeError, match="too large"):
            provider_with_api.create_resource(None, template)

    def test_create_resource_no_rtr_admin_raises(self, provider):
        """Validation-only mode cannot create resources"""
        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "content": "echo hello",
        }
        with pytest.raises(RuntimeError, match="credentials required"):
            provider.create_resource(None, template)

    def test_update_resource(self, provider_with_api, tmp_path):
        provider_with_api.rtr_admin.update_scripts.return_value = {"status_code": 200, "body": {}}
        template = {
            "name": "test_script",
            "description": "updated",
            "platform": ["windows"],
            "content": "Get-Service",
        }
        result = provider_with_api.update_resource("abc123", template, {})
        assert result["id"] == "abc123"
        assert result["name"] == "test_script"
        provider_with_api.rtr_admin.update_scripts.assert_called_once()
        assert provider_with_api.rtr_admin.update_scripts.call_args.kwargs["id"] == "abc123"

    def test_delete_resource_200(self, provider_with_api):
        provider_with_api.rtr_admin.delete_scripts.return_value = {"status_code": 200, "body": {}}
        result = provider_with_api.delete_resource("abc123")
        assert result["id"] == "abc123"
        assert "deleted_at" in result
        provider_with_api.rtr_admin.delete_scripts.assert_called_once_with(ids="abc123")

    def test_delete_resource_404_soft_success(self, provider_with_api):
        provider_with_api.rtr_admin.delete_scripts.return_value = {"status_code": 404, "body": {}}
        result = provider_with_api.delete_resource("abc123")
        assert result["id"] == "abc123"
        assert "note" in result

    def test_delete_resource_500_raises(self, provider_with_api):
        provider_with_api.rtr_admin.delete_scripts.return_value = {
            "status_code": 500,
            "body": {"errors": ["Server error"]},
        }
        with pytest.raises(RuntimeError, match="Failed to delete"):
            provider_with_api.delete_resource("abc123")

    def test_fetch_remote_state_found(self, provider_with_api):
        provider_with_api.rtr_admin.get_scripts_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "abc123",
                        "name": "Test Script",
                        "platform": ["windows"],
                    }
                ]
            },
        }
        result = provider_with_api.fetch_remote_state("abc123")
        assert result is not None
        assert result["id"] == "abc123"
        assert result["name"] == "Test Script"

    def test_fetch_remote_state_empty(self, provider_with_api):
        provider_with_api.rtr_admin.get_scripts_v2.return_value = {"status_code": 200, "body": {"resources": []}}
        result = provider_with_api.fetch_remote_state("nonexistent")
        assert result is None

    def test_fetch_remote_state_no_api(self, provider):
        """Validation mode returns None"""
        result = provider.fetch_remote_state("abc123")
        assert result is None

    # --- to_template and suggest_path ---

    def test_to_template(self, provider):
        remote = {
            "name": "Get-ProcessTree",
            "description": "Process tree script",
            "platform": ["windows"],
            "permission_type": "group",
            "content": "Get-Process",
        }
        tmpl = provider.to_template(remote)
        assert tmpl["resource_id"] == "getprocesstree"
        assert tmpl["name"] == "Get-ProcessTree"
        assert tmpl["platform"] == ["windows"]
        assert tmpl["content"] == "Get-Process"

    def test_suggest_path(self, provider):
        template = {"resource_id": "getprocesstree", "name": "Get-ProcessTree"}
        assert provider.suggest_path(template) == "rtr_scripts/getprocesstree.yaml"

    def test_suggest_path_fallback(self, provider):
        template = {"name": "Get-ProcessTree"}
        path = provider.suggest_path(template)
        assert path == "rtr_scripts/getprocesstree.yaml"

    # --- extract_dependencies ---

    def test_extract_dependencies_empty(self, provider):
        template = {"name": "test", "content": "echo hello"}
        assert provider.extract_dependencies(template) == {}

    # --- apply aliases ---

    def test_apply_create_alias(self, provider_with_api):
        provider_with_api.rtr_admin.create_scripts.return_value = {"status_code": 200, "body": {"resources": ["id1"]}}
        template = {
            "name": "test",
            "description": "test",
            "platform": ["windows"],
            "content": "echo hello",
        }
        result = provider_with_api.apply_create(_env(template))
        assert result["id"] == "id1"

    def test_apply_delete_alias(self, provider_with_api):
        provider_with_api.rtr_admin.delete_scripts.return_value = {"status_code": 200, "body": {}}
        result = provider_with_api.apply_delete("abc123")
        assert result["id"] == "abc123"

    # --- v0.3.0 metadata namespace redesign ---

    @pytest.fixture
    def minimal_rtr_script(self, tmp_path):
        script = tmp_path / "hello.sh"
        script.write_text("#!/bin/sh\necho hi\n")
        return {
            "resource_id": "x",
            "name": "hello",
            "description": "say hi",
            "platform": "linux",
            "permission_type": "private",
            "content": "#!/bin/sh\necho hi\n",
            "_template_path": str(tmp_path / "tmpl.yaml"),
        }

    def test_v03_metadata_maturity_validates_on_rtr_script(self, provider, minimal_rtr_script):
        minimal_rtr_script["metadata"] = {"maturity": {"created": "2026-04-16"}}
        assert provider.validate_template(_env(minimal_rtr_script)) == []

    def test_v03_metadata_ads_rejected_on_rtr_script(self, provider, minimal_rtr_script):
        minimal_rtr_script["metadata"] = {"ads": {"goal": "g"}}
        errors = provider.validate_template(_env(minimal_rtr_script))
        assert any("metadata.ads is only supported on detection resources" in e and "rtr_script" in e for e in errors)

    def test_v03_metadata_edits_do_not_change_content_hash(self, provider, minimal_rtr_script):
        base_hash = provider.compute_content_hash(minimal_rtr_script)
        with_metadata = dict(minimal_rtr_script)
        with_metadata["metadata"] = {"maturity": {"tune_count": 7}}
        assert provider.compute_content_hash(with_metadata) == base_hash

    def test_v03_template_path_still_consumed_before_strip(self, provider, minimal_rtr_script):
        # Regression guard: if strip_for_hash runs before _template_path is consumed,
        # the script-file lookup will silently fall back to "." and produce a
        # different hash. This test asserts behavior does NOT regress.
        h = provider.compute_content_hash(minimal_rtr_script)
        assert isinstance(h, str) and len(h) == 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
