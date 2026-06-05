"""
Unit tests for RTRPutFileProvider
"""

import pytest
import hashlib
from unittest.mock import Mock

from talonctl.providers.rtr_put_file_provider import RTRPutFileProvider
from talonctl.core import ResourceAction
from tests.unit._helpers import make_envelope


def _env(flat):
    """Wrap a legacy flat rtr_put_file dict as an Envelope for the provider's
    Envelope-consuming methods. Defaults a resource_id (which v1_to_v2 mints
    from name for rtr_put_file, but needs an explicit one when the test dict
    omits both) — these tests assert on validation/planned changes, not
    resource_id, so the default is inert. The provider resolves file_path
    relative to _template_path, so pass origin_path to re-inject it the way the
    loader will.
    """
    if "resource_id" not in flat:
        flat = {**flat, "resource_id": "test_resource"}
    origin_path = flat.get("_template_path")
    return make_envelope(flat, "rtr_put_file", origin_path=origin_path)


class TestRTRPutFileProvider:
    """Test suite for RTRPutFileProvider"""

    @pytest.fixture
    def mock_falcon(self):
        """Create mock Falcon client (no auth_object -> validation-only mode)"""
        return Mock(spec=[])

    @pytest.fixture
    def provider(self, mock_falcon):
        """Create RTRPutFileProvider in validation-only mode"""
        p = RTRPutFileProvider(mock_falcon)
        assert p.rtr_admin is None
        return p

    @pytest.fixture
    def provider_with_api(self, provider):
        """Provider with mocked RTR admin API"""
        provider.rtr_admin = Mock()
        return provider

    @pytest.fixture
    def binary_file(self, tmp_path):
        """Create a temporary binary file for testing"""
        f = tmp_path / "tool.exe"
        f.write_bytes(b"\x4d\x5a\x90\x00" + b"\x00" * 100)  # PE header stub
        return f

    @pytest.fixture
    def template_path(self, tmp_path):
        """Path to a fake template YAML (for _template_path resolution)"""
        t = tmp_path / "template.yaml"
        t.write_text("")
        return t

    # --- Resource Type ---

    def test_get_resource_type(self, provider):
        assert provider.get_resource_type() == "rtr_put_file"

    # --- Template Validation ---

    def test_validate_template_valid(self, provider, binary_file, template_path):
        template = {
            "name": "tool.exe",
            "description": "Investigation tool",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        errors = provider.validate_template(_env(template))
        assert errors == []

    def test_validate_template_missing_name(self, provider, binary_file, template_path):
        template = {
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        errors = provider.validate_template(_env(template))
        assert any("name" in err.lower() for err in errors)

    def test_validate_template_missing_description(self, provider, binary_file, template_path):
        template = {
            "name": "tool.exe",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        errors = provider.validate_template(_env(template))
        assert any("description" in err.lower() for err in errors)

    def test_validate_template_missing_file_path(self, provider):
        template = {
            "name": "tool.exe",
            "description": "test",
        }
        errors = provider.validate_template(_env(template))
        assert any("file_path" in err.lower() for err in errors)

    def test_validate_template_file_not_found(self, provider, template_path):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "nonexistent.exe",
            "_template_path": str(template_path),
        }
        errors = provider.validate_template(_env(template))
        assert any("not found" in err.lower() for err in errors)

    def test_validate_template_empty_name(self, provider, binary_file, template_path):
        template = {
            "name": "",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        errors = provider.validate_template(_env(template))
        assert any("non-empty" in err for err in errors)

    def test_validate_template_empty_file_path(self, provider):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "   ",
        }
        errors = provider.validate_template(_env(template))
        assert any("file_path" in err.lower() for err in errors)

    def test_validate_template_non_string_file_path(self, provider):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": 12345,
        }
        errors = provider.validate_template(_env(template))
        assert any("file_path" in err.lower() and "string" in err.lower() for err in errors)

    # --- Content Hashing ---

    def test_compute_content_hash_deterministic(self, provider, binary_file, template_path):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        hash1 = provider.compute_content_hash(template)
        hash2 = provider.compute_content_hash(template)
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_compute_content_hash_changes_on_file_change(self, provider, binary_file, template_path):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        hash1 = provider.compute_content_hash(template)

        binary_file.write_bytes(b"\x4d\x5a\x90\x00" + b"\xff" * 200)
        hash2 = provider.compute_content_hash(template)
        assert hash1 != hash2

    def test_compute_content_hash_missing_file_graceful(self, provider, template_path):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "nonexistent.exe",
            "_template_path": str(template_path),
        }
        h = provider.compute_content_hash(template)
        assert isinstance(h, str)
        assert len(h) == 64

    def test_get_file_hash_binary(self, provider, binary_file, template_path):
        """_get_file_hash reads binary content"""
        data = {
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        h = provider._get_file_hash(data)
        expected = hashlib.sha256(binary_file.read_bytes()).hexdigest()
        assert h == expected

    def test_get_file_hash_missing_file_fallback(self, provider, template_path):
        """Missing file returns empty string (or state metadata fallback)"""
        data = {
            "file_path": "nonexistent.exe",
            "_template_path": str(template_path),
        }
        h = provider._get_file_hash(data)
        assert h == ""

    def test_get_file_hash_state_metadata_fallback(self, provider):
        """Falls back to sha256 from state metadata"""
        data = {
            "sha256": "deadbeef1234",
        }
        h = provider._get_file_hash(data)
        assert h == "deadbeef1234"

    # --- Planning ---

    def test_plan_create(self, provider, binary_file, template_path):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        env = _env(template)
        change = provider.plan_create(env, "rtr_put_files/tool.yaml")
        assert change.action == ResourceAction.CREATE
        assert change.resource_type == "rtr_put_file"
        assert change.resource_name == "tool.exe"
        assert change.envelope is env

    def test_plan_update_no_change(self, provider, binary_file, template_path):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        # Current state with same hash
        current = {
            "id": "abc123",
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        change = provider.plan_update(_env(template), current, "rtr_put_files/tool.yaml")
        assert change.action == ResourceAction.NO_CHANGE

    def test_plan_update_file_content_changed(self, provider, tmp_path):
        """Changed binary content is detected via hash"""
        file_a = tmp_path / "tool_a.exe"
        file_a.write_bytes(b"\x00" * 100)
        file_b = tmp_path / "tool_b.exe"
        file_b.write_bytes(b"\xff" * 100)

        tpl_path = tmp_path / "template.yaml"
        tpl_path.write_text("")

        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool_b.exe",
            "_template_path": str(tpl_path),
        }
        current = {
            "id": "abc123",
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool_a.exe",
            "_template_path": str(tpl_path),
        }
        change = provider.plan_update(_env(template), current, "rtr_put_files/tool.yaml")
        assert change.action == ResourceAction.UPDATE
        assert "file_content" in change.changes
        assert "SHA256:" in change.changes["file_content"]["old"]

    def test_plan_delete(self, provider):
        change = provider.plan_delete("abc123", "tool.exe")
        assert change.action == ResourceAction.DELETE
        assert change.resource_type == "rtr_put_file"
        assert change.resource_id == "abc123"

    # --- API Operations ---

    def test_create_resource_binary(self, provider_with_api, binary_file, template_path):
        provider_with_api.rtr_admin.create_put_files.return_value = {
            "status_code": 200,
            "body": {"resources": ["new-id-789"]},
        }
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        result = provider_with_api.create_resource(None, template)
        assert result["id"] == "new-id-789"
        assert result["name"] == "tool.exe"
        assert result["size"] > 0
        provider_with_api.rtr_admin.create_put_files.assert_called_once()

    def test_create_resource_empty_file_raises(self, provider_with_api, tmp_path):
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")
        tpl = tmp_path / "template.yaml"
        tpl.write_text("")

        template = {
            "name": "empty.bin",
            "description": "test",
            "file_path": "empty.bin",
            "_template_path": str(tpl),
        }
        with pytest.raises(RuntimeError, match="empty"):
            provider_with_api.create_resource(None, template)

    def test_create_resource_no_api_raises(self, provider, binary_file, template_path):
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        with pytest.raises(RuntimeError, match="credentials required"):
            provider.create_resource(None, template)

    def test_update_resource_delete_then_create(self, provider_with_api, binary_file, template_path):
        """Update uses delete-then-create pattern"""
        provider_with_api.rtr_admin.delete_put_files.return_value = {"status_code": 200, "body": {}}
        provider_with_api.rtr_admin.create_put_files.return_value = {
            "status_code": 200,
            "body": {"resources": ["new-id-999"]},
        }
        template = {
            "name": "tool.exe",
            "description": "updated",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        result = provider_with_api.update_resource("old-id", template, {})
        assert result["id"] == "new-id-999"

        # Verify delete was called first, then create
        provider_with_api.rtr_admin.delete_put_files.assert_called_once_with(ids="old-id")
        provider_with_api.rtr_admin.create_put_files.assert_called_once()

    def test_delete_resource_200(self, provider_with_api):
        provider_with_api.rtr_admin.delete_put_files.return_value = {"status_code": 200, "body": {}}
        result = provider_with_api.delete_resource("abc123")
        assert result["id"] == "abc123"
        assert "deleted_at" in result

    def test_delete_resource_404_soft_success(self, provider_with_api):
        provider_with_api.rtr_admin.delete_put_files.return_value = {"status_code": 404, "body": {}}
        result = provider_with_api.delete_resource("abc123")
        assert result["id"] == "abc123"
        assert "note" in result

    def test_delete_resource_500_raises(self, provider_with_api):
        provider_with_api.rtr_admin.delete_put_files.return_value = {
            "status_code": 500,
            "body": {"errors": ["Server error"]},
        }
        with pytest.raises(RuntimeError, match="Failed to delete"):
            provider_with_api.delete_resource("abc123")

    def test_fetch_remote_state_found(self, provider_with_api):
        provider_with_api.rtr_admin.get_put_files_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "abc123",
                        "name": "tool.exe",
                        "size": 1024,
                    }
                ]
            },
        }
        result = provider_with_api.fetch_remote_state("abc123")
        assert result is not None
        assert result["id"] == "abc123"

    def test_fetch_remote_state_empty(self, provider_with_api):
        provider_with_api.rtr_admin.get_put_files_v2.return_value = {"status_code": 200, "body": {"resources": []}}
        assert provider_with_api.fetch_remote_state("nope") is None

    def test_fetch_remote_state_no_api(self, provider):
        assert provider.fetch_remote_state("abc123") is None

    # --- to_template and suggest_path ---

    def test_to_template(self, provider):
        remote = {
            "name": "incident_tool.exe",
            "description": "IR tool binary",
        }
        tmpl = provider.to_template(remote)
        assert tmpl["resource_id"] == "incident_toolexe"
        assert tmpl["name"] == "incident_tool.exe"
        assert tmpl["file_path"] == "files/incident_tool.exe"

    def test_suggest_path(self, provider):
        template = {"resource_id": "incident_toolexe"}
        assert provider.suggest_path(template) == "rtr_put_files/incident_toolexe.yaml"

    # --- extract_dependencies ---

    def test_extract_dependencies_empty(self, provider):
        assert provider.extract_dependencies({"name": "test"}) == {}

    # --- apply aliases ---

    def test_apply_create_alias(self, provider_with_api, binary_file, template_path):
        provider_with_api.rtr_admin.create_put_files.return_value = {"status_code": 200, "body": {"resources": ["id1"]}}
        template = {
            "name": "tool.exe",
            "description": "test",
            "file_path": "tool.exe",
            "_template_path": str(template_path),
        }
        result = provider_with_api.apply_create(_env(template))
        assert result["id"] == "id1"

    def test_apply_delete_alias(self, provider_with_api):
        provider_with_api.rtr_admin.delete_put_files.return_value = {"status_code": 200, "body": {}}
        result = provider_with_api.apply_delete("abc123")
        assert result["id"] == "abc123"

    # --- v0.3.0 metadata namespace redesign ---

    @pytest.fixture
    def minimal_rtr_put(self, tmp_path):
        bin_file = tmp_path / "payload.bin"
        bin_file.write_bytes(b"\x00\x01\x02")
        return {
            "resource_id": "x",
            "name": "payload",
            "description": "test put file",
            "file_path": "payload.bin",
            "_template_path": str(tmp_path / "tmpl.yaml"),
        }

    def test_v03_metadata_maturity_validates_on_rtr_put(self, provider, minimal_rtr_put):
        minimal_rtr_put["metadata"] = {"maturity": {"created": "2026-04-16"}}
        assert provider.validate_template(_env(minimal_rtr_put)) == []

    def test_v03_metadata_ads_rejected_on_rtr_put(self, provider, minimal_rtr_put):
        minimal_rtr_put["metadata"] = {"ads": {"goal": "g"}}
        errors = provider.validate_template(_env(minimal_rtr_put))
        assert any("metadata.ads is only supported on detection resources" in e and "rtr_put_file" in e for e in errors)

    def test_v03_metadata_edits_do_not_change_content_hash(self, provider, minimal_rtr_put):
        base_hash = provider.compute_content_hash(minimal_rtr_put)
        with_metadata = dict(minimal_rtr_put)
        with_metadata["metadata"] = {"maturity": {"tune_count": 2}}
        assert provider.compute_content_hash(with_metadata) == base_hash


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
