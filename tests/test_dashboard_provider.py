"""Tests for DashboardProvider — validation, hashing, dependency extraction."""

import copy
from unittest.mock import MagicMock

import pytest
import yaml

from tests.unit._helpers import make_envelope


def _env(flat):
    """Wrap a legacy flat dashboard dict as an Envelope for the provider's
    Envelope-consuming methods. Defaults a resource_id (which v1_to_v2 requires)
    from the name when the test dict omits it — these tests assert on validation
    errors / planned changes, not on resource_id, so the default is inert.
    """
    if "resource_id" not in flat:
        flat = {**flat, "resource_id": "test_resource"}
    return make_envelope(flat, "dashboard")


@pytest.fixture
def mock_falcon():
    return MagicMock()


@pytest.fixture
def provider(mock_falcon):
    from talonctl.providers.dashboard_provider import DashboardProvider

    return DashboardProvider(mock_falcon)


# --- Minimal valid template fixture ---


@pytest.fixture
def valid_template():
    return {
        "resource_id": "test_dashboard",
        "name": "Test Dashboard",
        "type": "dashboard",
        "description": "A test dashboard",
        "tags": ["test"],
        "_search_domain": "falcon",
        "sections": {
            "section-1": {"collapsed": False, "order": 0, "title": "Section One", "widgetIds": ["widget-aaa"]}
        },
        "widgets": {
            "widget-aaa": {
                "x": 0,
                "y": 0,
                "height": 4,
                "width": 12,
                "title": "Test Widget",
                "type": "query",
                "queryString": '#repo="base_sensor" | count()',
            }
        },
        "parameters": {},
        "sharedTimeInterval": {"enabled": True, "isLive": False, "start": "7d"},
        "updateFrequency": "never",
        "timeSelector": {},
    }


class TestGetResourceType:
    def test_returns_dashboard(self, provider):
        assert provider.get_resource_type() == "dashboard"


class TestValidateTemplate:
    def test_valid_template(self, provider, valid_template):
        errors = provider.validate_template(_env(valid_template))
        assert errors == []

    def test_missing_resource_id(self, provider, valid_template):
        # In v2 the Envelope guarantees a resource_id (metadata.resource_id is
        # mandatory); v1_to_v2 raises at load time when it is absent, so the
        # provider's own resource_id check is unreachable through the Envelope
        # path. Assert the v2 enforcement point instead.
        del valid_template["resource_id"]
        with pytest.raises(ValueError, match="resource_id"):
            make_envelope(valid_template, "dashboard")

    def test_missing_name(self, provider, valid_template):
        del valid_template["name"]
        errors = provider.validate_template(_env(valid_template))
        assert any("name" in e for e in errors)

    def test_missing_sections(self, provider, valid_template):
        del valid_template["sections"]
        errors = provider.validate_template(_env(valid_template))
        assert any("sections" in e for e in errors)

    def test_missing_widgets(self, provider, valid_template):
        del valid_template["widgets"]
        errors = provider.validate_template(_env(valid_template))
        assert any("widgets" in e for e in errors)

    def test_widget_ref_not_in_widgets(self, provider, valid_template):
        valid_template["sections"]["section-1"]["widgetIds"] = ["nonexistent"]
        errors = provider.validate_template(_env(valid_template))
        assert any("nonexistent" in e for e in errors)

    def test_query_widget_missing_querystring(self, provider, valid_template):
        valid_template["widgets"]["widget-aaa"]["queryString"] = ""
        errors = provider.validate_template(_env(valid_template))
        assert any("queryString" in e for e in errors)

    def test_note_widget_no_querystring_ok(self, provider, valid_template):
        valid_template["widgets"]["widget-aaa"] = {
            "x": 0,
            "y": 0,
            "height": 2,
            "width": 12,
            "title": "Note",
            "type": "note",
            "text": "Hello",
        }
        errors = provider.validate_template(_env(valid_template))
        assert errors == []

    def test_parameter_panel_no_querystring_ok(self, provider, valid_template):
        valid_template["widgets"]["widget-aaa"] = {
            "x": 0,
            "y": 0,
            "height": 2,
            "width": 12,
            "title": "Filters",
            "type": "parameterPanel",
            "parameterIds": ["param1"],
        }
        errors = provider.validate_template(_env(valid_template))
        assert errors == []


class TestComputeContentHash:
    def test_returns_consistent_hash(self, provider, valid_template):
        h1 = provider.compute_content_hash(valid_template)
        h2 = provider.compute_content_hash(valid_template)
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex

    def test_strips_iac_fields(self, provider, valid_template):
        t1 = copy.deepcopy(valid_template)
        t2 = copy.deepcopy(valid_template)
        t2["description"] = "Changed description"
        t2["tags"] = ["different"]
        t2["_search_domain"] = "all"
        assert provider.compute_content_hash(t1) == provider.compute_content_hash(t2)

    def test_different_query_different_hash(self, provider, valid_template):
        t1 = copy.deepcopy(valid_template)
        t2 = copy.deepcopy(valid_template)
        t2["widgets"]["widget-aaa"]["queryString"] = "different query"
        assert provider.compute_content_hash(t1) != provider.compute_content_hash(t2)

    def test_normalizes_widget_uuids(self, provider, valid_template):
        """Same content with different widget UUIDs should hash the same."""
        t1 = copy.deepcopy(valid_template)

        # Create t2 with different widget UUID but same content
        t2 = copy.deepcopy(valid_template)
        widget_data = t2["widgets"].pop("widget-aaa")
        t2["widgets"]["6ac67efb-50f7-4a3e-b103-7d63418b5cef"] = widget_data
        t2["sections"]["section-1"]["widgetIds"] = ["6ac67efb-50f7-4a3e-b103-7d63418b5cef"]

        assert provider.compute_content_hash(t1) == provider.compute_content_hash(t2)

    def test_widget_position_change_different_hash(self, provider, valid_template):
        t1 = copy.deepcopy(valid_template)
        t2 = copy.deepcopy(valid_template)
        t2["widgets"]["widget-aaa"]["x"] = 6  # Move widget
        assert provider.compute_content_hash(t1) != provider.compute_content_hash(t2)

    def test_multi_section_ordering(self, provider):
        """Widgets are keyed by section order then position in widgetIds."""
        base = {
            "sections": {
                "sec-a": {"order": 0, "title": "First", "widgetIds": ["w1", "w2"]},
                "sec-b": {"order": 1, "title": "Second", "widgetIds": ["w3"]},
            },
            "widgets": {
                "w1": {"x": 0, "y": 0, "height": 4, "width": 6, "type": "query", "queryString": "q1"},
                "w2": {"x": 6, "y": 0, "height": 4, "width": 6, "type": "query", "queryString": "q2"},
                "w3": {"x": 0, "y": 4, "height": 4, "width": 12, "type": "query", "queryString": "q3"},
            },
            "name": "Test",
        }

        # Same content, different UUIDs
        alt = copy.deepcopy(base)
        alt["widgets"] = {
            "uuid-1": alt["widgets"].pop("w1"),
            "uuid-2": alt["widgets"].pop("w2"),
            "uuid-3": alt["widgets"].pop("w3"),
        }
        alt["sections"]["sec-a"]["widgetIds"] = ["uuid-1", "uuid-2"]
        alt["sections"]["sec-b"]["widgetIds"] = ["uuid-3"]

        assert provider.compute_content_hash(base) == provider.compute_content_hash(alt)


class TestExtractDependencies:
    def test_extracts_saved_search_refs(self, provider):
        template = {
            "widgets": {"w1": {"type": "query", "queryString": "| $identity_enrich_from_email() | $score_geo_risk()"}},
            "parameters": {},
            "sections": {},
        }
        deps = provider.extract_dependencies(template)
        assert "saved_search.identity_enrich_from_email" in deps
        assert "saved_search.score_geo_risk" in deps

    def test_extracts_lookup_file_refs(self, provider):
        template = {
            "widgets": {
                "w1": {"type": "query", "queryString": '| match(file="cato-users.csv", field=ComputerName, column=x)'}
            },
            "parameters": {},
            "sections": {},
        }
        deps = provider.extract_dependencies(template)
        assert "lookup_file.cato_users" in deps

    def test_extracts_from_parameter_queries(self, provider):
        template = {
            "widgets": {},
            "parameters": {
                "dept": {"type": "query", "query": "| $identity_enrich_from_email() | groupBy([id.department])"}
            },
            "sections": {},
        }
        deps = provider.extract_dependencies(template)
        assert "saved_search.identity_enrich_from_email" in deps

    def test_merges_explicit_dependencies(self, provider):
        template = {
            "widgets": {"w1": {"type": "query", "queryString": "| $func_a()"}},
            "parameters": {},
            "sections": {},
            "dependencies": ["saved_search.func_b"],
        }
        deps = provider.extract_dependencies(template)
        assert "saved_search.func_a" in deps
        assert "saved_search.func_b" in deps

    def test_deduplicates(self, provider):
        template = {
            "widgets": {
                "w1": {"type": "query", "queryString": "| $func_a()"},
                "w2": {"type": "query", "queryString": "| $func_a()"},
            },
            "parameters": {},
            "sections": {},
        }
        deps = provider.extract_dependencies(template)
        assert deps.count("saved_search.func_a") == 1

    def test_no_deps_returns_empty(self, provider):
        template = {"widgets": {"w1": {"type": "query", "queryString": "count()"}}, "parameters": {}, "sections": {}}
        deps = provider.extract_dependencies(template)
        assert deps == []

    def test_lookup_filename_normalization(self, provider):
        """Hyphens -> underscores, extension stripped."""
        template = {
            "widgets": {
                "w1": {
                    "type": "query",
                    "queryString": '| match(file="entraid-user-groups-summary.csv", field=x, column=y)',
                }
            },
            "parameters": {},
            "sections": {},
        }
        deps = provider.extract_dependencies(template)
        assert "lookup_file.entraid_user_groups_summary" in deps


class TestPrepareYaml:
    def test_strips_iac_fields(self, provider, valid_template):
        yaml_str = provider._prepare_yaml_payload(valid_template)
        parsed = yaml.safe_load(yaml_str)
        assert "resource_id" not in parsed
        assert "type" not in parsed
        assert "description" not in parsed
        assert "_search_domain" not in parsed
        assert "dependencies" not in parsed

    def test_converts_tags_to_labels(self, provider, valid_template):
        valid_template["tags"] = ["CrowdStrike", "NGSIEM"]
        yaml_str = provider._prepare_yaml_payload(valid_template)
        parsed = yaml.safe_load(yaml_str)
        assert "tags" not in parsed
        assert parsed["labels"] == ["CrowdStrike", "NGSIEM"]

    def test_preserves_name(self, provider, valid_template):
        yaml_str = provider._prepare_yaml_payload(valid_template)
        parsed = yaml.safe_load(yaml_str)
        assert parsed["name"] == "Test Dashboard"

    def test_preserves_widgets_and_sections(self, provider, valid_template):
        yaml_str = provider._prepare_yaml_payload(valid_template)
        parsed = yaml.safe_load(yaml_str)
        assert "sections" in parsed
        assert "widgets" in parsed


class TestFetchDashboardById:
    def test_success(self, provider, mock_falcon):
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "dash-123", "name": "My Dashboard"}]},
        }
        result = provider._fetch_dashboard_by_id("dash-123")
        assert result["id"] == "dash-123"
        mock_falcon.command.assert_called_once()

    def test_not_found(self, provider, mock_falcon):
        mock_falcon.command.return_value = {"status_code": 200, "body": {"resources": []}}
        result = provider._fetch_dashboard_by_id("nonexistent")
        assert result is None

    def test_api_error(self, provider, mock_falcon):
        mock_falcon.command.return_value = {"status_code": 500, "body": {"errors": [{"message": "Internal error"}]}}
        result = provider._fetch_dashboard_by_id("dash-123")
        assert result is None


class TestCreateResource:
    def test_success(self, provider, mock_falcon, valid_template):
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "new-dash-uuid", "name": "Test Dashboard"}]},
        }
        result = provider.create_resource(valid_template)
        assert result["id"] == "new-dash-uuid"
        assert result["dashboard_id"] == "new-dash-uuid"

        call_kwargs = mock_falcon.command.call_args
        assert "POST" in call_kwargs.kwargs.get("override", call_kwargs[1].get("override", ""))

    def test_failure_raises(self, provider, mock_falcon, valid_template):
        mock_falcon.command.return_value = {"status_code": 500, "body": {"errors": [{"message": "Create failed"}]}}
        with pytest.raises(RuntimeError, match="Create failed"):
            provider.create_resource(valid_template)


class TestUpdateResource:
    def test_success_returns_new_id(self, provider, mock_falcon, valid_template):
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "new-id-after-patch", "name": "Test Dashboard"}]},
        }
        current_state = {"id": "old-dash-uuid", "provider_metadata": {"dashboard_id": "old-dash-uuid"}}
        result = provider.update_resource("old-dash-uuid", valid_template, current_state)
        assert result["id"] == "new-id-after-patch"
        assert result["dashboard_id"] == "new-id-after-patch"

    def test_failure_raises(self, provider, mock_falcon, valid_template):
        mock_falcon.command.return_value = {"status_code": 500, "body": {"errors": [{"message": "Update failed"}]}}
        current_state = {"id": "old-id", "provider_metadata": {"dashboard_id": "old-id"}}
        with pytest.raises(RuntimeError, match="Update failed"):
            provider.update_resource("old-id", valid_template, current_state)


class TestDeleteResource:
    def test_success(self, provider, mock_falcon):
        mock_falcon.command.return_value = {"status_code": 200, "body": {"resources": [{"id": "dash-123"}]}}
        result = provider.delete_resource("dash-123")
        assert result is not None

        call_kwargs = mock_falcon.command.call_args
        assert "DELETE" in call_kwargs.kwargs.get("override", call_kwargs[1].get("override", ""))

    def test_failure_raises(self, provider, mock_falcon):
        mock_falcon.command.return_value = {"status_code": 500, "body": {"errors": [{"message": "Delete failed"}]}}
        with pytest.raises(RuntimeError, match="Delete failed"):
            provider.delete_resource("dash-123")


class TestPlanMethods:
    def test_plan_create(self, provider, valid_template):
        from talonctl.core.base_provider import ResourceAction

        env = _env(valid_template)
        change = provider.plan_create(env, "/path/to/template.yaml")
        assert change.action == ResourceAction.CREATE
        assert change.resource_type == "dashboard"
        assert change.resource_id == "test_dashboard"
        assert change.resource_name == "Test Dashboard"
        assert change.envelope is env

    def test_plan_update(self, provider, valid_template):
        from talonctl.core.base_provider import ResourceAction

        current_state = {
            "id": "old-id",
            "content_hash": "different-hash",
            "provider_metadata": {"dashboard_id": "old-id"},
        }
        change = provider.plan_update(_env(valid_template), current_state, "/path/to/template.yaml")
        assert change.action == ResourceAction.UPDATE
        assert change.resource_type == "dashboard"

    def test_plan_update_no_change(self, provider, valid_template):
        from talonctl.core.base_provider import ResourceAction

        content_hash = provider.compute_content_hash(valid_template)
        current_state = {"id": "old-id", "content_hash": content_hash, "provider_metadata": {"dashboard_id": "old-id"}}
        change = provider.plan_update(_env(valid_template), current_state, "/path/to/template.yaml")
        assert change.action == ResourceAction.NO_CHANGE

    def test_plan_delete(self, provider):
        from talonctl.core.base_provider import ResourceAction

        change = provider.plan_delete("test_dashboard", "Test Dashboard")
        assert change.action == ResourceAction.DELETE
        assert change.resource_type == "dashboard"
        assert change.resource_id == "test_dashboard"


class TestApplyAliases:
    def test_apply_create_calls_create_resource(self, provider, mock_falcon, valid_template):
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "new-id", "name": "Test"}]},
        }
        result = provider.apply_create(_env(valid_template))
        assert result["id"] == "new-id"

    def test_apply_delete_calls_delete_resource(self, provider, mock_falcon):
        mock_falcon.command.return_value = {"status_code": 200, "body": {"resources": [{"id": "dash-123"}]}}
        result = provider.apply_delete("dash-123")
        assert result is not None


class TestFetchAllRemoteDashboards:
    def test_returns_dict_keyed_by_name(self, provider, mock_falcon):
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [{"id": "dash-1", "name": "Dashboard One"}, {"id": "dash-2", "name": "Dashboard Two"}]
            },
        }
        result = provider._fetch_all_remote_dashboards()
        assert "Dashboard One" in result
        assert "Dashboard Two" in result
        assert result["Dashboard One"]["id"] == "dash-1"

    def test_caches_result(self, provider, mock_falcon):
        mock_falcon.command.return_value = {"status_code": 200, "body": {"resources": [{"id": "dash-1", "name": "D1"}]}}
        r1 = provider._fetch_all_remote_dashboards()
        r2 = provider._fetch_all_remote_dashboards()
        assert r1 is r2
        assert mock_falcon.command.call_count == 1

    def test_empty_response(self, provider, mock_falcon):
        mock_falcon.command.return_value = {"status_code": 200, "body": {"resources": []}}
        result = provider._fetch_all_remote_dashboards()
        assert result == {}

    def test_handles_string_ids_with_individual_fetch(self, provider, mock_falcon):
        """If list endpoint returns IDs (strings), fetches each individually."""
        mock_falcon.command.side_effect = [
            # First call: list returns string IDs
            {"status_code": 200, "body": {"resources": ["id-1", "id-2"]}},
            # Second call: fetch id-1
            {"status_code": 200, "body": {"resources": [{"id": "id-1", "name": "Dash One"}]}},
            # Third call: fetch id-2
            {"status_code": 200, "body": {"resources": [{"id": "id-2", "name": "Dash Two"}]}},
        ]
        result = provider._fetch_all_remote_dashboards()
        assert "Dash One" in result
        assert "Dash Two" in result

    def test_api_error_returns_empty(self, provider, mock_falcon):
        mock_falcon.command.return_value = {"status_code": 500, "body": {"errors": [{"message": "Server error"}]}}
        result = provider._fetch_all_remote_dashboards()
        assert result == {}


class TestToTemplate:
    def test_adds_iac_fields(self, provider):
        remote = {
            "id": "dash-123",
            "name": "CrowdStrike - Endpoint - MCP Usage",
            "description": "Tracks MCP usage",
            "labels": ["CrowdStrike", "NGSIEM"],
            "sections": {"s1": {"order": 0, "title": "S", "widgetIds": ["w1"]}},
            "widgets": {"w1": {"type": "query", "queryString": "count()"}},
        }
        template = provider.to_template(remote)
        assert template["resource_id"] == "crowdstrike___endpoint___mcp_usage"
        assert template["type"] == "dashboard"
        assert template["tags"] == ["CrowdStrike", "NGSIEM"]
        assert template["_search_domain"] == "falcon"
        assert "labels" not in template

    def test_preserves_dashboard_content(self, provider):
        remote = {
            "id": "dash-456",
            "name": "Test Dash",
            "sections": {"s1": {"order": 0, "title": "S", "widgetIds": ["w1"]}},
            "widgets": {"w1": {"type": "query", "queryString": "q"}},
            "parameters": {"p": {"type": "list"}},
            "sharedTimeInterval": {"enabled": True},
        }
        template = provider.to_template(remote)
        assert template["sections"] == remote["sections"]
        assert template["widgets"] == remote["widgets"]
        assert template["parameters"] == remote["parameters"]

    def test_empty_labels_becomes_empty_tags(self, provider):
        remote = {"id": "d", "name": "D", "sections": {}, "widgets": {}}
        template = provider.to_template(remote)
        assert template.get("tags", []) == []


class TestSuggestPath:
    def test_crowdstrike_dashboard(self, provider):
        template = {"resource_id": "crowdstrike___endpoint___mcp_usage", "tags": ["CrowdStrike"]}
        path = provider.suggest_path(template)
        assert path == "resources/dashboards/crowdstrike/crowdstrike___endpoint___mcp_usage.yaml"

    def test_aws_dashboard(self, provider):
        template = {"resource_id": "aws___cloudtrail___activity", "tags": ["AWS"]}
        path = provider.suggest_path(template)
        assert path == "resources/dashboards/aws/aws___cloudtrail___activity.yaml"

    def test_fallback_to_general(self, provider):
        template = {"resource_id": "my_custom_dashboard", "tags": ["custom"]}
        path = provider.suggest_path(template)
        assert path == "resources/dashboards/general/my_custom_dashboard.yaml"

    def test_infers_from_resource_id_prefix(self, provider):
        template = {"resource_id": "crowdstrike___endpoint___something", "tags": []}
        path = provider.suggest_path(template)
        assert "crowdstrike/" in path


class TestRegistration:
    def test_dashboard_in_valid_resource_types(self):
        from talonctl.core.template_discovery import TemplateDiscovery

        assert "dashboard" in TemplateDiscovery.VALID_RESOURCE_TYPES

    def test_dashboard_in_type_to_dir(self):
        """Template discovery maps 'dashboard' to 'dashboards' directory."""
        from talonctl.core import template_discovery
        import inspect

        source = inspect.getsource(template_discovery)
        assert "'dashboard': 'dashboards'" in source or '"dashboard": "dashboards"' in source

    def test_provider_importable(self):
        from talonctl.providers.dashboard_provider import DashboardProvider

        assert DashboardProvider is not None

    def test_provider_in_init_exports(self):
        from talonctl.providers import DashboardProvider

        assert DashboardProvider is not None


# --- Issue #7 regression: _template_path must not leak into Humio payload ---


class TestIssue7Regression:
    """Direct regression for github.com/willwebster5/talonctl#7."""

    def test_template_path_does_not_leak_into_yaml_payload(self, provider, valid_template):
        tmpl = copy.deepcopy(valid_template)
        tmpl["_template_path"] = "/home/user/project/resources/dashboards/my.yaml"

        yaml_str = provider._prepare_yaml_payload(tmpl)

        assert "_template_path" not in yaml_str, (
            "issue #7: _template_path leaked into dashboard YAML payload — "
            "Humio schema validation will reject the upload."
        )

    def test_resource_id_and_type_and_dependencies_stripped_from_payload(self, provider, valid_template):
        tmpl = copy.deepcopy(valid_template)
        tmpl["dependencies"] = []
        yaml_str = provider._prepare_yaml_payload(tmpl)

        # Universally-IaC fields must not reach Humio.
        assert "resource_id:" not in yaml_str
        assert "dependencies:" not in yaml_str
        # `type:` is a valid YAML key inside widgets (e.g. type: query), so only
        # assert that top-level `type: dashboard` is absent. Parse to verify.
        data = yaml.safe_load(yaml_str)
        assert "type" not in data
        assert "resource_id" not in data
        assert "dependencies" not in data

    def test_description_still_stripped_for_dashboard_specifically(self, provider, valid_template):
        # Dashboard-specific behavior preserved: Humio dashboard YAML schema
        # does not carry `description` at the top level.
        data = yaml.safe_load(provider._prepare_yaml_payload(valid_template))
        assert "description" not in data

    def test_tags_renamed_to_labels(self, provider, valid_template):
        data = yaml.safe_load(provider._prepare_yaml_payload(valid_template))
        assert "tags" not in data
        assert data.get("labels") == ["test"]

    def test_future_internal_field_stripped(self, provider, valid_template):
        # Bug-class coverage: any future _-prefixed tool-internal field is
        # stripped without needing a code change.
        tmpl = copy.deepcopy(valid_template)
        tmpl["_some_future_internal"] = "should-not-leak"
        yaml_str = provider._prepare_yaml_payload(tmpl)
        assert "_some_future_internal" not in yaml_str

    def test_normalize_for_hash_ignores_template_path(self, provider, valid_template):
        hash_without = provider.compute_content_hash(valid_template)

        tmpl_with_path = copy.deepcopy(valid_template)
        tmpl_with_path["_template_path"] = "/tmp/different/path.yaml"
        hash_with = provider.compute_content_hash(tmpl_with_path)

        assert hash_without == hash_with


# --- v0.3.0 metadata namespace redesign ---


@pytest.fixture
def minimal_dashboard():
    return {
        "resource_id": "x",
        "name": "Test Dashboard",
        "sections": {"s0": {"order": 0, "widgetIds": ["w0"]}},
        "widgets": {"w0": {"type": "note", "text": "hi"}},
    }


class TestV03MetadataNamespace:
    def test_metadata_maturity_validates(self, provider, minimal_dashboard):
        minimal_dashboard["metadata"] = {"maturity": {"created": "2026-04-16", "confidence": "medium"}}
        assert provider.validate_template(_env(minimal_dashboard)) == []

    def test_metadata_ads_rejected(self, provider, minimal_dashboard):
        minimal_dashboard["metadata"] = {"ads": {"goal": "g"}}
        errors = provider.validate_template(_env(minimal_dashboard))
        assert any("metadata.ads is only supported on detection resources" in e and "dashboard" in e for e in errors)

    def test_old_top_level_ads_rejected(self, provider, minimal_dashboard):
        minimal_dashboard["ads"] = {"goal": "g"}
        errors = provider.validate_template(_env(minimal_dashboard))
        assert any("Top-level 'ads:' is removed in v0.3.0" in e for e in errors)

    def test_metadata_edits_do_not_change_content_hash(self, provider, minimal_dashboard):
        base_hash = provider.compute_content_hash(minimal_dashboard)
        with_metadata = copy.deepcopy(minimal_dashboard)
        with_metadata["metadata"] = {
            "maturity": {"created": "2026-04-16", "tune_count": 1},
            "acme_corp": {"any": "thing"},
        }
        assert provider.compute_content_hash(with_metadata) == base_hash

    def test_payload_strips_metadata_and_template_path(self, provider, minimal_dashboard):
        # Direct regression test for issue #7 — _template_path must not leak into
        # the Humio YAML upload, and neither should the new metadata: block.
        tmpl = copy.deepcopy(minimal_dashboard)
        tmpl["metadata"] = {"maturity": {"created": "2026-04-16"}, "acme_corp": {"a": 1}}
        tmpl["_template_path"] = "/tmp/x.yaml"
        yaml_str = provider._prepare_yaml_payload(tmpl)
        assert "_template_path" not in yaml_str
        assert "metadata:" not in yaml_str
        assert "acme_corp" not in yaml_str
        assert "resource_id" not in yaml_str
        # Provider-owned fields preserved (or transformed).
        assert "sections:" in yaml_str
        assert "widgets:" in yaml_str
