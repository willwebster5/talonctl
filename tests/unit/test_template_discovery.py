"""
Unit tests for TemplateDiscovery
"""

import textwrap

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone

from talonctl.core.template_library import TemplateDiscovery, Template
from talonctl.core.template_discovery import TemplateDiscovery as FsTemplateDiscovery


@pytest.fixture
def discovery():
    return TemplateDiscovery(dry_run=True)


class TestApplyFilters:
    def _make_template(self, severity):
        return Template(
            id="t1",
            name="Test",
            description="",
            severity=severity,
            vendors=["AWS"],
            data_sources=[],
            mitre_attack=[],
            created_timestamp="",
            modified_timestamp=None,
            query="",
            schedule="@every 1h0m",
            search_window_start="-70m",
            outcome="detection",
        )

    def test_severity_filter_works_with_int_severity(self, discovery):
        """API returns integer severity — apply_filters must not crash."""
        templates = [self._make_template(70)]  # int, API path
        result = discovery.apply_filters(templates, severity=["high"])
        assert len(result) == 1

    def test_severity_filter_works_with_str_severity(self, discovery):
        """CSV returns string severity — apply_filters must continue to work."""
        templates = [self._make_template("high")]  # str, CSV path
        result = discovery.apply_filters(templates, severity=["high"])
        assert len(result) == 1

    def test_severity_filter_excludes_non_matching(self, discovery):
        templates = [self._make_template(70)]  # 'high'
        result = discovery.apply_filters(templates, severity=["low"])
        assert len(result) == 0


class TestParseApiTemplate:
    def test_parses_full_entity(self, discovery):
        entity = {
            "id": "tmpl-abc123",
            "name": "AWS - CloudTrail - Root Login",
            "description": "Detects root login events",
            "severity": 70,
            "vendors": ["AWS"],
            "mitre_attack": [
                {"tactic_id": "TA0001", "technique_id": "T1078"},
            ],
            "search": {
                "filter": "#repo=cloudtrail | event.action=ConsoleLogin",
                "lookback": "-70m",
                "outcome": "detection",
            },
            "operation": {"schedule": {"definition": "@every 1h0m"}},
            "created_on": "2026-01-15T12:00:00Z",
            "last_updated_on": "2026-02-19T08:00:00Z",
            "type": "custom",
        }

        template = discovery._parse_api_template(entity)

        assert template is not None
        assert template.id == "tmpl-abc123"
        assert template.name == "AWS - CloudTrail - Root Login"
        assert template.severity == 70
        assert template.severity_numeric == 70
        assert template.vendors == ["AWS"]
        assert template.mitre_attack == ["TA0001:T1078"]
        assert template.query == "#repo=cloudtrail | event.action=ConsoleLogin"
        assert template.search_window_start == "-70m"
        assert template.outcome == "detection"
        assert template.schedule == "@every 1h0m"
        assert template.created_timestamp == "2026-01-15T12:00:00Z"
        assert template.modified_timestamp == "2026-02-19T08:00:00Z"
        assert template.type == "custom"
        assert template.data_sources == []  # not in API

    def test_mitre_normalization(self, discovery):
        entity = {
            "id": "tmpl-001",
            "name": "Test",
            "description": "",
            "severity": 50,
            "vendors": [],
            "mitre_attack": [
                {"tactic_id": "TA0003", "technique_id": "T1136"},
                {"tactic_id": "TA0005", "technique_id": "T1055.001"},
            ],
            "search": {},
            "operation": {},
            "created_on": "",
        }
        template = discovery._parse_api_template(entity)
        assert template.mitre_attack == ["TA0003:T1136", "TA0005:T1055.001"]

    def test_mitre_skips_incomplete_entries(self, discovery):
        entity = {
            "id": "tmpl-002",
            "name": "Test",
            "description": "",
            "severity": 50,
            "vendors": [],
            "mitre_attack": [
                {"tactic_id": "TA0003", "technique_id": ""},  # empty technique
                {"tactic_id": "", "technique_id": "T1078"},  # empty tactic
                {"tactic_id": "TA0001", "technique_id": "T1078"},  # valid
            ],
            "search": {},
            "operation": {},
            "created_on": "",
        }
        template = discovery._parse_api_template(entity)
        assert template.mitre_attack == ["TA0001:T1078"]

    def test_returns_none_on_malformed_entity(self, discovery):
        template = discovery._parse_api_template({"bad": "data"})
        assert template is None

    def test_missing_optional_fields_get_defaults(self, discovery):
        entity = {
            "id": "tmpl-min",
            "name": "Minimal Template",
        }
        template = discovery._parse_api_template(entity)
        assert template is not None
        assert template.description == ""
        assert template.severity == 50
        assert template.vendors == []
        assert template.mitre_attack == []
        assert template.query == ""
        assert template.schedule == "@every 1h0m"
        assert template.search_window_start == "-70m"
        assert template.outcome == "detection"
        assert template.type is None


class TestBuildFqlFilter:
    def test_no_params_returns_none(self, discovery):
        assert discovery._build_fql_filter() is None

    def test_days_back_only(self, discovery):
        result = discovery._build_fql_filter(
            days_back=7,
            _now=datetime(2026, 3, 14, 12, 0, 0, tzinfo=timezone.utc),
        )
        assert result == "last_updated_on:>'2026-03-07T12:00:00Z'"

    def test_single_vendor(self, discovery):
        result = discovery._build_fql_filter(vendor=["aws"])
        assert result == "vendor:'aws'"

    def test_multiple_vendors(self, discovery):
        result = discovery._build_fql_filter(vendor=["aws", "microsoft"])
        assert result == "(vendor:'aws',vendor:'microsoft')"

    def test_vendor_all_ignored(self, discovery):
        result = discovery._build_fql_filter(vendor=["all"])
        assert result is None

    def test_vendor_and_days_back(self, discovery):
        result = discovery._build_fql_filter(
            vendor=["crowdstrike"],
            days_back=30,
            _now=datetime(2026, 3, 14, 0, 0, 0, tzinfo=timezone.utc),
        )
        assert result == "last_updated_on:>'2026-02-12T00:00:00Z'+vendor:'crowdstrike'"


class TestFetchFromApi:
    API_ENTITY = {
        "id": "tmpl-001",
        "name": "AWS Root Login",
        "description": "Root login detected",
        "severity": 70,
        "vendors": ["AWS"],
        "mitre_attack": [{"tactic_id": "TA0001", "technique_id": "T1078"}],
        "search": {"filter": "#repo=cloudtrail", "lookback": "-70m", "outcome": "detection"},
        "operation": {"schedule": {"definition": "@every 1h0m"}},
        "created_on": "2026-01-01T00:00:00Z",
        "last_updated_on": "2026-02-19T00:00:00Z",
    }

    def _make_mock_creds(self):
        return {"falcon_client_id": "test-id", "falcon_client_secret": "test-secret", "base_url": "US1"}

    def _make_token_response(self):
        mock_auth = Mock()
        mock_auth.token.return_value = {"status_code": 201, "body": {"access_token": "fake-token"}}
        return mock_auth

    @patch("talonctl.core.template_library.OAuth2")
    @patch("talonctl.core.template_library.requests")
    def test_fetches_and_parses_templates(self, mock_requests, mock_oauth2, discovery):
        mock_oauth2.return_value = self._make_token_response()

        # Query response returns one ID
        query_resp = Mock()
        query_resp.status_code = 200
        query_resp.json.return_value = {"resources": ["tmpl-001"], "meta": {"pagination": {"total": 1}}}

        # Entities response returns full entity
        entities_resp = Mock()
        entities_resp.status_code = 200
        entities_resp.json.return_value = {"resources": [self.API_ENTITY]}

        mock_requests.get.side_effect = [query_resp, entities_resp]

        with patch.object(discovery, "load_credentials", return_value=self._make_mock_creds()):
            templates = discovery.fetch_from_api()

        assert len(templates) == 1
        assert templates[0].id == "tmpl-001"
        assert templates[0].mitre_attack == ["TA0001:T1078"]

    @patch("talonctl.core.template_library.OAuth2")
    @patch("talonctl.core.template_library.requests")
    def test_passes_fql_filter_to_query(self, mock_requests, mock_oauth2, discovery):
        mock_oauth2.return_value = self._make_token_response()

        query_resp = Mock()
        query_resp.status_code = 200
        query_resp.json.return_value = {"resources": [], "meta": {"pagination": {"total": 0}}}
        mock_requests.get.return_value = query_resp

        with patch.object(discovery, "load_credentials", return_value=self._make_mock_creds()):
            discovery.fetch_from_api(fql_filter="vendor:'aws'")

        call_kwargs = mock_requests.get.call_args
        assert call_kwargs[1]["params"]["filter"] == "vendor:'aws'"

    @patch("talonctl.core.template_library.OAuth2")
    @patch("talonctl.core.template_library.requests")
    def test_raises_on_auth_failure(self, mock_requests, mock_oauth2, discovery):
        mock_auth = Mock()
        mock_auth.token.return_value = {"status_code": 401, "body": {}}
        mock_oauth2.return_value = mock_auth

        with patch.object(discovery, "load_credentials", return_value=self._make_mock_creds()):
            with pytest.raises(ValueError, match="Failed to authenticate"):
                discovery.fetch_from_api()

    @patch("talonctl.core.template_library.OAuth2")
    @patch("talonctl.core.template_library.requests")
    def test_raises_on_api_error(self, mock_requests, mock_oauth2, discovery):
        mock_oauth2.return_value = self._make_token_response()

        error_resp = Mock()
        error_resp.status_code = 400
        error_resp.text = "bad filter"
        mock_requests.get.return_value = error_resp

        with patch.object(discovery, "load_credentials", return_value=self._make_mock_creds()):
            with pytest.raises(ValueError, match="400"):
                discovery.fetch_from_api(fql_filter="bad:fql")

    @patch("talonctl.core.template_library.OAuth2")
    @patch("talonctl.core.template_library.requests")
    def test_paginates_across_multiple_pages(self, mock_requests, mock_oauth2, discovery):
        mock_oauth2.return_value = self._make_token_response()

        # Page 1: 2 IDs, total=3
        page1 = Mock()
        page1.status_code = 200
        page1.json.return_value = {"resources": ["id-1", "id-2"], "meta": {"pagination": {"total": 3}}}
        # Page 2: 1 ID, exhausts total
        page2 = Mock()
        page2.status_code = 200
        page2.json.return_value = {"resources": ["id-3"], "meta": {"pagination": {"total": 3}}}
        # Entities call (all 3 in one batch)
        entities = Mock()
        entities.status_code = 200
        entities.json.return_value = {"resources": [{**self.API_ENTITY, "id": f"id-{i}"} for i in range(1, 4)]}

        mock_requests.get.side_effect = [page1, page2, entities]

        with patch.object(discovery, "load_credentials", return_value=self._make_mock_creds()):
            templates = discovery.fetch_from_api()

        assert len(templates) == 3


class TestProcessTemplateManifestCompat:
    def _make_template(self, id="tmpl-001", modified="2026-02-19T00:00:00Z"):
        return Template(
            id=id,
            name="Test",
            description="",
            severity=50,
            vendors=[],
            data_sources=[],
            mitre_attack=[],
            created_timestamp="2026-01-01T00:00:00Z",
            modified_timestamp=modified,
            query="",
            schedule="@every 1h0m",
            search_window_start="-70m",
            outcome="detection",
        )

    def test_old_manifest_key_does_not_trigger_mass_regen(self, discovery):
        """Existing manifest entries with modified_timestamp must not be treated as updated."""
        discovery.manifest = {
            "templates": {
                "tmpl-001": {
                    "name": "Test",
                    "modified_timestamp": "2026-02-19T00:00:00Z",  # old key
                    # no last_updated_on key
                }
            }
        }
        discovery.local_rules = []
        discovery.deployed_state = {}

        template = self._make_template(modified="2026-02-19T00:00:00Z")
        action = discovery.process_template(template)

        # Should be 'skipped' (no change), NOT 'updated'
        assert action == "skipped"

    def test_new_manifest_key_detects_update(self, discovery):
        """Entry with last_updated_on — newer template version triggers 'updated'."""
        discovery.manifest = {
            "templates": {
                "tmpl-001": {
                    "name": "Test",
                    "last_updated_on": "2026-01-01T00:00:00Z",  # older than template
                }
            }
        }
        discovery.local_rules = []
        discovery.deployed_state = {}

        template = self._make_template(modified="2026-02-19T00:00:00Z")
        action = discovery.process_template(template)

        assert action == "updated"

    def test_manifest_write_uses_new_key(self, discovery, tmp_path):
        """Generated manifest entries should use last_updated_on, not modified_timestamp."""
        discovery.dry_run = False
        discovery.review_dir = tmp_path
        discovery.manifest = {"templates": {}}

        template = self._make_template(modified="2026-02-19T00:00:00Z")
        discovery.generate_template_file(template, "new")

        assert "last_updated_on" in discovery.manifest["templates"]["tmpl-001"]
        assert "modified_timestamp" not in discovery.manifest["templates"]["tmpl-001"]


class TestFsTemplateDiscoveryEnvelopeDelegation:
    """Filesystem TemplateDiscovery delegates to load_envelopes (one parse path).

    Covers core.template_discovery.TemplateDiscovery — the resources/ tree
    discoverer, distinct from the API template_library discoverer above.
    """

    def _write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip())

    def _build_tree(self, tmp_path):
        resources = tmp_path / "resources"

        # (a) v1 detection (flat dict, no apiVersion)
        self._write(
            resources / "detections" / "v1_rule.yaml",
            """
            resource_id: v1_rule
            name: V1 Rule
            type: detection
            tags:
              - aws
            search:
              filter: "#repo=cloudtrail"
            """,
        )

        # (b) canonical v2 detection (name lives under metadata)
        self._write(
            resources / "detections" / "v2_rule.yaml",
            """
            apiVersion: talon/v2
            kind: Detection
            metadata:
              resource_id: v2_rule
              name: V2 Rule
              tags:
                - azure
            spec:
              search:
                filter: "#repo=azure"
            """,
        )

        # (c) multi-doc v2 file (two Detections via ---)
        self._write(
            resources / "detections" / "multi.yaml",
            """
            apiVersion: talon/v2
            kind: Detection
            metadata:
              resource_id: multi_one
              name: Multi One
            spec:
              search:
                filter: "#repo=one"
            ---
            apiVersion: talon/v2
            kind: Detection
            metadata:
              resource_id: multi_two
              name: Multi Two
            spec:
              search:
                filter: "#repo=two"
            """,
        )

        return resources

    def test_discovers_v1_and_v2_with_envelopes(self, tmp_path, caplog):
        resources = self._build_tree(tmp_path)
        disco = FsTemplateDiscovery(resources_dir=resources, project_root=tmp_path)

        with caplog.at_level("WARNING"):
            discovered = disco.discover_all(resource_types=["detection"])

        detections = discovered["detection"]
        by_id = {t.name: t for t in detections}

        # All v1 + v2 + both multi-doc resources discovered.
        assert set(by_id) == {"v1_rule", "v2_rule", "multi_one", "multi_two"}

        # Every DiscoveredTemplate is envelope-backed.
        for t in detections:
            assert t.envelope is not None
            assert t.resource_type == "detection"

        # template_data is derived from the envelope (compatibility property).
        v2 = by_id["v2_rule"]
        assert v2.envelope.resource_id == "v2_rule"
        assert v2.template_data["resource_id"] == "v2_rule"
        assert v2.template_data["name"] == "V2 Rule"
        assert v2.display_name == "V2 Rule"
        assert v2.tags == ["azure"]

        v1 = by_id["v1_rule"]
        assert v1.template_data["resource_id"] == "v1_rule"
        assert v1.template_data["name"] == "V1 Rule"

        # No spurious "missing 'name'" warning for the v2 file.
        assert "missing 'name'" not in caplog.text

    def test_template_data_reinjects_template_path(self, tmp_path):
        resources = self._build_tree(tmp_path)
        disco = FsTemplateDiscovery(resources_dir=resources, project_root=tmp_path)

        discovered = disco.discover_all(resource_types=["detection"])
        v2 = {t.name: t for t in discovered["detection"]}["v2_rule"]

        assert v2.template_data["_template_path"].endswith("v2_rule.yaml")

    def test_valid_resource_types_matches_type_to_dir(self):
        """Drift guard: VALID_RESOURCE_TYPES and TYPE_TO_DIR must cover the same keys."""
        assert set(FsTemplateDiscovery.VALID_RESOURCE_TYPES) == set(FsTemplateDiscovery.TYPE_TO_DIR)

    def test_kind_dir_mismatch_skipped_with_warning(self, tmp_path, caplog):
        resources = tmp_path / "resources"
        # A Detection authored under saved_searches/ — kind/dir mismatch.
        self._write(
            resources / "saved_searches" / "wrong.yaml",
            """
            apiVersion: talon/v2
            kind: Detection
            metadata:
              resource_id: misplaced
              name: Misplaced
            spec:
              search:
                filter: "#repo=x"
            """,
        )
        disco = FsTemplateDiscovery(resources_dir=resources, project_root=tmp_path)

        with caplog.at_level("WARNING"):
            discovered = disco.discover_all(resource_types=["saved_search"])

        assert discovered["saved_search"] == []
        assert "mismatch" in caplog.text.lower()
