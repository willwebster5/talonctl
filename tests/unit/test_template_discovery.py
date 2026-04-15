"""
Unit tests for TemplateDiscovery
"""
import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# template_discovery.py is a standalone script in scripts/, not part of the talonctl package
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from template_discovery import TemplateDiscovery, Template


@pytest.fixture
def discovery():
    return TemplateDiscovery(dry_run=True)


class TestApplyFilters:

    def _make_template(self, severity):
        return Template(
            id='t1', name='Test', description='', severity=severity,
            vendors=['AWS'], data_sources=[], mitre_attack=[],
            created_timestamp='', modified_timestamp=None,
            query='', schedule='@every 1h0m', search_window_start='-70m',
            outcome='detection',
        )

    def test_severity_filter_works_with_int_severity(self, discovery):
        """API returns integer severity — apply_filters must not crash."""
        templates = [self._make_template(70)]  # int, API path
        result = discovery.apply_filters(templates, severity=['high'])
        assert len(result) == 1

    def test_severity_filter_works_with_str_severity(self, discovery):
        """CSV returns string severity — apply_filters must continue to work."""
        templates = [self._make_template('high')]  # str, CSV path
        result = discovery.apply_filters(templates, severity=['high'])
        assert len(result) == 1

    def test_severity_filter_excludes_non_matching(self, discovery):
        templates = [self._make_template(70)]  # 'high'
        result = discovery.apply_filters(templates, severity=['low'])
        assert len(result) == 0


class TestParseApiTemplate:

    def test_parses_full_entity(self, discovery):
        entity = {
            'id': 'tmpl-abc123',
            'name': 'AWS - CloudTrail - Root Login',
            'description': 'Detects root login events',
            'severity': 70,
            'vendors': ['AWS'],
            'mitre_attack': [
                {'tactic_id': 'TA0001', 'technique_id': 'T1078'},
            ],
            'search': {
                'filter': '#repo=cloudtrail | event.action=ConsoleLogin',
                'lookback': '-70m',
                'outcome': 'detection',
            },
            'operation': {
                'schedule': {'definition': '@every 1h0m'}
            },
            'created_on': '2026-01-15T12:00:00Z',
            'last_updated_on': '2026-02-19T08:00:00Z',
            'type': 'custom',
        }

        template = discovery._parse_api_template(entity)

        assert template is not None
        assert template.id == 'tmpl-abc123'
        assert template.name == 'AWS - CloudTrail - Root Login'
        assert template.severity == 70
        assert template.severity_numeric == 70
        assert template.vendors == ['AWS']
        assert template.mitre_attack == ['TA0001:T1078']
        assert template.query == '#repo=cloudtrail | event.action=ConsoleLogin'
        assert template.search_window_start == '-70m'
        assert template.outcome == 'detection'
        assert template.schedule == '@every 1h0m'
        assert template.created_timestamp == '2026-01-15T12:00:00Z'
        assert template.modified_timestamp == '2026-02-19T08:00:00Z'
        assert template.type == 'custom'
        assert template.data_sources == []  # not in API

    def test_mitre_normalization(self, discovery):
        entity = {
            'id': 'tmpl-001',
            'name': 'Test',
            'description': '',
            'severity': 50,
            'vendors': [],
            'mitre_attack': [
                {'tactic_id': 'TA0003', 'technique_id': 'T1136'},
                {'tactic_id': 'TA0005', 'technique_id': 'T1055.001'},
            ],
            'search': {},
            'operation': {},
            'created_on': '',
        }
        template = discovery._parse_api_template(entity)
        assert template.mitre_attack == ['TA0003:T1136', 'TA0005:T1055.001']

    def test_mitre_skips_incomplete_entries(self, discovery):
        entity = {
            'id': 'tmpl-002',
            'name': 'Test',
            'description': '',
            'severity': 50,
            'vendors': [],
            'mitre_attack': [
                {'tactic_id': 'TA0003', 'technique_id': ''},   # empty technique
                {'tactic_id': '', 'technique_id': 'T1078'},    # empty tactic
                {'tactic_id': 'TA0001', 'technique_id': 'T1078'},  # valid
            ],
            'search': {},
            'operation': {},
            'created_on': '',
        }
        template = discovery._parse_api_template(entity)
        assert template.mitre_attack == ['TA0001:T1078']

    def test_returns_none_on_malformed_entity(self, discovery):
        template = discovery._parse_api_template({'bad': 'data'})
        assert template is None

    def test_missing_optional_fields_get_defaults(self, discovery):
        entity = {
            'id': 'tmpl-min',
            'name': 'Minimal Template',
        }
        template = discovery._parse_api_template(entity)
        assert template is not None
        assert template.description == ''
        assert template.severity == 50
        assert template.vendors == []
        assert template.mitre_attack == []
        assert template.query == ''
        assert template.schedule == '@every 1h0m'
        assert template.search_window_start == '-70m'
        assert template.outcome == 'detection'
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
        result = discovery._build_fql_filter(vendor=['aws'])
        assert result == "vendor:'aws'"

    def test_multiple_vendors(self, discovery):
        result = discovery._build_fql_filter(vendor=['aws', 'microsoft'])
        assert result == "(vendor:'aws',vendor:'microsoft')"

    def test_vendor_all_ignored(self, discovery):
        result = discovery._build_fql_filter(vendor=['all'])
        assert result is None

    def test_vendor_and_days_back(self, discovery):
        result = discovery._build_fql_filter(
            vendor=['crowdstrike'],
            days_back=30,
            _now=datetime(2026, 3, 14, 0, 0, 0, tzinfo=timezone.utc),
        )
        assert result == "last_updated_on:>'2026-02-12T00:00:00Z'+vendor:'crowdstrike'"


class TestFetchFromApi:

    API_ENTITY = {
        'id': 'tmpl-001',
        'name': 'AWS Root Login',
        'description': 'Root login detected',
        'severity': 70,
        'vendors': ['AWS'],
        'mitre_attack': [{'tactic_id': 'TA0001', 'technique_id': 'T1078'}],
        'search': {'filter': '#repo=cloudtrail', 'lookback': '-70m', 'outcome': 'detection'},
        'operation': {'schedule': {'definition': '@every 1h0m'}},
        'created_on': '2026-01-01T00:00:00Z',
        'last_updated_on': '2026-02-19T00:00:00Z',
    }

    def _make_mock_creds(self):
        return {
            'falcon_client_id': 'test-id',
            'falcon_client_secret': 'test-secret',
            'base_url': 'US1'
        }

    def _make_token_response(self):
        mock_auth = Mock()
        mock_auth.token.return_value = {
            'status_code': 201,
            'body': {'access_token': 'fake-token'}
        }
        return mock_auth

    @patch('template_discovery.OAuth2')
    @patch('template_discovery.requests')
    def test_fetches_and_parses_templates(self, mock_requests, mock_oauth2, discovery):
        mock_oauth2.return_value = self._make_token_response()

        # Query response returns one ID
        query_resp = Mock()
        query_resp.status_code = 200
        query_resp.json.return_value = {
            'resources': ['tmpl-001'],
            'meta': {'pagination': {'total': 1}}
        }

        # Entities response returns full entity
        entities_resp = Mock()
        entities_resp.status_code = 200
        entities_resp.json.return_value = {'resources': [self.API_ENTITY]}

        mock_requests.get.side_effect = [query_resp, entities_resp]

        with patch.object(discovery, 'load_credentials', return_value=self._make_mock_creds()):
            templates = discovery.fetch_from_api()

        assert len(templates) == 1
        assert templates[0].id == 'tmpl-001'
        assert templates[0].mitre_attack == ['TA0001:T1078']

    @patch('template_discovery.OAuth2')
    @patch('template_discovery.requests')
    def test_passes_fql_filter_to_query(self, mock_requests, mock_oauth2, discovery):
        mock_oauth2.return_value = self._make_token_response()

        query_resp = Mock()
        query_resp.status_code = 200
        query_resp.json.return_value = {'resources': [], 'meta': {'pagination': {'total': 0}}}
        mock_requests.get.return_value = query_resp

        with patch.object(discovery, 'load_credentials', return_value=self._make_mock_creds()):
            discovery.fetch_from_api(fql_filter="vendor:'aws'")

        call_kwargs = mock_requests.get.call_args
        assert call_kwargs[1]['params']['filter'] == "vendor:'aws'"

    @patch('template_discovery.OAuth2')
    @patch('template_discovery.requests')
    def test_raises_on_auth_failure(self, mock_requests, mock_oauth2, discovery):
        mock_auth = Mock()
        mock_auth.token.return_value = {'status_code': 401, 'body': {}}
        mock_oauth2.return_value = mock_auth

        with patch.object(discovery, 'load_credentials', return_value=self._make_mock_creds()):
            with pytest.raises(ValueError, match="Failed to authenticate"):
                discovery.fetch_from_api()

    @patch('template_discovery.OAuth2')
    @patch('template_discovery.requests')
    def test_raises_on_api_error(self, mock_requests, mock_oauth2, discovery):
        mock_oauth2.return_value = self._make_token_response()

        error_resp = Mock()
        error_resp.status_code = 400
        error_resp.text = 'bad filter'
        mock_requests.get.return_value = error_resp

        with patch.object(discovery, 'load_credentials', return_value=self._make_mock_creds()):
            with pytest.raises(ValueError, match="400"):
                discovery.fetch_from_api(fql_filter="bad:fql")

    @patch('template_discovery.OAuth2')
    @patch('template_discovery.requests')
    def test_paginates_across_multiple_pages(self, mock_requests, mock_oauth2, discovery):
        mock_oauth2.return_value = self._make_token_response()

        # Page 1: 2 IDs, total=3
        page1 = Mock()
        page1.status_code = 200
        page1.json.return_value = {
            'resources': ['id-1', 'id-2'],
            'meta': {'pagination': {'total': 3}}
        }
        # Page 2: 1 ID, exhausts total
        page2 = Mock()
        page2.status_code = 200
        page2.json.return_value = {
            'resources': ['id-3'],
            'meta': {'pagination': {'total': 3}}
        }
        # Entities call (all 3 in one batch)
        entities = Mock()
        entities.status_code = 200
        entities.json.return_value = {'resources': [
            {**self.API_ENTITY, 'id': f'id-{i}'} for i in range(1, 4)
        ]}

        mock_requests.get.side_effect = [page1, page2, entities]

        with patch.object(discovery, 'load_credentials', return_value=self._make_mock_creds()):
            templates = discovery.fetch_from_api()

        assert len(templates) == 3


class TestProcessTemplateManifestCompat:

    def _make_template(self, id='tmpl-001', modified='2026-02-19T00:00:00Z'):
        return Template(
            id=id, name='Test', description='', severity=50,
            vendors=[], data_sources=[], mitre_attack=[],
            created_timestamp='2026-01-01T00:00:00Z',
            modified_timestamp=modified,
            query='', schedule='@every 1h0m',
            search_window_start='-70m', outcome='detection',
        )

    def test_old_manifest_key_does_not_trigger_mass_regen(self, discovery):
        """Existing manifest entries with modified_timestamp must not be treated as updated."""
        discovery.manifest = {
            'templates': {
                'tmpl-001': {
                    'name': 'Test',
                    'modified_timestamp': '2026-02-19T00:00:00Z',  # old key
                    # no last_updated_on key
                }
            }
        }
        discovery.local_rules = []
        discovery.deployed_state = {}

        template = self._make_template(modified='2026-02-19T00:00:00Z')
        action = discovery.process_template(template)

        # Should be 'skipped' (no change), NOT 'updated'
        assert action == 'skipped'

    def test_new_manifest_key_detects_update(self, discovery):
        """Entry with last_updated_on — newer template version triggers 'updated'."""
        discovery.manifest = {
            'templates': {
                'tmpl-001': {
                    'name': 'Test',
                    'last_updated_on': '2026-01-01T00:00:00Z',  # older than template
                }
            }
        }
        discovery.local_rules = []
        discovery.deployed_state = {}

        template = self._make_template(modified='2026-02-19T00:00:00Z')
        action = discovery.process_template(template)

        assert action == 'updated'

    def test_manifest_write_uses_new_key(self, discovery, tmp_path):
        """Generated manifest entries should use last_updated_on, not modified_timestamp."""
        discovery.dry_run = False
        discovery.review_dir = tmp_path
        discovery.manifest = {'templates': {}}

        template = self._make_template(modified='2026-02-19T00:00:00Z')
        discovery.generate_template_file(template, 'new')

        assert 'last_updated_on' in discovery.manifest['templates']['tmpl-001']
        assert 'modified_timestamp' not in discovery.manifest['templates']['tmpl-001']
