"""
Unit tests for SavedSearchProvider
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone

from talonctl.providers.saved_search_provider import SavedSearchProvider
from talonctl.core import ResourceAction


class TestSavedSearchProvider:
    """Test suite for SavedSearchProvider"""

    @pytest.fixture
    def mock_falcon(self):
        """Create mock Falcon client"""
        return Mock()

    @pytest.fixture
    def provider(self, mock_falcon):
        """Create SavedSearchProvider instance"""
        return SavedSearchProvider(mock_falcon)

    def test_get_resource_type(self, provider):
        """Test resource type identifier"""
        assert provider.get_resource_type() == "saved_search"

    def test_validate_template_valid(self, provider):
        """Test validation of valid template"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon',
            'description': 'Test saved query'
        }

        errors = provider.validate_template(template)
        assert errors == []

    def test_validate_template_missing_required_fields(self, provider):
        """Test validation catches missing required fields"""
        template = {
            'name': 'test_query'
            # Missing: $schema, queryString, _search_domain
        }

        errors = provider.validate_template(template)
        assert len(errors) >= 3
        assert any('$schema' in err for err in errors)
        assert any('queryString' in err for err in errors)
        assert any('_search_domain' in err for err in errors)

    def test_validate_template_invalid_search_domain(self, provider):
        """Test validation catches invalid search_domain"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'invalid_domain'
        }

        errors = provider.validate_template(template)
        assert any('_search_domain' in err for err in errors)
        assert any('invalid_domain' in err for err in errors)

    def test_validate_template_empty_query(self, provider):
        """Test validation catches empty queryString"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '',
            '_search_domain': 'falcon'
        }

        errors = provider.validate_template(template)
        assert any('queryString' in err for err in errors)

    def test_validate_template_empty_name(self, provider):
        """Test validation catches empty name"""
        template = {
            'name': '',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        errors = provider.validate_template(template)
        assert any('name' in err for err in errors)

    def test_validate_template_invalid_description_type(self, provider):
        """Test validation catches invalid description type"""
        template = {
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon',
            'description': 12345  # Should be string
        }

        errors = provider.validate_template(template)
        assert any('description' in err for err in errors)

    def test_validate_template_with_optional_fields(self, provider):
        """Test validation with all optional fields"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon',
            'description': 'Test query',
            'timeInterval': '24h'
        }

        errors = provider.validate_template(template)
        assert errors == []

    def test_fetch_remote_state_success(self, provider, mock_falcon):
        """Test successful fetch of saved query"""
        # Mock API response - returns on first domain try ('all')
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'resources': [
                    """
$schema: https://schemas.humio.com/query/v0.5.0
name: test_query
queryString: |
  | limit 10
description: Test query
"""
                ]
            }
        }

        result = provider.fetch_remote_state('query-123')

        assert result is not None
        assert result['name'] == 'test_query'
        assert result['id'] == 'query-123'
        # _search_domain will be 'all' since that's the first domain checked
        assert result['_search_domain'] == 'all'

    def test_fetch_remote_state_not_found(self, provider, mock_falcon):
        """Test fetch when query doesn't exist"""
        # Mock API response - not found
        mock_falcon.command.return_value = {
            'status_code': 404,
            'body': {}
        }

        result = provider.fetch_remote_state('nonexistent-id')
        assert result is None

    def test_create_resource_success(self, provider, mock_falcon):
        """Test successful creation of saved query"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'new_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        # Mock API response
        mock_falcon.command.return_value = {
            'status_code': 201,
            'body': {
                'resources': [
                    {'id': 'query-new-123'}
                ]
            }
        }

        result = provider.create_resource(None, template)

        assert result is not None
        assert result['id'] == 'query-new-123'
        assert result['name'] == 'new_query'
        assert result['search_domain'] == 'falcon'

        # Verify command was called with correct override
        mock_falcon.command.assert_called_once()
        call_args = mock_falcon.command.call_args
        assert 'POST,/ngsiem-content/entities/savedqueries-template/v1' in call_args[1]['override']

    def test_update_resource_success_new_id(self, provider, mock_falcon):
        """Test successful update returns new ID"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'updated_query',
            'queryString': '| limit 20',
            '_search_domain': 'falcon'
        }

        current_state = {
            'id': 'query-old-123',
            'name': 'old_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        # Mock API response - PATCH returns new ID!
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'resources': [
                    {'id': 'query-new-456'}
                ]
            }
        }

        result = provider.update_resource('query-old-123', template, current_state)

        assert result is not None
        assert result['id'] == 'query-new-456'
        assert result['old_id'] == 'query-old-123'
        assert result['name'] == 'updated_query'

        # Verify command was called with PATCH
        mock_falcon.command.assert_called_once()
        call_args = mock_falcon.command.call_args
        assert 'PATCH,/ngsiem-content/entities/savedqueries-template/v1' in call_args[1]['override']

    def test_delete_resource_success(self, provider, mock_falcon):
        """Test successful deletion of saved query"""
        # Mock API response
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'meta': {'writes': {'resources_affected': 1}},
                'resources': ['query-123']
            }
        }

        result = provider.delete_resource('query-123')

        assert result is not None
        assert result['id'] == 'query-123'
        assert 'deleted_at' in result

        # Verify command was called with DELETE
        mock_falcon.command.assert_called()

    def test_compute_content_hash_consistency(self, provider):
        """Test content hash is consistent"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon',
            'description': 'Test'
        }

        hash1 = provider.compute_content_hash(template)
        hash2 = provider.compute_content_hash(template)
        hash3 = provider.compute_content_hash(template)

        assert hash1 == hash2 == hash3

    def test_compute_content_hash_changes(self, provider):
        """Test content hash changes when content changes"""
        template1 = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        template2 = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 20',  # Different query
            '_search_domain': 'falcon'
        }

        hash1 = provider.compute_content_hash(template1)
        hash2 = provider.compute_content_hash(template2)

        assert hash1 != hash2

    def test_extract_dependencies_empty(self, provider):
        """Test dependency extraction returns empty (saved queries don't depend on others)"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| readFile("some_file.csv") | limit 10',
            '_search_domain': 'falcon'
        }

        deps = provider.extract_dependencies(template)
        assert deps == {}

    def test_plan_create(self, provider):
        """Test planning a create operation"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'new_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        change = provider.plan_create(template, '/path/to/template.yaml')

        assert change.action == ResourceAction.CREATE
        assert change.resource_type == 'saved_search'
        assert change.resource_name == 'new_query'
        assert change.new_value == template

    def test_plan_update_with_changes(self, provider):
        """Test planning an update when content changed"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 20',
            '_search_domain': 'falcon'
        }

        current_state = {
            'id': 'query-123',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        change = provider.plan_update(template, current_state, '/path/to/template.yaml')

        assert change.action == ResourceAction.UPDATE
        assert change.resource_type == 'saved_search'
        assert change.resource_name == 'test_query'
        assert change.resource_id == 'query-123'
        assert 'queryString' in change.changes
        assert change.changes['queryString']['old'] == '| limit 10'
        assert change.changes['queryString']['new'] == '| limit 20'

    def test_plan_update_no_changes(self, provider):
        """Test planning returns NO_CHANGE when content identical"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        current_state = {
            'id': 'query-123',
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        change = provider.plan_update(template, current_state, '/path/to/template.yaml')

        assert change.action == ResourceAction.NO_CHANGE
        assert change.resource_type == 'saved_search'
        assert change.resource_name == 'test_query'

    def test_plan_delete(self, provider):
        """Test planning a delete operation"""
        change = provider.plan_delete('query-123', 'test_query')

        assert change.action == ResourceAction.DELETE
        assert change.resource_type == 'saved_search'
        assert change.resource_name == 'test_query'
        assert change.resource_id == 'query-123'

    def test_calculate_content_hash_alias(self, provider):
        """Test calculate_content_hash alias works"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        hash1 = provider.calculate_content_hash(template)
        hash2 = provider.compute_content_hash(template)

        assert hash1 == hash2

    def test_apply_create_alias(self, provider, mock_falcon):
        """Test apply_create alias calls create_resource"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        mock_falcon.command.return_value = {
            'status_code': 201,
            'body': {
                'resources': [{'id': 'query-123'}]
            }
        }

        result = provider.apply_create(template)

        assert result is not None
        assert result['id'] == 'query-123'

    def test_apply_update_alias(self, provider, mock_falcon):
        """Test apply_update alias calls update_resource"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 20',
            '_search_domain': 'falcon'
        }

        current_state = {
            'id': 'query-123',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'resources': [{'id': 'query-456'}]
            }
        }

        result = provider.apply_update('query-123', template, current_state)

        assert result is not None
        assert result['id'] == 'query-456'
        assert result['old_id'] == 'query-123'

    def test_apply_delete_alias(self, provider, mock_falcon):
        """Test apply_delete alias calls delete_resource"""
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {
                'meta': {'writes': {'resources_affected': 1}},
                'resources': ['query-123']
            }
        }

        result = provider.apply_delete('query-123')

        assert result is not None
        assert result['id'] == 'query-123'

    def test_valid_search_domains_constant(self, provider):
        """Test VALID_SEARCH_DOMAINS constant"""
        expected = ['all', 'falcon', 'third-party', 'dashboards']
        assert provider.VALID_SEARCH_DOMAINS == expected

    def test_create_resource_failure(self, provider, mock_falcon):
        """Test create_resource handles API errors"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        # Mock API error
        mock_falcon.command.return_value = {
            'status_code': 400,
            'body': {'errors': ['Bad request']}
        }

        with pytest.raises(RuntimeError, match="Failed to create saved query"):
            provider.create_resource(None, template)

    def test_update_resource_failure(self, provider, mock_falcon):
        """Test update_resource handles API errors"""
        template = {
            '$schema': 'https://schemas.humio.com/query/v0.5.0',
            'name': 'test_query',
            'queryString': '| limit 20',
            '_search_domain': 'falcon'
        }

        current_state = {
            'id': 'query-123',
            'name': 'test_query',
            'queryString': '| limit 10',
            '_search_domain': 'falcon'
        }

        # Mock API error
        mock_falcon.command.return_value = {
            'status_code': 500,
            'body': {'errors': ['Server error']}
        }

        with pytest.raises(RuntimeError, match="Failed to update saved query"):
            provider.update_resource('query-123', template, current_state)
