"""
Unit Tests for LookupFileProvider

Tests all provider methods without making actual API calls.
"""

import os
import json
import hashlib
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open

# Add scripts directory to path
import sys
SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / 'scripts'
sys.path.insert(0, str(SCRIPTS_DIR))

from providers.lookup_file_provider import LookupFileProvider
from core import ResourceAction


class TestLookupFileProvider:
    """Test suite for LookupFileProvider"""

    @pytest.fixture
    def mock_falcon(self):
        """Mock FalconPy client"""
        return Mock()

    @pytest.fixture
    def provider(self, mock_falcon):
        """Create LookupFileProvider instance"""
        return LookupFileProvider(mock_falcon)

    @pytest.fixture
    def temp_csv_file(self):
        """Create a temporary CSV file for testing"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("ip_address,location,owner\n")
            f.write("10.0.1.0/24,us-east-1,engineering\n")
            f.write("192.168.1.0/24,us-west-2,security\n")
            temp_path = f.name

        yield temp_path

        # Cleanup
        try:
            os.unlink(temp_path)
        except:
            pass

    @pytest.fixture
    def temp_json_file(self):
        """Create a temporary JSON file for testing"""
        data = {
            "trusted_ips": [
                {"ip": "10.0.1.0/24", "location": "us-east-1"},
                {"ip": "192.168.1.0/24", "location": "us-west-2"}
            ]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        yield temp_path

        # Cleanup
        try:
            os.unlink(temp_path)
        except:
            pass

    @pytest.fixture
    def valid_csv_template(self, temp_csv_file):
        """Valid CSV lookup file template"""
        return {
            'name': 'trusted_ips.csv',
            'description': 'Trusted IP addresses',
            'format': 'csv',
            'source': temp_csv_file,
            '_search_domain': 'falcon',
            'tags': ['networking', 'security']
        }

    @pytest.fixture
    def valid_json_template(self, temp_json_file):
        """Valid JSON lookup file template"""
        return {
            'name': 'trusted_ips.json',
            'description': 'Trusted IP addresses',
            'format': 'json',
            'source': temp_json_file,
            '_search_domain': 'falcon'
        }

    # Test: Resource Type
    def test_get_resource_type(self, provider):
        """Test resource type identifier"""
        assert provider.get_resource_type() == "lookup_file"

    # Test: Template Validation - Valid Templates
    def test_validate_template_valid_csv(self, provider, valid_csv_template):
        """Test validation of valid CSV template"""
        errors = provider.validate_template(valid_csv_template)
        assert errors == []

    def test_validate_template_valid_json(self, provider, valid_json_template):
        """Test validation of valid JSON template"""
        errors = provider.validate_template(valid_json_template)
        assert errors == []

    # Test: Template Validation - Missing Required Fields
    def test_validate_template_missing_name(self, provider, temp_csv_file):
        """Test validation fails when name is missing"""
        template = {
            'format': 'csv',
            'source': temp_csv_file
        }
        errors = provider.validate_template(template)
        assert any('name' in err.lower() for err in errors)

    def test_validate_template_missing_format(self, provider, temp_csv_file):
        """Test validation fails when format is missing"""
        template = {
            'name': 'test.csv',
            'source': temp_csv_file
        }
        errors = provider.validate_template(template)
        assert any('format' in err.lower() for err in errors)

    def test_validate_template_missing_source(self, provider):
        """Test validation fails when source is missing"""
        template = {
            'name': 'test.csv',
            'format': 'csv'
        }
        errors = provider.validate_template(template)
        assert any('source' in err.lower() for err in errors)

    # Test: Template Validation - Invalid Values
    def test_validate_template_invalid_format(self, provider, temp_csv_file):
        """Test validation fails with invalid format"""
        template = {
            'name': 'test.txt',
            'format': 'txt',  # Invalid
            'source': temp_csv_file
        }
        errors = provider.validate_template(template)
        assert any('invalid format' in err.lower() for err in errors)

    def test_validate_template_invalid_search_domain(self, provider, temp_csv_file):
        """Test validation fails with invalid search domain"""
        template = {
            'name': 'test.csv',
            'format': 'csv',
            'source': temp_csv_file,
            '_search_domain': 'invalid_domain'
        }
        errors = provider.validate_template(template)
        assert any('search_domain' in err.lower() for err in errors)

    def test_validate_template_nonexistent_file(self, provider):
        """Test validation fails when source file doesn't exist"""
        template = {
            'name': 'test.csv',
            'format': 'csv',
            'source': '/nonexistent/path/to/file.csv'
        }
        errors = provider.validate_template(template)
        assert any('not found' in err.lower() for err in errors)

    def test_validate_template_empty_name(self, provider, temp_csv_file):
        """Test validation fails with empty name"""
        template = {
            'name': '',
            'format': 'csv',
            'source': temp_csv_file
        }
        errors = provider.validate_template(template)
        assert any('name' in err.lower() and 'non-empty' in err.lower() for err in errors)

    def test_validate_template_invalid_description_type(self, provider, temp_csv_file):
        """Test validation fails when description is not a string"""
        template = {
            'name': 'test.csv',
            'format': 'csv',
            'source': temp_csv_file,
            'description': 123  # Invalid type
        }
        errors = provider.validate_template(template)
        assert any('description' in err.lower() for err in errors)

    # Test: File Size Validation
    def test_validate_template_csv_size_limit(self, provider):
        """Test validation checks CSV file size limit"""
        # Create a mock template with oversized file
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv', delete=False) as f:
            # Write more than 209.7 MB (just write 210 MB worth of data)
            chunk = b'x' * (1024 * 1024)  # 1 MB chunk
            for _ in range(211):
                f.write(chunk)
            temp_path = f.name

        try:
            template = {
                'name': 'large.csv',
                'format': 'csv',
                'source': temp_path
            }
            errors = provider.validate_template(template)
            assert any('exceeds' in err.lower() and '209.7' in err for err in errors)
        finally:
            os.unlink(temp_path)

    # Test: Content Hashing
    def test_compute_content_hash(self, provider, valid_csv_template):
        """Test content hash computation"""
        hash1 = provider.compute_content_hash(valid_csv_template)
        assert isinstance(hash1, str)
        assert len(hash1) == 64  # SHA256 produces 64 hex characters

    def test_compute_content_hash_consistency(self, provider, valid_csv_template):
        """Test content hash is consistent for same content"""
        hash1 = provider.compute_content_hash(valid_csv_template)
        hash2 = provider.compute_content_hash(valid_csv_template)
        assert hash1 == hash2

    def test_compute_content_hash_changes_on_file_change(self, provider, temp_csv_file):
        """Test content hash changes when file content changes"""
        template1 = {
            'name': 'test.csv',
            'format': 'csv',
            'source': temp_csv_file
        }
        hash1 = provider.compute_content_hash(template1)

        # Modify file
        with open(temp_csv_file, 'a') as f:
            f.write("10.0.2.0/24,us-west-1,operations\n")

        hash2 = provider.compute_content_hash(template1)
        assert hash1 != hash2

    # Test: Fetch Remote State
    def test_fetch_remote_state_found(self, provider, mock_falcon):
        """Test fetching remote state when file exists"""
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': b'ip,location\n10.0.1.0/24,us-east-1'
        }

        result = provider.fetch_remote_state('test.csv')
        assert result is not None
        assert result['filename'] == 'test.csv'
        assert 'content' in result
        assert 'content_hash' in result

    def test_fetch_remote_state_not_found(self, provider, mock_falcon):
        """Test fetching remote state when file doesn't exist"""
        mock_falcon.command.return_value = {
            'status_code': 404,
            'body': {'errors': ['File not found']}
        }

        result = provider.fetch_remote_state('nonexistent.csv')
        assert result is None

    # Test: Planning Operations
    def test_plan_create(self, provider, valid_csv_template):
        """Test planning a create operation"""
        change = provider.plan_create(valid_csv_template, 'templates/test.yaml')
        assert change.action == ResourceAction.CREATE
        assert change.resource_type == 'lookup_file'
        assert change.resource_name == valid_csv_template['name']
        assert change.new_value == valid_csv_template

    def test_plan_update_with_changes(self, provider, valid_csv_template):
        """Test planning an update when content changed"""
        current_state = {
            'filename': 'test.csv',
            'content_hash': 'old_hash_value'
        }

        change = provider.plan_update(valid_csv_template, current_state, 'templates/test.yaml')
        assert change.action == ResourceAction.UPDATE
        assert change.resource_name == valid_csv_template['name']

    def test_plan_update_no_changes(self, provider, valid_csv_template):
        """Test planning an update when no changes detected"""
        # Compute actual hash
        actual_hash = provider.compute_content_hash(valid_csv_template)

        current_state = {
            'filename': 'test.csv',
            'content_hash': actual_hash  # Same hash
        }

        change = provider.plan_update(valid_csv_template, current_state, 'templates/test.yaml')
        assert change.action == ResourceAction.NO_CHANGE

    def test_plan_delete(self, provider):
        """Test planning a delete operation"""
        change = provider.plan_delete('test.csv', 'test.csv')
        assert change.action == ResourceAction.DELETE
        assert change.resource_id == 'test.csv'

    # Test: CRUD Operations (Mocked)
    @patch('builtins.open', new_callable=mock_open, read_data=b'test,data\n1,2')
    def test_apply_create(self, mock_file, provider, mock_falcon, valid_csv_template):
        """Test creating a lookup file"""
        mock_falcon.command.return_value = {
            'status_code': 201,
            'body': {'resources': ['test.csv']}
        }

        result = provider.apply_create(valid_csv_template)
        assert result['filename'] == valid_csv_template['name']
        assert result['format'] == 'csv'
        assert 'created_at' in result

        # Verify API call
        mock_falcon.command.assert_called_once()
        call_args = mock_falcon.command.call_args
        assert 'POST,/ngsiem-content/entities/lookupfiles/v1' in call_args.kwargs['override']

    @patch('builtins.open', new_callable=mock_open, read_data=b'test,data\n1,2')
    def test_apply_update(self, mock_file, provider, mock_falcon, valid_csv_template):
        """Test updating a lookup file"""
        mock_falcon.command.return_value = {
            'status_code': 200,
            'body': {'resources': ['test.csv']}
        }

        current_state = {'filename': 'test.csv', 'search_domain': 'falcon'}
        result = provider.apply_update('test.csv', valid_csv_template, current_state)
        assert result['filename'] == valid_csv_template['name']
        assert 'updated_at' in result

        # Verify API call
        call_args = mock_falcon.command.call_args
        assert 'PATCH,/ngsiem-content/entities/lookupfiles/v1' in call_args.kwargs['override']

    def test_apply_delete(self, provider, mock_falcon):
        """Test deleting a lookup file"""
        mock_falcon.command.return_value = {
            'status_code': 204
        }

        result = provider.apply_delete('test.csv')
        assert result is True

        # Verify API call
        mock_falcon.command.assert_called()

    # Test: Dependency Extraction
    def test_extract_dependencies(self, provider, valid_csv_template):
        """Test dependency extraction (should be empty for lookup files)"""
        deps = provider.extract_dependencies(valid_csv_template)
        assert deps == {}

    # Test: Convenience Methods
    def test_create_resource_alias(self, provider, mock_falcon, valid_csv_template):
        """Test create_resource is an alias for apply_create"""
        with patch.object(provider, 'apply_create', return_value={'id': 'test'}) as mock_apply:
            result = provider.create_resource(valid_csv_template)
            mock_apply.assert_called_once_with(valid_csv_template)
            assert result == {'id': 'test'}

    def test_update_resource_alias(self, provider, mock_falcon, valid_csv_template):
        """Test update_resource is an alias for apply_update"""
        current_state = {'filename': 'test.csv'}
        with patch.object(provider, 'apply_update', return_value={'id': 'test'}) as mock_apply:
            result = provider.update_resource('test.csv', valid_csv_template, current_state)
            mock_apply.assert_called_once_with('test.csv', valid_csv_template, current_state)
            assert result == {'id': 'test'}

    def test_delete_resource_alias(self, provider, mock_falcon):
        """Test delete_resource is an alias for apply_delete"""
        with patch.object(provider, 'apply_delete', return_value=True) as mock_apply:
            result = provider.delete_resource('test.csv')
            mock_apply.assert_called_once_with('test.csv')
            assert result is True

    # Test: Valid Search Domains
    def test_valid_search_domains(self, provider):
        """Test all valid search domains are accepted"""
        for domain in provider.VALID_SEARCH_DOMAINS:
            template = {
                'name': 'test.csv',
                'format': 'csv',
                'source': '/tmp/test.csv',
                '_search_domain': domain
            }
            # Create a temporary file for validation
            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                f.write("test\n")
                template['source'] = f.name

            try:
                errors = provider.validate_template(template)
                # Should not have search_domain errors
                assert not any('search_domain' in err.lower() for err in errors)
            finally:
                os.unlink(template['source'])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
