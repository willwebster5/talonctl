"""
Unit tests for DependencyValidator — static analysis of saved search references in detection CQL.
"""

import pytest
from unittest.mock import MagicMock

from talonctl.core.dependency_validator import DependencyValidator


class TestExtractFunctionReferences:
    """Test extraction of $function_name() references from CQL."""

    def test_extract_single_function(self):
        cql = "| $aws_enrich_user_identity() | count()"
        refs = DependencyValidator.extract_function_references(cql)
        assert refs == {"aws_enrich_user_identity"}

    def test_extract_multiple_functions(self):
        cql = "| $aws_enrich_user_identity() | $aws_classify_identity_type() | count()"
        refs = DependencyValidator.extract_function_references(cql)
        assert refs == {"aws_enrich_user_identity", "aws_classify_identity_type"}

    def test_no_functions(self):
        cql = '#Vendor="aws" | count()'
        refs = DependencyValidator.extract_function_references(cql)
        assert refs == set()

    def test_function_in_comment_still_extracted(self):
        # Comments in CQL use //, but we extract all references — the CQL engine
        # strips comments before execution, so a commented reference is harmless.
        # We still extract it because false positives are better than missed breaks.
        cql = "// | $old_function()\n| $aws_enrich_user_identity()"
        refs = DependencyValidator.extract_function_references(cql)
        assert "aws_enrich_user_identity" in refs

    def test_function_with_arguments(self):
        # Saved searches can take arguments: $func(field=value)
        cql = "| $score_geo_risk(ip=source.ip)"
        refs = DependencyValidator.extract_function_references(cql)
        assert refs == {"score_geo_risk"}


class TestValidateDependencies:
    """Test full dependency validation across templates."""

    @pytest.fixture
    def mock_discovery(self):
        """Create a mock TemplateDiscovery with known saved searches."""
        discovery = MagicMock()
        # Simulate saved_search templates
        ss1 = MagicMock()
        ss1.name = "aws_enrich_user_identity"
        ss2 = MagicMock()
        ss2.name = "aws_classify_identity_type"
        discovery.discover_all.return_value = {
            "saved_search": [ss1, ss2],
            "detection": [],
            "workflow": [],
            "lookup_file": [],
            "rtr_script": [],
            "rtr_put_file": [],
        }
        return discovery

    def test_valid_dependencies(self, mock_discovery):
        """Detection referencing existing saved searches passes."""
        det = MagicMock()
        det.name = "aws_test_detection"
        det.resource_id = "detection.aws_test_detection"
        det.template_data = {
            "search": {"filter": "| $aws_enrich_user_identity() | $aws_classify_identity_type() | count()"}
        }

        validator = DependencyValidator(mock_discovery)
        issues = validator.validate_detection(det)
        assert issues == []

    def test_broken_dependency(self, mock_discovery):
        """Detection referencing nonexistent saved search flags an issue."""
        det = MagicMock()
        det.name = "aws_broken_detection"
        det.resource_id = "detection.aws_broken_detection"
        det.template_data = {"search": {"filter": "| $aws_enrich_user_identity() | $nonexistent_function() | count()"}}

        validator = DependencyValidator(mock_discovery)
        issues = validator.validate_detection(det)
        assert len(issues) == 1
        assert issues[0].missing_function == "nonexistent_function"
        assert issues[0].detection_id == "detection.aws_broken_detection"

    def test_detection_without_filter(self, mock_discovery):
        """Detection with no search.filter is skipped (no issues)."""
        det = MagicMock()
        det.name = "no_filter_detection"
        det.resource_id = "detection.no_filter_detection"
        det.template_data = {}

        validator = DependencyValidator(mock_discovery)
        issues = validator.validate_detection(det)
        assert issues == []

    def test_validate_all_detections(self, mock_discovery):
        """validate_all() scans all detection templates."""
        det_good = MagicMock()
        det_good.name = "good"
        det_good.resource_id = "detection.good"
        det_good.template_data = {"search": {"filter": "| $aws_enrich_user_identity() | count()"}}
        det_bad = MagicMock()
        det_bad.name = "bad"
        det_bad.resource_id = "detection.bad"
        det_bad.template_data = {"search": {"filter": "| $missing_func() | count()"}}

        mock_discovery.discover_all.return_value["detection"] = [det_good, det_bad]

        validator = DependencyValidator(mock_discovery)
        all_issues = validator.validate_all()
        assert len(all_issues) == 1
        assert all_issues[0].missing_function == "missing_func"
