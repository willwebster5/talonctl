"""
Unit tests for DetectionProvider
"""

import pytest
from unittest.mock import Mock

from talonctl.providers.detection_provider import DetectionProvider
from talonctl.core import ResourceAction


class TestDetectionProvider:
    """Test suite for DetectionProvider"""

    @pytest.fixture
    def mock_falcon(self):
        """Create mock Falcon client"""
        return Mock()

    @pytest.fixture
    def provider(self, mock_falcon):
        """Create DetectionProvider instance"""
        return DetectionProvider(mock_falcon)

    def test_get_resource_type(self, provider):
        """Test resource type identifier"""
        assert provider.get_resource_type() == "detection"

    def test_validate_template_valid(self, provider):
        """Test validation of valid template"""
        template = {
            "name": "Test Rule",
            "description": "A test detection rule",
            "severity": 50,
            "search": {"query": "#event_simpleName=ProcessRollup2 | select([aid, FileName])"},
        }

        errors = provider.validate_template(template)
        assert errors == []

    def test_validate_template_missing_fields(self, provider):
        """Test validation catches missing required fields"""
        template = {
            "name": "Test Rule"
            # Missing: description, severity, search
        }

        errors = provider.validate_template(template)
        assert len(errors) >= 3
        assert any("description" in err for err in errors)
        assert any("severity" in err for err in errors)
        assert any("search" in err for err in errors)

    def test_validate_template_invalid_severity(self, provider):
        """Test validation catches invalid severity"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 99,  # Invalid
            "search": {"query": "test"},
        }

        errors = provider.validate_template(template)
        assert any("severity" in err.lower() for err in errors)

    def test_validate_template_missing_query(self, provider):
        """Test validation catches missing query"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {},  # No query
        }

        errors = provider.validate_template(template)
        assert any("query" in err.lower() for err in errors)

    def test_validate_template_invalid_status(self, provider):
        """Test validation catches invalid status"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "status": "paused",  # Invalid
            "search": {"query": "test"},
        }

        errors = provider.validate_template(template)
        assert any("status" in err.lower() for err in errors)

    def test_fetch_remote_state(self, provider, mock_falcon):
        """Test fetching remote rule state"""
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "rule_id": "test123",
                        "name": "Test Rule",
                        "description": "Test",
                        "severity": 50,
                        "status": "active",
                        "query": "test query",
                    }
                ]
            },
        }

        result = provider.fetch_remote_state("test123")

        assert result is not None
        assert result["rule_id"] == "test123"
        assert result["name"] == "Test Rule"
        assert "search" in result
        assert result["search"]["query"] == "test query"

    def test_fetch_remote_state_not_found(self, provider, mock_falcon):
        """Test fetching non-existent rule"""
        mock_falcon.command.return_value = {"status_code": 200, "body": {"resources": []}}

        result = provider.fetch_remote_state("nonexistent")
        assert result is None

    def test_plan_create(self, provider):
        """Test planning rule creation"""
        template = {"name": "New Rule", "description": "Test", "severity": 50, "search": {"query": "test"}}

        change = provider.plan_create(template, "rules/test.yaml")

        assert change.action == ResourceAction.CREATE
        assert change.resource_type == "detection"
        assert change.resource_name == "New Rule"
        assert change.resource_id is None
        assert change.new_value == template
        assert change.template_path == "rules/test.yaml"

    def test_plan_update_with_changes(self, provider):
        """Test planning rule update when changes exist"""
        template = {
            "name": "Test Rule",
            "description": "Updated description",
            "severity": 70,
            "search": {"query": "new query"},
        }

        current_state = {
            "rule_id": "rule123",
            "name": "Test Rule",
            "description": "Old description",
            "severity": 50,
            "search": {"query": "old query"},
        }

        change = provider.plan_update(template, current_state, "rules/test.yaml")

        assert change.action == ResourceAction.UPDATE
        assert change.resource_type == "detection"
        assert change.resource_name == "Test Rule"
        assert change.resource_id == "rule123"
        assert "description" in change.changes
        assert "severity" in change.changes
        assert "search" in change.changes

    def test_plan_update_no_changes(self, provider):
        """Test planning rule update when no changes exist"""
        template = {"name": "Test Rule", "description": "Test", "severity": 50, "search": {"query": "test query"}}

        current_state = template.copy()
        current_state["rule_id"] = "rule123"

        change = provider.plan_update(template, current_state, "rules/test.yaml")

        assert change.action == ResourceAction.NO_CHANGE
        assert change.resource_id == "rule123"

    def test_plan_delete(self, provider, mock_falcon):
        """Test planning rule deletion"""
        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"rule_id": "rule123", "name": "Test Rule", "description": "Test", "severity": 50}]},
        }

        change = provider.plan_delete("rule123", "Test Rule")

        assert change.action == ResourceAction.DELETE
        assert change.resource_type == "detection"
        assert change.resource_name == "Test Rule"
        assert change.resource_id == "rule123"

    def test_apply_create(self, provider, mock_falcon):
        """Test creating a rule"""
        template = {"name": "New Rule", "description": "Test", "severity": 50, "search": {"query": "test query"}}

        mock_falcon.command.return_value = {
            "status_code": 201,
            "body": {"resources": [{"rule_id": "new123", "name": "New Rule"}]},
        }

        result = provider.apply_create(template)

        assert result["rule_id"] == "new123"
        assert result["name"] == "New Rule"
        assert "created_at" in result
        mock_falcon.command.assert_called_once()

    def test_apply_update(self, provider, mock_falcon):
        """Test updating a rule"""
        template = {
            "name": "Updated Rule",
            "description": "New description",
            "severity": 70,
            "search": {"query": "new query"},
        }

        mock_falcon.command.return_value = {
            "status_code": 200,
            "body": {"resources": [{"rule_id": "rule123", "name": "Updated Rule"}]},
        }

        result = provider.apply_update("rule123", template, {})

        assert result["rule_id"] == "rule123"
        assert result["name"] == "Updated Rule"
        assert "updated_at" in result
        # apply_update calls fetch_remote_state first, then patches the rule
        # Verify the last (patch) call was made
        assert mock_falcon.command.call_count >= 2  # fetch_remote_state + patch

    def test_apply_delete(self, provider, mock_falcon):
        """Test deleting a rule"""
        mock_falcon.command.return_value = {"status_code": 200, "body": {}}

        result = provider.apply_delete("rule123")

        assert result["rule_id"] == "rule123"
        assert "deleted_at" in result
        mock_falcon.command.assert_called_once_with("entities_rules_delete_v1", ids=["rule123"])

    def test_compute_content_hash_identical(self, provider):
        """Test hash computation produces identical results for same content"""
        template1 = {"name": "Test", "description": "Test rule", "severity": 50, "search": {"query": "test"}}

        template2 = template1.copy()

        hash1 = provider.compute_content_hash(template1)
        hash2 = provider.compute_content_hash(template2)

        assert hash1 == hash2

    def test_compute_content_hash_different(self, provider):
        """Test hash computation produces different results for different content"""
        template1 = {"name": "Test", "description": "Test rule", "severity": 50, "search": {"query": "test"}}

        template2 = {
            "name": "Test",
            "description": "Different description",
            "severity": 50,
            "search": {"query": "test"},
        }

        hash1 = provider.compute_content_hash(template1)
        hash2 = provider.compute_content_hash(template2)

        assert hash1 != hash2

    def test_extract_dependencies_query_id(self, provider):
        """Test extracting saved search dependency from query_id"""
        template = {"name": "Test", "search": {"query_id": "aws_accounts_search"}}

        deps = provider.extract_dependencies(template)

        assert "saved_search.aws_accounts_search" in deps

    def test_extract_dependencies_readfile(self, provider):
        """Test extracting lookup file dependency from readFile()"""
        template = {"name": "Test", "search": {"query": 'readFile(fileName="aws_service_accounts") | ...'}}

        deps = provider.extract_dependencies(template)

        assert "lookup_file.aws_service_accounts" in deps

    def test_extract_dependencies_in_function(self, provider):
        """Test extracting lookup file dependency from in() function"""
        template = {"name": "Test", "search": {"query": '| srcIpAddr in(name="trusted_ips")'}}

        deps = provider.extract_dependencies(template)

        assert "lookup_file.trusted_ips" in deps

    def test_extract_dependencies_multiple(self, provider):
        """Test extracting multiple dependencies"""
        template = {
            "name": "Test",
            "search": {
                "query": 'readFile(fileName="aws_accounts") | srcIpAddr in(name="trusted_ips")',
                "query_id": "base_search",
            },
        }

        deps = provider.extract_dependencies(template)

        assert len(deps) == 3
        assert "saved_search.base_search" in deps
        assert "lookup_file.aws_accounts" in deps
        assert "lookup_file.trusted_ips" in deps

    def test_prepare_rule_payload(self, provider):
        """Test preparing API payload from template"""
        template = {
            "name": "Test Rule",
            "description": "Test description",
            "severity": 50,
            "status": "active",
            "search": {
                "query": "test query",
                "use_ingest_time": True,
                "search_window": 24,
                "search_window_unit": "hour",
            },
            "mitre_attack": [{"tactic": "TA0001", "technique": "T1078"}],
        }

        payload = provider._prepare_rule_payload(template)

        assert payload["name"] == "Test Rule"
        assert payload["description"] == "Test description"
        assert payload["severity"] == 50
        assert payload["status"] == "active"
        assert payload["search"]["query"] == "test query"
        assert payload["search"]["use_ingest_time"] is True
        assert payload["search"]["search_window"] == 24
        assert payload["search"]["search_window_unit"] == "hour"
        assert "mitre_attack" in payload

    def test_prepare_rule_payload_includes_template_id_when_present(self, provider):
        """template_id in YAML should be passed to create payload for lineage tracking."""
        template = {
            "name": "AWS Root Login",
            "description": "Detects root login",
            "severity": 70,
            "status": "active",
            "template_id": "tmpl-abc123",
            "search": {"filter": "#repo=cloudtrail", "lookback": "-70m"},
        }
        payload = provider._prepare_rule_payload(template)
        assert payload.get("template_id") == "tmpl-abc123"

    def test_prepare_rule_payload_omits_template_id_when_absent(self, provider):
        """Rules without template_id (custom rules) should not include the field."""
        template = {
            "name": "Custom Rule",
            "description": "A custom rule",
            "severity": 50,
            "status": "active",
            "search": {"filter": "#repo=cloudtrail"},
        }
        payload = provider._prepare_rule_payload(template)
        assert "template_id" not in payload

    # --- ADS metadata validation ---

    def test_validate_template_ads_absent_passes(self, provider):
        """ads: block is optional — absence should not cause errors"""
        template = {"name": "Test Rule", "description": "Test", "severity": 50, "search": {"query": "test"}}
        errors = provider.validate_template(template)
        assert errors == []

    def test_validate_template_ads_valid(self, provider):
        """Valid ads: block with required goal field"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": {
                "goal": "Detect unauthorized access to EC2 security groups",
                "mitre_attack": ["Defense Evasion / Impair Defenses"],
                "blind_spots": ["Service-linked role changes not logged"],
                "strategy_abstract": "Correlates EC2 SG changes with known CI/CD patterns",
            },
        }
        errors = provider.validate_template(template)
        assert errors == []

    def test_validate_template_ads_missing_goal(self, provider):
        """ads: block present without goal should fail"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": {
                "strategy_abstract": "Some strategy",
            },
        }
        errors = provider.validate_template(template)
        assert any("ads.goal" in err for err in errors)

    def test_validate_template_ads_empty_goal(self, provider):
        """ads: block with empty goal should fail"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": {
                "goal": "",
            },
        }
        errors = provider.validate_template(template)
        assert any("ads.goal" in err for err in errors)

    def test_validate_template_ads_unknown_field(self, provider):
        """Unknown fields in ads: block should be rejected"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": {
                "goal": "Detect something",
                "unknown_field": "value",
            },
        }
        errors = provider.validate_template(template)
        assert any("unknown_field" in err for err in errors)

    def test_validate_template_ads_list_field_not_list(self, provider):
        """List fields in ads: must be lists"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": {
                "goal": "Detect something",
                "blind_spots": "not a list",
            },
        }
        errors = provider.validate_template(template)
        assert any("ads.blind_spots" in err and "list" in err for err in errors)

    def test_validate_template_ads_string_field_not_string(self, provider):
        """String fields in ads: must be strings"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": {
                "goal": ["not", "a", "string"],
            },
        }
        errors = provider.validate_template(template)
        assert any("ads.goal" in err and "string" in err for err in errors)

    def test_validate_template_ads_not_dict(self, provider):
        """ads: must be a dictionary if present"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": "not a dict",
        }
        errors = provider.validate_template(template)
        assert any("'ads' must be a dictionary" in err for err in errors)

    def test_validate_template_ads_false_positives_mixed_entries(self, provider):
        """false_positives can contain both dicts and string references"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": {
                "goal": "Detect something",
                "false_positives": [
                    {
                        "pattern": "CI/CD Terraform deployments",
                        "characteristics": "github-actions-role ARN",
                        "tuning": "Filtered via $aws_service_account_detector()",
                        "status": "tuned",
                    },
                    "-> knowledge/patterns/aws.md#autoscaling-service-role",
                ],
            },
        }
        errors = provider.validate_template(template)
        assert errors == []

    def test_validate_template_ads_all_optional_fields(self, provider):
        """All optional ADS fields should be accepted"""
        template = {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
            "ads": {
                "goal": "Detect unauthorized access",
                "mitre_attack": ["TA0005:T1562"],
                "strategy_abstract": "Correlates SG changes",
                "technical_context": "CloudTrail, EC2 SG API calls",
                "blind_spots": ["Service-linked roles"],
                "false_positives": ["CI/CD automation"],
                "validation": ["Modify SG from unapproved role"],
                "priority_rationale": "High-value asset modification",
                "response": "See playbook cloud-security-aws.md",
                "ads_created": "2026-04-14",
                "ads_updated": "2026-04-14",
                "ads_author": "Will Webster",
            },
        }
        errors = provider.validate_template(template)
        assert errors == []

    # --- metadata: block validation ---

    @pytest.fixture
    def minimal_detection(self):
        """Minimal valid detection template — used for metadata/ADS test permutations."""
        return {
            "name": "Test Rule",
            "description": "Test",
            "severity": 50,
            "search": {"query": "test"},
        }

    def test_validate_metadata_absent_passes(self, provider, minimal_detection):
        """metadata: block is optional — absence should not cause errors."""
        errors = provider.validate_template(minimal_detection)
        assert errors == []

    def test_validate_metadata_empty_dict_passes(self, provider, minimal_detection):
        """Empty metadata: {} is valid (all fields optional when block present)."""
        minimal_detection["metadata"] = {}
        errors = provider.validate_template(minimal_detection)
        assert errors == []

    def test_validate_metadata_full_valid_block(self, provider, minimal_detection):
        """All four fields populated with valid values passes."""
        minimal_detection["metadata"] = {
            "created": "2026-01-15",
            "last_tuned": "2026-04-10",
            "tune_count": 3,
            "confidence": "high",
        }
        errors = provider.validate_template(minimal_detection)
        assert errors == []

    def test_validate_metadata_not_dict(self, provider, minimal_detection):
        """metadata: must be a dictionary when present."""
        minimal_detection["metadata"] = "not a dict"
        errors = provider.validate_template(minimal_detection)
        assert any("'metadata' must be a dictionary" in err for err in errors)

    def test_validate_metadata_unknown_key(self, provider, minimal_detection):
        """Unknown keys in metadata: are rejected with typo-friendly error."""
        minimal_detection["metadata"] = {"created": "2026-01-15", "confidance": "high"}
        errors = provider.validate_template(minimal_detection)
        assert any("confidance" in err for err in errors)
        # Error should list known keys for user guidance
        assert any("confidence" in err and "created" in err for err in errors)

    def test_validate_metadata_last_tuned_null(self, provider, minimal_detection):
        """last_tuned: null is valid (means never tuned)."""
        minimal_detection["metadata"] = {"last_tuned": None, "tune_count": 0}
        errors = provider.validate_template(minimal_detection)
        assert errors == []

    def test_validate_metadata_bad_date_format(self, provider, minimal_detection):
        """created/last_tuned must match YYYY-MM-DD."""
        minimal_detection["metadata"] = {"created": "2026-4-14"}  # missing zero pad
        errors = provider.validate_template(minimal_detection)
        assert any("metadata.created" in err and "YYYY-MM-DD" in err for err in errors)

    def test_validate_metadata_non_date_string(self, provider, minimal_detection):
        """Non-date strings rejected for date fields."""
        minimal_detection["metadata"] = {"last_tuned": "yesterday"}
        errors = provider.validate_template(minimal_detection)
        assert any("metadata.last_tuned" in err for err in errors)

    def test_validate_metadata_tune_count_negative(self, provider, minimal_detection):
        """tune_count must be >= 0."""
        minimal_detection["metadata"] = {"tune_count": -1}
        errors = provider.validate_template(minimal_detection)
        assert any("metadata.tune_count" in err and "non-negative" in err for err in errors)

    def test_validate_metadata_tune_count_string(self, provider, minimal_detection):
        """tune_count must be an int, not a string."""
        minimal_detection["metadata"] = {"tune_count": "3"}
        errors = provider.validate_template(minimal_detection)
        assert any("metadata.tune_count" in err for err in errors)

    def test_validate_metadata_tune_count_bool_rejected(self, provider, minimal_detection):
        """Python bool is technically int — must be explicitly rejected."""
        minimal_detection["metadata"] = {"tune_count": True}
        errors = provider.validate_template(minimal_detection)
        assert any("metadata.tune_count" in err for err in errors)

    def test_validate_metadata_tune_count_float(self, provider, minimal_detection):
        """tune_count must be int, not float."""
        minimal_detection["metadata"] = {"tune_count": 1.5}
        errors = provider.validate_template(minimal_detection)
        assert any("metadata.tune_count" in err for err in errors)

    def test_validate_metadata_tune_count_zero(self, provider, minimal_detection):
        """tune_count: 0 is valid (boundary)."""
        minimal_detection["metadata"] = {"tune_count": 0}
        errors = provider.validate_template(minimal_detection)
        assert errors == []

    def test_validate_metadata_confidence_valid_values(self, provider, minimal_detection):
        """Each of the four confidence values must pass."""
        for value in ("low", "medium", "high", "validated"):
            minimal_detection["metadata"] = {"confidence": value}
            errors = provider.validate_template(minimal_detection)
            assert errors == [], f"confidence={value} should pass, got {errors}"

    def test_validate_metadata_confidence_invalid(self, provider, minimal_detection):
        """Confidence value not in enum rejected, error names all allowed values."""
        minimal_detection["metadata"] = {"confidence": "mature"}
        errors = provider.validate_template(minimal_detection)
        assert any(
            "metadata.confidence" in err and "low" in err and "validated" in err
            for err in errors
        )

    def test_validate_metadata_errors_accumulate(self, provider, minimal_detection):
        """Multiple metadata errors produce multiple distinct errors (no short-circuit)."""
        minimal_detection["metadata"] = {
            "created": "bad-date",
            "tune_count": -1,
            "confidence": "not-in-enum",
        }
        errors = provider.validate_template(minimal_detection)
        metadata_errors = [e for e in errors if "metadata." in e]
        assert len(metadata_errors) >= 3, f"expected 3+ metadata errors, got {metadata_errors}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
