"""Unit tests for core/metadata_validators.py.

The maturity validator is universal across all seven resource types. These tests
verify shape only — the caller decides whether to run them (e.g. every provider's
validate_template adds the returned errors to its own error list).
"""

from __future__ import annotations

import pytest

from talonctl.core.metadata_validators import reject_old_shape, validate_maturity


class TestValidateMaturityAbsent:
    def test_no_metadata_key_is_valid(self):
        assert validate_maturity({"name": "x"}) == []

    def test_metadata_without_maturity_subkey_is_valid(self):
        assert validate_maturity({"metadata": {"ads": {}}}) == []

    def test_empty_maturity_block_is_valid(self):
        # All four fields are optional when the block is present.
        assert validate_maturity({"metadata": {"maturity": {}}}) == []


class TestValidateMaturityShape:
    def test_metadata_not_a_dict(self):
        errors = validate_maturity({"metadata": "oops"})
        assert errors == ["'metadata' must be a dictionary"]

    def test_maturity_not_a_dict(self):
        errors = validate_maturity({"metadata": {"maturity": "oops"}})
        assert errors == ["'metadata.maturity' must be a dictionary"]

    def test_unknown_maturity_field(self):
        errors = validate_maturity({"metadata": {"maturity": {"typo": "v", "confidence": "high"}}})
        assert len(errors) == 1
        assert "Unknown metadata.maturity key(s): typo" in errors[0]
        assert "Known keys:" in errors[0]

    def test_multiple_unknown_fields_sorted(self):
        errors = validate_maturity({"metadata": {"maturity": {"zzz": 1, "aaa": 2}}})
        assert len(errors) == 1
        assert "aaa, zzz" in errors[0]


class TestValidateMaturityDateFields:
    @pytest.mark.parametrize("field", ["created", "last_tuned"])
    def test_bad_date_format_rejected(self, field):
        errors = validate_maturity({"metadata": {"maturity": {field: "not-a-date"}}})
        assert any(f"metadata.maturity.{field}" in e for e in errors)

    @pytest.mark.parametrize("field", ["created", "last_tuned"])
    def test_valid_iso_date_accepted(self, field):
        assert validate_maturity({"metadata": {"maturity": {field: "2026-04-16"}}}) == []

    def test_last_tuned_allows_null(self):
        assert validate_maturity({"metadata": {"maturity": {"last_tuned": None}}}) == []

    def test_created_rejects_null(self):
        errors = validate_maturity({"metadata": {"maturity": {"created": None}}})
        assert any("metadata.maturity.created" in e for e in errors)


class TestValidateMaturityTuneCount:
    def test_zero_ok(self):
        assert validate_maturity({"metadata": {"maturity": {"tune_count": 0}}}) == []

    def test_positive_int_ok(self):
        assert validate_maturity({"metadata": {"maturity": {"tune_count": 42}}}) == []

    def test_negative_rejected(self):
        errors = validate_maturity({"metadata": {"maturity": {"tune_count": -1}}})
        assert any("tune_count" in e for e in errors)

    def test_bool_rejected(self):
        # True would accidentally pass isinstance(True, int); explicitly rejected.
        errors = validate_maturity({"metadata": {"maturity": {"tune_count": True}}})
        assert any("tune_count" in e for e in errors)

    def test_float_rejected(self):
        errors = validate_maturity({"metadata": {"maturity": {"tune_count": 1.5}}})
        assert any("tune_count" in e for e in errors)


class TestValidateMaturityConfidence:
    @pytest.mark.parametrize("val", ["low", "medium", "high", "validated"])
    def test_allowed_values(self, val):
        assert validate_maturity({"metadata": {"maturity": {"confidence": val}}}) == []

    def test_unknown_value_rejected(self):
        errors = validate_maturity({"metadata": {"maturity": {"confidence": "supreme"}}})
        assert any("metadata.maturity.confidence" in e for e in errors)
        assert any("low, medium, high, validated" in e for e in errors)


class TestValidateMaturityAccumulatesErrors:
    def test_multiple_problems_all_reported(self):
        errors = validate_maturity(
            {
                "metadata": {
                    "maturity": {
                        "created": "bad-date",
                        "tune_count": -5,
                        "confidence": "wrong",
                    }
                }
            }
        )
        # Should surface three distinct errors in one pass.
        assert len(errors) == 3


class TestRejectOldShape:
    def test_clean_template_no_errors(self):
        assert reject_old_shape({"name": "x", "metadata": {"maturity": {}}}) == []

    def test_top_level_ads_rejected(self):
        errors = reject_old_shape({"name": "x", "ads": {"goal": "g"}})
        assert len(errors) == 1
        assert "Top-level 'ads:' is removed in v0.3.0" in errors[0]
        assert "metadata.ads" in errors[0]
        assert "CHANGELOG.md" in errors[0]

    def test_flat_metadata_maturity_field_at_root_rejected(self):
        # Old-style top-level metadata: {created: ..., tune_count: ...}
        errors = reject_old_shape({"metadata": {"created": "2026-04-16", "tune_count": 2}})
        assert len(errors) == 1
        assert "Top-level 'metadata:' now reserves sub-namespaces" in errors[0]
        assert "metadata.maturity" in errors[0]

    def test_new_shape_with_maturity_nested_not_rejected(self):
        # metadata.maturity.created is the new correct shape.
        assert reject_old_shape({"metadata": {"maturity": {"created": "2026-04-16"}}}) == []

    def test_metadata_with_only_third_party_namespace_not_rejected(self):
        assert reject_old_shape({"metadata": {"acme_corp": {"anything": True}}}) == []

    def test_both_old_ads_and_flat_metadata_both_reported(self):
        errors = reject_old_shape({"ads": {}, "metadata": {"created": "2026-04-16"}})
        assert len(errors) == 2
