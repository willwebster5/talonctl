"""Unit tests for core/template_sanitizer.py.

The helper strips universally-IaC top-level fields and any underscore-prefixed
tool-internal key. Every provider's API-payload prep and content-hash path
calls this helper as its first step, so these tests lock in the contract
between the helper and all seven providers.
"""

from __future__ import annotations

from talonctl.core.template_sanitizer import (
    RESERVED_TOP_LEVEL_FIELDS,
    strip_for_api,
    strip_for_hash,
)


class TestReservedFieldSet:
    def test_reserved_set_is_exactly_these_four(self):
        # Locked in — changing this set is a multi-provider contract change.
        assert RESERVED_TOP_LEVEL_FIELDS == frozenset({"resource_id", "type", "dependencies", "metadata"})

    def test_description_is_not_reserved(self):
        # description is an API field on detection and saved_search — must NOT
        # be stripped universally.
        assert "description" not in RESERVED_TOP_LEVEL_FIELDS

    def test_tags_is_not_reserved(self):
        # tags is provider-owned (renamed to labels on dashboard, kept by
        # saved_search, etc.) — must NOT be stripped universally.
        assert "tags" not in RESERVED_TOP_LEVEL_FIELDS


class TestStripForApi:
    def test_empty_template_returns_empty(self):
        assert strip_for_api({}) == {}

    def test_strips_resource_id(self):
        assert strip_for_api({"resource_id": "x", "name": "n"}) == {"name": "n"}

    def test_strips_type(self):
        assert strip_for_api({"type": "detection", "name": "n"}) == {"name": "n"}

    def test_strips_dependencies(self):
        assert strip_for_api({"dependencies": ["a.b"], "name": "n"}) == {"name": "n"}

    def test_strips_metadata(self):
        tmpl = {"metadata": {"maturity": {}, "ads": {}, "custom": {}}, "name": "n"}
        assert strip_for_api(tmpl) == {"name": "n"}

    def test_strips_underscore_prefix_keys(self):
        tmpl = {
            "_template_path": "/tmp/x.yaml",
            "_search_domain": "falcon",
            "_future_internal": 42,
            "name": "n",
        }
        assert strip_for_api(tmpl) == {"name": "n"}

    def test_preserves_description(self):
        # Provider-owned — helper must not touch.
        tmpl = {"description": "a desc", "resource_id": "x"}
        assert strip_for_api(tmpl) == {"description": "a desc"}

    def test_preserves_tags(self):
        tmpl = {"tags": ["a", "b"], "resource_id": "x"}
        assert strip_for_api(tmpl) == {"tags": ["a", "b"]}

    def test_preserves_unknown_top_level_keys(self):
        # Passthrough contract — if it's not reserved and doesn't start with
        # `_`, it survives untouched.
        tmpl = {"severity": 50, "search": {"filter": "x"}, "resource_id": "drop"}
        assert strip_for_api(tmpl) == {"severity": 50, "search": {"filter": "x"}}

    def test_input_is_not_mutated(self):
        tmpl = {"resource_id": "x", "name": "n", "metadata": {"maturity": {}}}
        strip_for_api(tmpl)
        # Original dict must retain all keys — helper returns a new dict.
        assert "resource_id" in tmpl
        assert "metadata" in tmpl

    def test_returns_shallow_copy_not_deep(self):
        # Caller responsibility to deepcopy nested structures if they need to
        # mutate them. The contract is shallow-copy.
        nested = {"filter": "x"}
        tmpl = {"search": nested, "resource_id": "drop"}
        result = strip_for_api(tmpl)
        assert result["search"] is nested  # same object, shallow copy


class TestStripForHash:
    def test_identical_rules_to_strip_for_api(self):
        tmpl = {
            "resource_id": "x",
            "type": "detection",
            "dependencies": ["a"],
            "metadata": {"maturity": {"tune_count": 1}},
            "_template_path": "/tmp/x",
            "name": "n",
            "description": "d",
            "tags": ["t"],
            "severity": 50,
        }
        assert strip_for_hash(tmpl) == strip_for_api(tmpl)

    def test_hash_stable_across_metadata_edits(self):
        base = {"name": "n", "severity": 50}
        base_stripped = strip_for_hash(base)

        with_metadata = {
            "name": "n",
            "severity": 50,
            "metadata": {"maturity": {"tune_count": 99}, "acme": {"x": 1}},
        }
        assert strip_for_hash(with_metadata) == base_stripped


class TestIssue7Regression:
    """Direct regression test for github.com/willwebster5/talonctl#7 —
    _template_path leaked into Humio dashboard YAML validation."""

    def test_template_path_stripped(self):
        tmpl = {
            "name": "My Dashboard",
            "_template_path": "/home/user/project/resources/dashboards/my.yaml",
            "sections": {},
            "widgets": {},
        }
        result = strip_for_api(tmpl)
        assert "_template_path" not in result
        assert result == {"name": "My Dashboard", "sections": {}, "widgets": {}}
