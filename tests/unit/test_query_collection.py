"""Tests for talonctl.core.query_collection."""

from talonctl.core.query_collection import QueryRef, collect_queries_from_templates


def test_queryref_fields():
    ref = QueryRef(
        resource_type="detection",
        resource_id="detection.foo",
        resource_name="foo",
        query="#event.module=/box/",
        location="search.filter",
        query_snippet="#event.module=/box/",
    )
    assert ref.resource_type == "detection"
    assert ref.resource_id == "detection.foo"
    assert ref.resource_name == "foo"
    assert ref.query == "#event.module=/box/"
    assert ref.location == "search.filter"
    assert ref.query_snippet == "#event.module=/box/"


def test_collect_empty_returns_empty_list():
    assert collect_queries_from_templates({}) == []
