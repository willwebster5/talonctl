"""Tests for talonctl.core.query_collection."""

from talonctl.core.query_collection import QueryRef, collect_queries_from_templates
from talonctl.core.template_discovery import DiscoveredTemplate


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


def _make(resource_type: str, name: str, data: dict) -> DiscoveredTemplate:
    return DiscoveredTemplate(
        resource_type=resource_type,
        name=name,
        file_path="/tmp/ignored.yaml",
        template_data=data,
        tags=[],
    )


def test_snippet_collapses_newlines_and_truncates():
    from talonctl.core.query_collection import _make_snippet

    short = _make_snippet("  foo\nbar  ")
    assert short == "foo bar"

    long_query = "a" * 150
    snippet = _make_snippet(long_query)
    assert len(snippet) == 103  # 100 chars + "..."
    assert snippet.endswith("...")


def test_detection_with_filter():
    t = _make("detection", "box_new_device", {"search": {"filter": "#event.module=/box/"}})
    refs = collect_queries_from_templates({"detection": [t]})
    assert len(refs) == 1
    assert refs[0].location == "search.filter"
    assert refs[0].query == "#event.module=/box/"
    assert refs[0].resource_id == "detection.box_new_device"
    assert refs[0].resource_type == "detection"


def test_detection_with_query_only():
    t = _make("detection", "foo", {"search": {"query": "#vendor=aws"}})
    refs = collect_queries_from_templates({"detection": [t]})
    assert len(refs) == 1
    assert refs[0].location == "search.query"


def test_detection_prefers_filter_over_query():
    t = _make("detection", "foo", {"search": {"filter": "A", "query": "B"}})
    refs = collect_queries_from_templates({"detection": [t]})
    assert len(refs) == 1
    assert refs[0].query == "A"
    assert refs[0].location == "search.filter"


def test_detection_without_query_is_skipped():
    t = _make("detection", "foo", {"search": {}})
    assert collect_queries_from_templates({"detection": [t]}) == []

    t2 = _make("detection", "foo", {"search": {"filter": "   "}})
    assert collect_queries_from_templates({"detection": [t2]}) == []


def test_saved_search_with_query_string():
    t = _make("saved_search", "slow_login", {"queryString": "user=* | count()"})
    refs = collect_queries_from_templates({"saved_search": [t]})
    assert len(refs) == 1
    assert refs[0].location == "queryString"
    assert refs[0].query == "user=* | count()"
    assert refs[0].resource_type == "saved_search"


def test_saved_search_without_query_skipped():
    t = _make("saved_search", "foo", {"queryString": ""})
    assert collect_queries_from_templates({"saved_search": [t]}) == []

    t2 = _make("saved_search", "foo", {})
    assert collect_queries_from_templates({"saved_search": [t2]}) == []


def test_dashboard_widgets_and_parameters_fan_out():
    template_data = {
        "widgets": {
            "top_ips": {"type": "query", "queryString": "sourceIPAddress=* | groupBy(ip)"},
            "top_users": {"type": "query", "queryString": "user=* | groupBy(user)"},
            "header": {"type": "markdown", "queryString": ""},
        },
        "parameters": {
            "region": {"query": "region=*"},
            "empty": {"query": ""},
        },
    }
    t = _make("dashboard", "threat_hunting", template_data)
    refs = collect_queries_from_templates({"dashboard": [t]})
    assert len(refs) == 3

    locations = sorted(r.location for r in refs)
    assert locations == [
        "parameters.region.query",
        "widgets.top_ips.queryString",
        "widgets.top_users.queryString",
    ]

    for r in refs:
        assert r.resource_type == "dashboard"
        assert r.resource_id == "dashboard.threat_hunting"


def test_dashboard_no_widgets_or_params():
    t = _make("dashboard", "empty", {})
    assert collect_queries_from_templates({"dashboard": [t]}) == []


def test_query_less_types_return_empty():
    for resource_type in ("workflow", "lookup_file", "rtr_script", "rtr_put_file"):
        t = _make(resource_type, "foo", {"name": "foo"})
        assert collect_queries_from_templates({resource_type: [t]}) == [], resource_type


def test_mixed_types_only_include_known():
    detection = _make("detection", "d1", {"search": {"filter": "A"}})
    workflow = _make("workflow", "wf1", {"name": "wf1"})
    refs = collect_queries_from_templates(
        {
            "detection": [detection],
            "workflow": [workflow],
        }
    )
    assert len(refs) == 1
    assert refs[0].resource_type == "detection"
