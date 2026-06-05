"""Tests for talonctl.core.query_collection."""

from pathlib import Path

from talonctl.core.envelope import Envelope
from talonctl.core.query_collection import QueryRef, collect_queries_from_templates
from talonctl.core.template_discovery import DiscoveredTemplate
from tests.unit._helpers import make_envelope


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
    flat = {"resource_id": name, **data}
    return DiscoveredTemplate(
        resource_type=resource_type,
        name=name,
        file_path="/tmp/ignored.yaml",
        tags=[],
        envelope=make_envelope(flat, resource_type),
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


# ---------------------------------------------------------------------------
# v2-authored (native Envelope) tests — verify the template_data property
# transparently surfaces spec fields to collect_queries_from_templates.
# ---------------------------------------------------------------------------


def _make_v2(resource_type: str, name: str, spec: dict, metadata: dict | None = None) -> DiscoveredTemplate:
    """Build a DiscoveredTemplate from a *native* v2 Envelope (not via v1_to_v2)."""
    from talonctl.core.envelope import TYPE_TO_KIND

    md = {"resource_id": name}
    if metadata:
        md.update(metadata)
    env = Envelope(
        api_version="talon/v2",
        kind=TYPE_TO_KIND[resource_type],
        metadata=md,
        spec=spec,
    )
    return DiscoveredTemplate(
        resource_type=resource_type,
        name=name,
        file_path=Path("/tmp/ignored.yaml"),
        tags=[],
        envelope=env,
    )


def test_v2_detection_filter_extracted():
    """Native v2 Envelope: detection.search.filter is found by the extractor."""
    t = _make_v2("detection", "v2_rule", {"search": {"filter": "#vendor=aws | count()"}})
    refs = collect_queries_from_templates({"detection": [t]})
    assert len(refs) == 1
    assert refs[0].query == "#vendor=aws | count()"
    assert refs[0].location == "search.filter"
    assert refs[0].resource_id == "detection.v2_rule"


def test_v2_saved_search_query_string_extracted():
    """Native v2 Envelope: saved_search.query_string -> queryString round-trip via to_working_dict."""
    t = _make_v2("saved_search", "v2_search", {"query_string": "user=* | count()"})
    refs = collect_queries_from_templates({"saved_search": [t]})
    assert len(refs) == 1
    assert refs[0].query == "user=* | count()"
    assert refs[0].location == "queryString"
    assert refs[0].resource_type == "saved_search"


def test_v2_dashboard_widgets_extracted():
    """Native v2 Envelope: dashboard widget queryStrings are fanned out."""
    spec = {
        "widgets": {
            "top_ips": {"queryString": "sourceIPAddress=* | groupBy(ip)"},
        },
        "parameters": {},
    }
    t = _make_v2("dashboard", "v2_dash", spec)
    refs = collect_queries_from_templates({"dashboard": [t]})
    assert len(refs) == 1
    assert refs[0].location == "widgets.top_ips.queryString"


def test_v2_and_v1_detection_produce_identical_query_refs():
    """v2-native and v1-compat Envelopes produce identical QueryRef output."""
    query = "#vendor=okta | count()"

    # v1 path (via make_envelope / v1_to_v2)
    t_v1 = _make("detection", "same_rule", {"search": {"filter": query}})
    # v2 native path
    t_v2 = _make_v2("detection", "same_rule", {"search": {"filter": query}})

    refs_v1 = collect_queries_from_templates({"detection": [t_v1]})
    refs_v2 = collect_queries_from_templates({"detection": [t_v2]})

    assert len(refs_v1) == 1
    assert len(refs_v2) == 1
    assert refs_v1[0].query == refs_v2[0].query
    assert refs_v1[0].location == refs_v2[0].location
    assert refs_v1[0].resource_id == refs_v2[0].resource_id
