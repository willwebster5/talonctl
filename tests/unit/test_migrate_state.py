from __future__ import annotations

from pathlib import Path

from talonctl.core.migrate import (
    FileRewrap,
    MigrationReport,
    StateReconcile,
    TemplateIndex,
    build_template_index,
    reconcile_state,
)
from talonctl.core.template_discovery import DiscoveredTemplate


def _idx(ids, by_path=None, by_display=None):
    return TemplateIndex(ids=set(ids), by_path=by_path or {}, by_display=by_display or {})


def test_already_resource_id_keyed_is_noop():
    resources = {"detection": {"susp": {"id": "rule-1", "deployed_at": "t"}}}
    rep = reconcile_state(resources, _idx({("detection", "susp")}))
    assert rep.rekeyed == [] and rep.orphans == [] and rep.unmanaged == [] and rep.conflicts == []


def test_display_name_key_rekeyed_via_template_path():
    resources = {
        "detection": {
            "Suspicious Process": {"template_path": "/r/detections/susp.yaml", "display_name": "Suspicious Process"}
        }
    }
    index = _idx(
        {("detection", "susp")},
        by_path={"/r/detections/susp.yaml": [("detection", "susp")]},
        by_display={("detection", "Suspicious Process"): "susp"},
    )
    rep = reconcile_state(resources, index)
    assert rep.rekeyed == [("detection", "Suspicious Process", "susp")]
    assert rep.unmanaged == []


def test_display_name_fallback_when_path_missing():
    resources = {"detection": {"Old Name": {"display_name": "Old Name"}}}
    index = _idx({("detection", "new_id")}, by_display={("detection", "Old Name"): "new_id"})
    assert reconcile_state(resources, index).rekeyed == [("detection", "Old Name", "new_id")]


def test_unresolvable_entry_is_orphan():
    resources = {"detection": {"Ghost": {"display_name": "Ghost"}}}
    index = _idx({("detection", "real")}, by_display={("detection", "Real"): "real"})
    rep = reconcile_state(resources, index)
    assert rep.orphans == [("detection", "Ghost")]
    assert rep.rekeyed == []
    assert rep.unmanaged == [("detection", "real")]


def test_template_without_state_is_unmanaged():
    rep = reconcile_state({"detection": {}}, _idx({("detection", "fresh")}))
    assert rep.unmanaged == [("detection", "fresh")]


def test_collision_target_already_present_is_conflict():
    resources = {"detection": {"susp": {"id": "rule-1"}, "Suspicious Process": {"display_name": "Suspicious Process"}}}
    index = _idx({("detection", "susp")}, by_display={("detection", "Suspicious Process"): "susp"})
    rep = reconcile_state(resources, index)
    assert rep.rekeyed == []
    assert any(c[0:3] == ("detection", "Suspicious Process", "susp") for c in rep.conflicts)


def test_two_entries_resolving_to_same_id_both_conflict():
    resources = {"detection": {"Name A": {"display_name": "Dup"}, "Name B": {"display_name": "Dup"}}}
    index = _idx({("detection", "dup")}, by_display={("detection", "Dup"): "dup"})
    rep = reconcile_state(resources, index)
    assert rep.rekeyed == []
    assert {c[1] for c in rep.conflicts} == {"Name A", "Name B"}
    assert all(c[3] == "multiple entries resolve to same resource_id" for c in rep.conflicts)


def test_ambiguous_path_resolution_is_conflict():
    resources = {"detection": {"Legacy": {"template_path": "/r/d/multi.yaml", "display_name": "Legacy"}}}
    index = _idx(
        {("detection", "a"), ("detection", "b")},
        by_path={"/r/d/multi.yaml": [("detection", "a"), ("detection", "b")]},
        by_display={("detection", "Legacy"): None},
    )
    rep = reconcile_state(resources, index)
    assert rep.rekeyed == []
    assert any(c[3] == "ambiguous resolution" for c in rep.conflicts)


def test_migration_report_to_dict_is_json_serializable():
    import json

    rep = MigrationReport(
        dry_run=True,
        rewraps=[
            FileRewrap(path=Path("/r/detections/a.yaml"), status="rewrap", comments_dropped=2, kinds=["Detection"])
        ],
        state=StateReconcile(
            rekeyed=[("detection", "Old", "old")],
            orphans=[("workflow", "Ghost")],
            unmanaged=[("detection", "fresh")],
            conflicts=[("detection", "X", "x", "target present")],
        ),
    )
    data = rep.to_dict()
    assert data["dry_run"] is True
    assert data["templates"]["rewrap"][0]["path"].endswith("a.yaml")
    assert data["templates"]["rewrap"][0]["comments_dropped"] == 2
    assert data["state"]["rekeyed"][0] == ["detection", "Old", "old"]
    assert data["state"]["orphans"] == [["workflow", "Ghost"]]
    json.dumps(data)


# -- build_template_index direct tests -----------------------------------------


def _tmpl(rtype, name, file_path, display_name):
    return DiscoveredTemplate(
        resource_type=rtype, name=name, file_path=Path(file_path), tags=[], display_name=display_name
    )


def test_build_index_single_template_per_file():
    discovered = {"detection": [_tmpl("detection", "susp", "/r/detections/susp.yaml", "Susp")]}
    index = build_template_index(discovered)
    assert ("detection", "susp") in index.ids
    assert index.by_path[str(Path("/r/detections/susp.yaml").resolve())] == [("detection", "susp")]
    assert index.by_display[("detection", "Susp")] == "susp"


def test_build_index_same_display_same_type_is_ambiguous_none():
    discovered = {
        "detection": [
            _tmpl("detection", "a", "/r/detections/a.yaml", "Dup"),
            _tmpl("detection", "b", "/r/detections/b.yaml", "Dup"),
        ]
    }
    index = build_template_index(discovered)
    assert index.by_display[("detection", "Dup")] is None  # ambiguous
    assert ("detection", "a") in index.ids and ("detection", "b") in index.ids


def test_build_index_same_display_different_types_are_separate():
    discovered = {
        "detection": [_tmpl("detection", "x", "/r/detections/x.yaml", "Shared")],
        "saved_search": [_tmpl("saved_search", "y", "/r/saved_searches/y.yaml", "Shared")],
    }
    index = build_template_index(discovered)
    assert index.by_display[("detection", "Shared")] == "x"
    assert index.by_display[("saved_search", "Shared")] == "y"


def test_build_index_multiple_resources_same_file():
    f = "/r/detections/multi.yaml"
    discovered = {"detection": [_tmpl("detection", "a", f, "A"), _tmpl("detection", "b", f, "B")]}
    index = build_template_index(discovered)
    assert sorted(index.by_path[str(Path(f).resolve())]) == [("detection", "a"), ("detection", "b")]
