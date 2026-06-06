# tests/unit/test_migrate_rewrap.py
from __future__ import annotations

from pathlib import Path

import yaml

from talonctl.core.migrate import scan_templates


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_v1_file_is_marked_for_rewrap_and_serialized(tmp_path):
    res = tmp_path / "resources"
    _write(
        res / "detections" / "susp.yaml",
        "# author comment\nresource_id: susp\nname: Susp\nseverity: 70\nstatus: active\nsearch:\n  filter: '#x'\n",
    )
    results = scan_templates(res)
    by_path = {r.path: r for r in results}
    fr = by_path[res / "detections" / "susp.yaml"]
    assert fr.status == "rewrap"
    assert fr.comments_dropped == 1
    doc = yaml.safe_load(fr.new_text)
    assert doc["apiVersion"] == "talon/v2"
    assert doc["kind"] == "Detection"
    assert doc["metadata"]["resource_id"] == "susp"
    assert doc["spec"]["severity"] == 70
    assert "resource_id" not in doc["spec"]


def test_already_v2_file_is_skipped(tmp_path):
    res = tmp_path / "resources"
    _write(
        res / "detections" / "v2.yaml",
        "apiVersion: talon/v2\nkind: Detection\nmetadata:\n  resource_id: a\nspec:\n  severity: 1\n",
    )
    results = scan_templates(res)
    fr = next(r for r in results if r.path.name == "v2.yaml")
    assert fr.status == "skip"
    assert fr.new_text is None


def test_schema_invalid_v1_file_reports_error_and_is_not_written(tmp_path):
    res = tmp_path / "resources"
    # Missing resource_id for a non-mintable type -> v1_to_v2 raises -> error.
    _write(res / "detections" / "bad.yaml", "name: NoId\nseverity: 5\n")
    results = scan_templates(res)
    fr = next(r for r in results if r.path.name == "bad.yaml")
    assert fr.status == "error"
    assert fr.errors
    assert fr.new_text is None


def test_loads_but_schema_invalid_reports_error(tmp_path):
    # Loads cleanly (has resource_id) but v1_to_v2 yields an empty spec, which the
    # envelope schema rejects (spec.minProperties == 1). Exercises the SECOND error
    # path: validate_authored_envelope, not the load-time ValueError.
    res = tmp_path / "resources"
    _write(res / "detections" / "empty.yaml", "resource_id: empty\nname: Empty\n")
    fr = next(r for r in scan_templates(res) if r.path.name == "empty.yaml")
    assert fr.status == "error"
    assert fr.errors
    assert fr.new_text is None


def test_rewrap_is_idempotent(tmp_path):
    res = tmp_path / "resources"
    src = res / "detections" / "susp.yaml"
    _write(src, "resource_id: susp\nname: Susp\nseverity: 70\nstatus: active\n")
    first = next(r for r in scan_templates(res) if r.path == src).new_text
    src.write_text(first)
    fr2 = next(r for r in scan_templates(res) if r.path == src)
    assert fr2.status == "skip"  # second pass: already v2
