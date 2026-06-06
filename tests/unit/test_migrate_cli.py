from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from talonctl.cli import cli


def _project(tmp_path: Path) -> Path:
    (tmp_path / ".crowdstrike").mkdir()
    (tmp_path / "resources" / "detections").mkdir(parents=True)
    (tmp_path / "resources" / "detections" / "susp.yaml").write_text(
        "# comment\nresource_id: susp\nname: Susp\nseverity: 70\nstatus: active\nsearch:\n  filter: '#x'\n"
    )
    return tmp_path


def test_dry_run_writes_nothing(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    monkeypatch.chdir(proj)
    src = proj / "resources" / "detections" / "susp.yaml"
    before = src.read_text()
    result = CliRunner().invoke(cli, ["migrate"])
    assert result.exit_code == 0, result.output
    assert src.read_text() == before
    assert not (proj / ".crowdstrike" / "deployed_state.json").exists()


def test_write_rewraps_templates_in_place(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    monkeypatch.chdir(proj)
    src = proj / "resources" / "detections" / "susp.yaml"
    result = CliRunner().invoke(cli, ["migrate", "--write"])
    assert result.exit_code == 0, result.output
    doc = yaml.safe_load(src.read_text())
    assert doc["apiVersion"] == "talon/v2"
    assert doc["metadata"]["resource_id"] == "susp"


def test_write_is_idempotent(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    monkeypatch.chdir(proj)
    src = proj / "resources" / "detections" / "susp.yaml"
    CliRunner().invoke(cli, ["migrate", "--write"])
    after_first = src.read_text()
    CliRunner().invoke(cli, ["migrate", "--write"])
    assert src.read_text() == after_first


def test_templates_only_skips_state(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    monkeypatch.chdir(proj)
    result = CliRunner().invoke(cli, ["migrate", "--write", "--templates-only"])
    assert result.exit_code == 0, result.output


def test_state_and_templates_only_are_mutually_exclusive(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    monkeypatch.chdir(proj)
    result = CliRunner().invoke(cli, ["migrate", "--templates-only", "--state-only"])
    assert result.exit_code != 0


def test_json_output(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    monkeypatch.chdir(proj)
    out = proj / "report.json"
    result = CliRunner().invoke(cli, ["migrate", "--format", "json", "-o", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["dry_run"] is True
    assert data["templates"]["rewrap"]


def _project_with_v3_state(tmp_path: Path) -> Path:
    proj = _project(tmp_path)
    state = {
        "version": "3.0",
        "resources": {
            "detection": {
                "Susp": {
                    "type": "detection",
                    "id": "rule-123",
                    "content_hash": "abc",
                    "template_path": str(proj / "resources" / "detections" / "susp.yaml"),
                    "deployed_at": "2026-01-01T00:00:00Z",
                    "last_modified": "2026-01-01T00:00:00Z",
                    "provider_metadata": {},
                    "dependencies": [],
                    "display_name": "Susp",
                }
            }
        },
        "resource_graph": {"nodes": [], "edges": []},
    }
    (proj / ".crowdstrike" / "deployed_state.json").write_text(json.dumps(state))
    return proj


def test_state_only_dry_run_leaves_state_untouched(tmp_path, monkeypatch):
    proj = _project_with_v3_state(tmp_path)
    monkeypatch.chdir(proj)
    statefile = proj / ".crowdstrike" / "deployed_state.json"
    before = statefile.read_text()
    result = CliRunner().invoke(cli, ["migrate", "--state-only"])
    assert result.exit_code == 0, result.output
    assert statefile.read_text() == before


def test_state_only_write_rekeys_to_resource_id(tmp_path, monkeypatch):
    proj = _project_with_v3_state(tmp_path)
    monkeypatch.chdir(proj)
    statefile = proj / ".crowdstrike" / "deployed_state.json"
    result = CliRunner().invoke(cli, ["migrate", "--state-only", "--write"])
    assert result.exit_code == 0, result.output
    data = json.loads(statefile.read_text())
    assert data["version"] == "4.0"
    assert "susp" in data["resources"]["detection"]
    assert "Susp" not in data["resources"]["detection"]
    assert data["resources"]["detection"]["susp"]["id"] == "rule-123"
