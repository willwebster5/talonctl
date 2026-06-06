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
