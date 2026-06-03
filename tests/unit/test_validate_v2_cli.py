from pathlib import Path
from click.testing import CliRunner
from talonctl.cli import cli


def _project(tmp_path: Path):
    (tmp_path / ".crowdstrike").mkdir()
    (tmp_path / "resources" / "detections").mkdir(parents=True)
    return tmp_path


def test_valid_v2_file_passes(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    (proj / "resources" / "detections" / "ok.yaml").write_text(
        "apiVersion: talon/v2\nkind: Detection\nmetadata: {resource_id: d1}\nspec: {severity: 1}\n"
    )
    monkeypatch.chdir(proj)
    result = CliRunner().invoke(cli, ["validate"])
    assert result.exit_code == 0


def test_invalid_v2_file_fails_with_message(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    (proj / "resources" / "detections" / "bad.yaml").write_text(
        "apiVersion: talon/v2\nkind: Detection\nmetadata: {resource_id: d1}\nspec: {severity: 1}\nstatus: {rule_id: x}\n"
    )
    monkeypatch.chdir(proj)
    result = CliRunner().invoke(cli, ["validate"])
    assert result.exit_code != 0
    assert "status" in result.output.lower()


def test_malformed_yaml_file_is_reported(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    # invalid YAML (unbalanced brackets) under resources/
    (proj / "resources" / "detections" / "broken.yaml").write_text(
        "apiVersion: talon/v2\nkind: Detection\nmetadata: {resource_id: d1\nspec: {severity: 1}\n"
    )
    monkeypatch.chdir(proj)
    result = CliRunner().invoke(cli, ["validate"])
    assert result.exit_code != 0
    assert "parse error" in result.output.lower() or "yaml" in result.output.lower()
