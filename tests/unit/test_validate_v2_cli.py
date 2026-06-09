import re
from pathlib import Path
from click.testing import CliRunner
from talonctl.cli import cli


def _plain(s: str) -> str:
    # strip ANSI color codes and collapse whitespace (rich wraps long lines)
    return re.sub(r"\s+", " ", re.sub(r"\x1b\[[0-9;]*m", "", s)).lower()


def _project(tmp_path: Path):
    (tmp_path / ".crowdstrike").mkdir()
    (tmp_path / "resources" / "detections").mkdir(parents=True)
    return tmp_path


def test_valid_v2_file_passes(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    # A complete, valid v2 detection: passes both envelope-schema validation
    # and the detection provider's validate_template (now reached via discovery).
    (proj / "resources" / "detections" / "ok.yaml").write_text(
        "apiVersion: talon/v2\n"
        "kind: Detection\n"
        "metadata:\n"
        "  resource_id: d1\n"
        "  name: D1\n"
        "spec:\n"
        "  description: A valid detection.\n"
        "  severity: 50\n"
        "  search:\n"
        "    filter: '#repo=test'\n"
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


def test_trailing_whitespace_in_block_scalar_fails(tmp_path, monkeypatch):
    proj = _project(tmp_path)
    # filter block scalar whose first content line has trailing whitespace
    (proj / "resources" / "detections" / "ws.yaml").write_text(
        "apiVersion: talon/v2\n"
        "kind: Detection\n"
        "metadata:\n"
        "  resource_id: d1\n"
        "  name: D1\n"
        "spec:\n"
        "  severity: 50\n"
        "  search:\n"
        "    filter: |\n"
        "      #repo=test   \n"
        "      | head()\n"
    )
    monkeypatch.chdir(proj)
    result = CliRunner().invoke(cli, ["validate"])
    assert result.exit_code != 0
    assert "trailing whitespace" in _plain(result.output)


def test_global_path_redirects_discovery(tmp_path, monkeypatch):
    # Project root (for state) has NO resources/. Templates live in a separate dir.
    proj = tmp_path / "proj"
    (proj / ".crowdstrike").mkdir(parents=True)
    custom = tmp_path / "elsewhere"
    (custom / "detections").mkdir(parents=True)
    # A schema-invalid v2 detection (authored `status`) — only caught if discovery
    # actually scans the custom path.
    (custom / "detections" / "bad.yaml").write_text(
        "apiVersion: talon/v2\nkind: Detection\nmetadata: {resource_id: d1}\nspec: {severity: 1}\nstatus: {rule_id: x}\n"
    )
    monkeypatch.chdir(proj)

    # Without --path: nothing under proj/resources, so validate passes.
    assert CliRunner().invoke(cli, ["validate"]).exit_code == 0

    # With --path: discovery is redirected to the custom dir and the bad file fails.
    result = CliRunner().invoke(cli, ["--path", str(custom), "validate"])
    assert result.exit_code != 0
    assert "status" in _plain(result.output)
