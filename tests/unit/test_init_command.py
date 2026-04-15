"""Tests for talonctl init command."""

from pathlib import Path

from click.testing import CliRunner

from talonctl.cli import cli


class TestInitCommand:
    def test_creates_project_structure(self, tmp_path):
        """talonctl init should create the full project directory structure."""
        runner = CliRunner()
        result = runner.invoke(cli, ["init", str(tmp_path / "myproject")])
        assert result.exit_code == 0

        project = tmp_path / "myproject"
        assert (project / "resources" / "detections").is_dir()
        assert (project / "resources" / "saved_searches").is_dir()
        assert (project / "resources" / "dashboards").is_dir()
        assert (project / "resources" / "workflows").is_dir()
        assert (project / "resources" / "lookup_files").is_dir()
        assert (project / "resources" / "rtr_scripts").is_dir()
        assert (project / "resources" / "rtr_put_files").is_dir()
        assert (project / "knowledge" / "INDEX.md").is_file()
        assert (project / "knowledge" / "context" / "environmental-context.md").is_file()
        assert (project / "knowledge" / "techniques" / "investigation-techniques.md").is_file()
        assert (project / "knowledge" / "tuning" / "tuning-backlog.md").is_file()
        assert (project / "knowledge" / "tuning" / "tuning-log.md").is_file()
        assert (project / "knowledge" / "metrics" / "detection-metrics.jsonl").is_file()
        assert (project / "knowledge" / "ideas" / "detection-ideas.md").is_file()
        assert (project / ".crowdstrike" / "deployed_state.json").is_file()
        assert (project / ".gitignore").is_file()

    def test_creates_valid_state_file(self, tmp_path):
        """State file should be valid JSON with correct format version."""
        import json

        runner = CliRunner()
        runner.invoke(cli, ["init", str(tmp_path / "myproject")])
        state = json.loads((tmp_path / "myproject" / ".crowdstrike" / "deployed_state.json").read_text())
        assert state["format_version"] == "3.0"
        assert state["resources"] == {}

    def test_refuses_existing_directory_with_crowdstrike(self, tmp_path):
        """Should refuse to init if .crowdstrike/ already exists."""
        project = tmp_path / "existing"
        project.mkdir()
        (project / ".crowdstrike").mkdir()
        runner = CliRunner()
        result = runner.invoke(cli, ["init", str(project)])
        assert result.exit_code != 0
        assert "already" in result.output.lower()

    def test_init_current_directory(self, tmp_path):
        """talonctl init with no path should use current directory."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            result = runner.invoke(cli, ["init"])
            assert result.exit_code == 0
            assert (Path(td) / ".crowdstrike" / "deployed_state.json").is_file()
