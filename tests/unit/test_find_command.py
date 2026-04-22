"""Integration tests for the `talonctl find` CLI command."""

import json
from pathlib import Path

from click.testing import CliRunner

from talonctl.commands.find import find


def _write_state(tmp_path: Path) -> Path:
    """Materialize the canonical fixture state dict to a state file."""
    state = {
        "version": "3.0",
        "last_updated": "2026-04-21T00:00:00Z",
        "metadata": {},
        "resources": {
            "detection": {
                "aws_root_login": {
                    "type": "detection",
                    "id": "det-id-1",
                    "content_hash": "abc",
                    "template_path": "resources/detections/aws/aws_root_login.yaml",
                    "deployed_at": "2026-03-14T19:22:03Z",
                    "last_modified": "2026-03-14T19:22:03Z",
                    "provider_metadata": {
                        "rule_id": "c1d430691e8b42e7b336956f6a3af6fc",
                        "status": "active",
                        "severity": 70,
                    },
                    "dependencies": [],
                    "display_name": "AWS - Root Login via Console",
                }
            }
        },
        "resource_graph": {"nodes": [], "edges": []},
    }
    state_file = tmp_path / "deployed_state.json"
    state_file.write_text(json.dumps(state))
    return state_file


class TestFindCommandTable:
    def test_table_default_format_shows_match(self, tmp_path):
        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(find, ["c1d430691e8b42e7b336956f6a3af6fc", "--state-file", str(state_file)])
        assert result.exit_code == 0
        assert "aws_root_login" in result.output
        assert "detection" in result.output
        assert "rule_id" in result.output  # header line includes strategy

    def test_table_zero_match_exit_1(self, tmp_path):
        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(find, ["nonexistent_resource", "--state-file", str(state_file)])
        assert result.exit_code == 1


class TestFindCommandJson:
    def test_json_output_shape_stable(self, tmp_path):
        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            find,
            [
                "c1d430691e8b42e7b336956f6a3af6fc",
                "--format",
                "json",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 0
        output = result.output.strip()
        assert output.startswith("{"), f"output must be JSON, got: {output[:80]!r}"
        parsed = json.loads(output)
        assert parsed["query"] == "c1d430691e8b42e7b336956f6a3af6fc"
        assert parsed["strategy_used"] == "rule_id"
        assert len(parsed["matches"]) == 1
        assert parsed["non_iac_info"] is None
        m = parsed["matches"][0]
        assert m["resource_type"] == "detection"
        assert m["resource_id"] == "aws_root_login"
        assert m["iac_tunable"] is True
        assert m["deployed"] is True

    def test_json_zero_match_still_valid_json(self, tmp_path):
        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            find,
            ["nothing_matches", "--format", "json", "--state-file", str(state_file)],
        )
        assert result.exit_code == 1
        output = result.output.strip()
        assert output.startswith("{")
        parsed = json.loads(output)
        assert parsed["matches"] == []
        assert parsed["strategy_used"] == "none"

    def test_json_non_iac_prefix(self, tmp_path):
        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            find,
            ["fcs:abc", "--format", "json", "--state-file", str(state_file)],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output.strip())
        assert parsed["strategy_used"] == "composite_id_non_iac"
        assert parsed["non_iac_info"]["prefix"] == "fcs"

    def test_banner_suppressed_through_full_cli_group_for_json(self, tmp_path):
        """Invoke the full cli group to exercise the banner-suppression path in cli.py."""
        from talonctl.cli import cli

        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "find",
                "c1d430691e8b42e7b336956f6a3af6fc",
                "--format",
                "json",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 0
        # First non-empty line must be JSON — no banner preamble
        first = next(ln for ln in result.output.splitlines() if ln.strip())
        assert first.startswith("{"), f"banner leaked: {result.output[:200]!r}"

    def test_banner_still_shown_for_table_format_through_cli_group(self, tmp_path):
        """Sanity check: banner IS present when --format is table."""
        from talonctl.cli import cli

        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["find", "aws_root_login", "--state-file", str(state_file)],
        )
        assert result.exit_code == 0
        assert "talonctl" in result.output  # banner present


class TestFindCommandPath:
    def test_path_format_emits_bare_lines(self, tmp_path):
        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            find,
            [
                "c1d430691e8b42e7b336956f6a3af6fc",
                "--format",
                "path",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 0
        lines = [ln for ln in result.output.splitlines() if ln.strip()]
        assert lines == ["resources/detections/aws/aws_root_login.yaml"]

    def test_path_format_zero_match_empty_output_exit_1(self, tmp_path):
        state_file = _write_state(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            find,
            ["nothing_matches", "--format", "path", "--state-file", str(state_file)],
        )
        assert result.exit_code == 1
        assert result.output.strip() == ""

    def test_path_format_skips_entries_without_template_path(self, tmp_path):
        state_file = tmp_path / "s.json"
        state_file.write_text(
            json.dumps(
                {
                    "version": "3.0",
                    "resources": {
                        "detection": {
                            "foo": {
                                "type": "detection",
                                "id": "x",
                                "content_hash": "",
                                "template_path": "",
                                "deployed_at": "",
                                "last_modified": "",
                                "provider_metadata": {},
                                "dependencies": [],
                                "display_name": "Foo",
                            }
                        }
                    },
                }
            )
        )
        runner = CliRunner()
        result = runner.invoke(find, ["foo", "--format", "path", "--state-file", str(state_file)])
        # Match is present, but path is empty → skipped, stderr warned → exit 0 still (match exists).
        assert result.exit_code == 0
        # No template paths should be printed to stdout, but warning goes to stderr (mixed in output)
        assert "Warning: detection.foo has no template_path; skipping" in result.output
