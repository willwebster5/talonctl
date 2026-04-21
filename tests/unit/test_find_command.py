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
