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


class TestFindCommandStateEdges:
    def test_missing_state_file_exit_1_with_stderr_note(self, tmp_path):
        missing = tmp_path / "does-not-exist.json"
        runner = CliRunner()
        result = runner.invoke(find, ["anything", "--state-file", str(missing)])
        assert result.exit_code == 1
        # stderr note is merged into result.output by CliRunner when mix_stderr=True (default)
        assert "No state file" in result.output or "No state file" in (result.stderr or "")

    def test_corrupt_state_file_exit_2(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        runner = CliRunner()
        result = runner.invoke(find, ["anything", "--state-file", str(bad)])
        assert result.exit_code == 2

    def test_include_undeployed_with_no_state(self, tmp_path, monkeypatch):
        # No state file + --include-undeployed + no templates → exit 1 cleanly
        missing = tmp_path / "none.json"
        # Stub template discovery to return empty
        import talonctl.commands.find as find_mod

        monkeypatch.setattr(find_mod, "_discover_templates", lambda: [])
        runner = CliRunner()
        result = runner.invoke(
            find,
            ["anything", "--state-file", str(missing), "--include-undeployed"],
        )
        assert result.exit_code == 1


class TestFindCommandRegistration:
    def test_find_is_registered_in_cli_group(self):
        from talonctl.cli import cli

        assert "find" in cli.commands
        assert cli.commands["find"] is find


class TestAcceptanceCriteria:
    """Mirrors the spec's acceptance criteria list verbatim."""

    def test_ac1_bare_uuid(self, tmp_path):
        state_file = _write_state(tmp_path)
        r = CliRunner().invoke(
            find,
            ["c1d430691e8b42e7b336956f6a3af6fc", "--format", "json", "--state-file", str(state_file)],
        )
        assert r.exit_code == 0
        parsed = json.loads(r.output.strip())
        assert parsed["strategy_used"] == "rule_id"
        assert len(parsed["matches"]) == 1

    def test_ac2_exact_resource_id(self, tmp_path):
        state_file = _write_state(tmp_path)
        r = CliRunner().invoke(find, ["aws_root_login", "--format", "json", "--state-file", str(state_file)])
        parsed = json.loads(r.output.strip())
        assert parsed["strategy_used"] == "resource_id"

    def test_ac3_display_name_substring(self, tmp_path):
        state_file = _write_state(tmp_path)
        r = CliRunner().invoke(find, ["root login", "--format", "json", "--state-file", str(state_file)])
        parsed = json.loads(r.output.strip())
        assert parsed["strategy_used"] == "name_substring"
        assert len(parsed["matches"]) == 1

    def test_ac4_glob_with_type(self, tmp_path):
        state_file = _write_state(tmp_path)
        r = CliRunner().invoke(
            find,
            ["aws_*_login", "--type", "detection", "--format", "json", "--state-file", str(state_file)],
        )
        parsed = json.loads(r.output.strip())
        assert parsed["strategy_used"] == "glob"
        assert all(m["resource_type"] == "detection" for m in parsed["matches"])

    def test_ac5_ngsiem_composite_equivalent_to_bare_uuid(self, tmp_path):
        state_file = _write_state(tmp_path)
        r = CliRunner().invoke(
            find,
            ["ngsiem:c1d430691e8b42e7b336956f6a3af6fc", "--format", "json", "--state-file", str(state_file)],
        )
        parsed = json.loads(r.output.strip())
        assert parsed["strategy_used"] == "composite_id_ngsiem"
        assert len(parsed["matches"]) == 1

    def test_ac6_fcs_non_iac(self, tmp_path):
        state_file = _write_state(tmp_path)
        r = CliRunner().invoke(find, ["fcs:abc", "--format", "json", "--state-file", str(state_file)])
        assert r.exit_code == 0
        parsed = json.loads(r.output.strip())
        assert parsed["matches"] == []
        assert parsed["non_iac_info"]["prefix"] == "fcs"

    def test_ac7_include_undeployed(self, tmp_path, monkeypatch):
        state_file = _write_state(tmp_path)
        from types import SimpleNamespace

        fake_template = SimpleNamespace(
            resource_type="detection",
            name="aws_iam_key_created",
            display_name="AWS - IAM Access Key Created",
            file_path=Path("resources/detections/aws/aws_iam_key_created.yaml"),
            tags=[],
            template_data={},
        )
        import talonctl.commands.find as find_mod

        monkeypatch.setattr(find_mod, "_discover_templates", lambda: [fake_template])
        r = CliRunner().invoke(
            find,
            ["aws_iam_key_created", "--include-undeployed", "--format", "json", "--state-file", str(state_file)],
        )
        parsed = json.loads(r.output.strip())
        assert parsed["strategy_used"] == "resource_id"
        assert parsed["matches"][0]["deployed"] is False

    def test_ac8_json_shape_stable_zero_match(self, tmp_path):
        state_file = _write_state(tmp_path)
        r = CliRunner().invoke(find, ["nothing", "--format", "json", "--state-file", str(state_file)])
        assert r.exit_code == 1
        parsed = json.loads(r.output.strip())
        assert set(parsed.keys()) == {"query", "strategy_used", "matches", "non_iac_info"}

    def test_ac9_path_format_pipe_clean(self, tmp_path):
        state_file = _write_state(tmp_path)
        r = CliRunner().invoke(
            find,
            ["c1d430691e8b42e7b336956f6a3af6fc", "--format", "path", "--state-file", str(state_file)],
        )
        # First non-empty line is a raw template path, not a banner.
        first = next(ln for ln in r.output.splitlines() if ln.strip())
        assert first == "resources/detections/aws/aws_root_login.yaml"

    def test_ac10_exit_codes(self, tmp_path):
        state_file = _write_state(tmp_path)
        runner = CliRunner()
        # 0: match
        assert runner.invoke(find, ["aws_root_login", "--state-file", str(state_file)]).exit_code == 0
        # 0: non-iac
        assert runner.invoke(find, ["fcs:x", "--state-file", str(state_file)]).exit_code == 0
        # 1: zero match
        assert runner.invoke(find, ["nothing", "--state-file", str(state_file)]).exit_code == 1
        # 2: bad --type
        assert runner.invoke(find, ["x", "--type", "bogus", "--state-file", str(state_file)]).exit_code == 2
