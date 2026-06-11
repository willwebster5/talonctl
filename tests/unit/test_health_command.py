"""Unit tests for talonctl health command."""

import json
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from talonctl.commands.health import health


class TestHealthCommand:
    """Test talonctl health CLI integration."""

    @patch("talonctl.commands.health.DetectionHealthChecker")
    def test_health_default_text_output(self, MockChecker):
        """health command produces text output by default."""
        mock_report = MagicMock()
        mock_report.format_text.return_value = "Detection Health Report"
        MockChecker.return_value.run.return_value = mock_report

        runner = CliRunner()
        result = runner.invoke(health, [])
        assert result.exit_code == 0
        assert "Detection Health Report" in result.output

    @patch("talonctl.commands.health.DetectionHealthChecker")
    def test_health_json_output(self, MockChecker):
        """health --format json produces JSON output."""
        mock_report = MagicMock()
        mock_report.to_dict.return_value = {"summary": {"total_detections": 10}}
        MockChecker.return_value.run.return_value = mock_report

        runner = CliRunner()
        result = runner.invoke(health, ["--format", "json"])
        assert result.exit_code == 0
        # The JSON output is pretty-printed; find the JSON block in output
        # by looking for the first '{' to the last '}'
        output = result.output.strip()
        json_start = output.index("{")
        json_end = output.rindex("}") + 1
        parsed = json.loads(output[json_start:json_end])
        assert parsed["summary"]["total_detections"] == 10

    @patch("talonctl.commands.health.DetectionHealthChecker")
    def test_health_period_option(self, MockChecker):
        """health --period passes through to checker."""
        mock_report = MagicMock()
        mock_report.format_text.return_value = "ok"
        MockChecker.return_value.run.return_value = mock_report

        runner = CliRunner()
        runner.invoke(health, ["--period", "30"])
        MockChecker.return_value.run.assert_called_once_with(period_days=30)

    @patch("talonctl.commands.health.DetectionHealthChecker")
    def test_health_output_file(self, MockChecker, tmp_path):
        """health --output writes JSON to file."""
        mock_report = MagicMock()
        mock_report.to_dict.return_value = {"summary": {}}
        MockChecker.return_value.run.return_value = mock_report

        out_file = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(health, ["--output", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()

    @patch("talonctl.commands.health.DetectionHealthChecker")
    def test_health_wires_ngsiem_query_fn(self, MockChecker):
        """Regression: the checker must be built WITH an ngsiem_query_fn.

        Without it, query_alert_volumes() returns empty volumes and every
        detection is misreported as zero-hits.
        """
        mock_report = MagicMock()
        mock_report.format_text.return_value = "ok"
        MockChecker.return_value.run.return_value = mock_report

        runner = CliRunner()
        runner.invoke(health, [])

        _, kwargs = MockChecker.call_args
        assert kwargs.get("ngsiem_query_fn") is not None
        assert callable(kwargs["ngsiem_query_fn"])
