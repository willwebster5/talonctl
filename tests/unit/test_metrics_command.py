"""Unit tests for talonctl metrics command."""

import json
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from talonctl.commands.metrics import metrics


class TestMetricsCommand:
    """Test talonctl metrics CLI integration."""

    def test_metrics_group_has_update_detections(self):
        assert "update-detections" in [c.name for c in metrics.commands.values()]

    def test_metrics_group_has_update_kpis(self):
        assert "update-kpis" in [c.name for c in metrics.commands.values()]

    def test_update_detections_requires_report(self):
        """update-detections fails without --report."""
        runner = CliRunner()
        result = runner.invoke(metrics, ["update-detections"])
        assert result.exit_code != 0

    @patch("talonctl.commands.metrics.MetricsAggregator")
    def test_update_detections_with_report(self, MockAgg, tmp_path):
        """update-detections processes a health report JSON."""
        report_file = tmp_path / "report.json"
        csv_file = tmp_path / "metrics.csv"
        report_data = {
            "generated_at": "2026-04-14T00:00:00Z",
            "summary": {"total_detections": 5, "disabled": 1},
            "detections": [
                {
                    "resource_id": "test",
                    "platform": "aws",
                    "severity": 50,
                    "enabled": True,
                    "alert_count": 10,
                    "dependencies_valid": True,
                }
            ],
        }
        report_file.write_text(json.dumps(report_data))

        mock_agg = MagicMock()
        mock_agg.read_csv.return_value = []
        mock_agg.merge_rows.return_value = [{"week_start": "2026-04-13"}]
        mock_agg.trim_old_weeks.return_value = [{"week_start": "2026-04-13"}]
        MockAgg.return_value = mock_agg

        runner = CliRunner()
        result = runner.invoke(
            metrics, ["update-detections", "--report", str(report_file), "--csv-path", str(csv_file)]
        )
        assert result.exit_code == 0
