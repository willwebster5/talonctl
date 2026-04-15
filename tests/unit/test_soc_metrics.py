"""
Unit tests for soc_metrics.py — metric aggregation and CSV management.
"""

from talonctl.commands.metrics import (
    MetricsAggregator,
    WeeklyDetectionRow,
    compute_week_start,
)


class TestComputeWeekStart:
    """Test week-start calculation (ISO Monday)."""

    def test_monday(self):
        # 2026-03-23 is a Monday
        assert compute_week_start("2026-03-23") == "2026-03-23"

    def test_wednesday(self):
        # 2026-03-25 is a Wednesday -> Monday is 2026-03-23
        assert compute_week_start("2026-03-25") == "2026-03-23"

    def test_sunday(self):
        # 2026-03-29 is a Sunday -> Monday is 2026-03-23
        assert compute_week_start("2026-03-29") == "2026-03-23"


class TestWeeklyDetectionRow:
    """Test per-detection weekly metric row."""

    def test_from_health_entry(self):
        entry = {
            "resource_id": "aws___cloudtrail___console_root_login",
            "platform": "aws",
            "severity": 50,
            "enabled": True,
            "alert_count": 15,
            "health": "healthy",
            "dependencies_valid": True,
        }
        row = WeeklyDetectionRow.from_health_entry("2026-03-23", entry)
        assert row.week_start == "2026-03-23"
        assert row.resource_id == "aws___cloudtrail___console_root_login"
        assert row.alert_count == 15
        assert row.enabled is True

    def test_to_csv_dict(self):
        row = WeeklyDetectionRow(
            week_start="2026-03-23",
            resource_id="test_rule",
            platform="aws",
            severity=50,
            enabled=True,
            alert_count=10,
            fp_count=0,
            tp_count=0,
            info_count=0,
            fp_rate=0.0,
            last_alert_at="",
            dependency_status="valid",
        )
        d = row.to_csv_dict()
        assert d["week_start"] == "2026-03-23"
        assert d["alert_count"] == "10"
        assert d["enabled"] == "true"


class TestMetricsAggregator:
    """Test CSV reading, trimming, and appending logic."""

    def test_trim_old_weeks(self):
        agg = MetricsAggregator(retention_weeks=2)
        rows = [
            {"week_start": "2026-01-05", "resource_id": "a"},
            {"week_start": "2026-03-16", "resource_id": "b"},
            {"week_start": "2026-03-23", "resource_id": "c"},
        ]
        trimmed = agg.trim_old_weeks(rows, current_week="2026-03-23")
        # Only last 2 weeks kept
        assert len(trimmed) == 2
        assert trimmed[0]["week_start"] == "2026-03-16"

    def test_append_and_deduplicate(self):
        """If same week_start + resource_id exists, replace it."""
        agg = MetricsAggregator(retention_weeks=52)
        existing = [
            {"week_start": "2026-03-23", "resource_id": "a", "alert_count": "5"},
        ]
        new = [
            {"week_start": "2026-03-23", "resource_id": "a", "alert_count": "10"},
            {"week_start": "2026-03-23", "resource_id": "b", "alert_count": "3"},
        ]
        merged = agg.merge_rows(existing, new)
        assert len(merged) == 2
        # 'a' should have updated count
        a_row = next(r for r in merged if r["resource_id"] == "a")
        assert a_row["alert_count"] == "10"
