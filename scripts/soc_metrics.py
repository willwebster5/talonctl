#!/usr/bin/env python3
"""
SOC Metrics Aggregator

Reads detection health reports and manages weekly metric CSV files for NGSIEM lookup tables.

Usage:
    python scripts/soc_metrics.py update-detection-metrics --report report.json
    python scripts/soc_metrics.py update-kpis --report report.json
"""

import sys
import csv
import json
import io
import argparse
import logging
from pathlib import Path
from dataclasses import dataclass, fields
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone

from talonctl.project import find_project_root

logger = logging.getLogger(__name__)


def compute_week_start(date_str: str) -> str:
    """
    Compute the ISO Monday (week start) for a given date string.

    Args:
        date_str: Date in YYYY-MM-DD format.

    Returns:
        The Monday of that week in YYYY-MM-DD format.
    """
    dt = datetime.strptime(date_str, "%Y-%m-%d")
    monday = dt - timedelta(days=dt.weekday())
    return monday.strftime("%Y-%m-%d")


@dataclass
class WeeklyDetectionRow:
    """One row in detection_health_metrics.csv."""
    week_start: str
    resource_id: str
    platform: str
    severity: int
    enabled: bool
    alert_count: int
    fp_count: int
    tp_count: int
    info_count: int
    fp_rate: float
    last_alert_at: str
    dependency_status: str

    @classmethod
    def from_health_entry(cls, week_start: str, entry: Dict[str, Any]) -> "WeeklyDetectionRow":
        """Build from a detection health report entry."""
        return cls(
            week_start=week_start,
            resource_id=entry.get("resource_id", ""),
            platform=entry.get("platform", "unknown"),
            severity=entry.get("severity", 0),
            enabled=entry.get("enabled", True),
            alert_count=entry.get("alert_count", 0),
            fp_count=entry.get("fp_count", 0),
            tp_count=entry.get("tp_count", 0),
            info_count=entry.get("info_count", 0),
            fp_rate=entry.get("fp_rate", 0.0),
            last_alert_at=entry.get("last_alert_at", ""),
            dependency_status="valid" if entry.get("dependencies_valid", True) else "broken",
        )

    def to_csv_dict(self) -> Dict[str, str]:
        """Convert to a dict suitable for csv.DictWriter."""
        return {
            "week_start": self.week_start,
            "resource_id": self.resource_id,
            "platform": self.platform,
            "severity": str(self.severity),
            "enabled": str(self.enabled).lower(),
            "alert_count": str(self.alert_count),
            "fp_count": str(self.fp_count),
            "tp_count": str(self.tp_count),
            "info_count": str(self.info_count),
            "fp_rate": f"{self.fp_rate:.3f}",
            "last_alert_at": self.last_alert_at,
            "dependency_status": self.dependency_status,
        }


@dataclass
class WeeklyKPIRow:
    """One row in soc_weekly_kpis.csv."""
    week_start: str
    total_alerts: int
    total_triaged: int
    fp_count: int
    tp_count: int
    info_count: int
    fp_rate: float
    mttt_hours: float
    detections_total: int
    detections_enabled: int
    detections_zero_hit: int
    detections_error: int
    detections_deployed_new: int
    detections_tuned: int
    detections_retired: int

    def to_csv_dict(self) -> Dict[str, str]:
        return {f.name: str(getattr(self, f.name)) for f in fields(self)}


DETECTION_METRICS_HEADER = [
    "week_start", "resource_id", "platform", "severity", "enabled",
    "alert_count", "fp_count", "tp_count", "info_count", "fp_rate",
    "last_alert_at", "dependency_status",
]

KPI_HEADER = [
    "week_start", "total_alerts", "total_triaged", "fp_count", "tp_count",
    "info_count", "fp_rate", "mttt_hours", "detections_total",
    "detections_enabled", "detections_zero_hit", "detections_error",
    "detections_deployed_new", "detections_tuned", "detections_retired",
]


class MetricsAggregator:
    """Manages CSV read/write/trim operations for metric lookup files."""

    def __init__(self, retention_weeks: int = 52):
        self.retention_weeks = retention_weeks

    def trim_old_weeks(
        self,
        rows: List[Dict[str, str]],
        current_week: str,
    ) -> List[Dict[str, str]]:
        """
        Remove rows older than retention_weeks before current_week.

        Args:
            rows: List of CSV row dicts (must have 'week_start' key).
            current_week: The current week start (YYYY-MM-DD).

        Returns:
            Trimmed list.
        """
        cutoff = datetime.strptime(current_week, "%Y-%m-%d") - timedelta(weeks=self.retention_weeks)
        cutoff_str = cutoff.strftime("%Y-%m-%d")
        return [r for r in rows if r.get("week_start", "") >= cutoff_str]

    def merge_rows(
        self,
        existing: List[Dict[str, str]],
        new_rows: List[Dict[str, str]],
    ) -> List[Dict[str, str]]:
        """
        Merge new rows into existing, replacing duplicates on (week_start, resource_id).

        Args:
            existing: Current CSV rows.
            new_rows: New rows to add/update.

        Returns:
            Merged list with duplicates replaced by new data.
        """
        # Build lookup of new rows by composite key
        new_lookup = {}
        for row in new_rows:
            key = (row.get("week_start", ""), row.get("resource_id", ""))
            new_lookup[key] = row

        # Replace existing rows that match, keep others
        result = []
        seen_keys = set()
        for row in existing:
            key = (row.get("week_start", ""), row.get("resource_id", ""))
            if key in new_lookup:
                result.append(new_lookup[key])
                seen_keys.add(key)
            else:
                result.append(row)

        # Add new rows that weren't replacements
        for key, row in new_lookup.items():
            if key not in seen_keys:
                result.append(row)

        return result

    def read_csv(self, path: Path) -> List[Dict[str, str]]:
        """Read a CSV file into a list of dicts."""
        if not path.exists():
            return []
        with open(path, "r", newline="") as f:
            reader = csv.DictReader(f)
            return list(reader)

    def write_csv(
        self,
        path: Path,
        rows: List[Dict[str, str]],
        header: List[str],
    ) -> None:
        """Write rows to a CSV file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            # Sort by week_start then resource_id for deterministic output
            sorted_rows = sorted(rows, key=lambda r: (r.get("week_start", ""), r.get("resource_id", "")))
            writer.writerows(sorted_rows)


def main():
    parser = argparse.ArgumentParser(description="SOC Metrics Aggregator")
    sub = parser.add_subparsers(dest="command")

    update_det = sub.add_parser("update-detection-metrics", help="Update per-detection weekly CSV")
    update_det.add_argument("--report", required=True, help="Path to health report JSON")
    update_det.add_argument("--csv-path", help="Path to detection metrics CSV (default: auto)")

    update_kpi = sub.add_parser("update-kpis", help="Update weekly KPI CSV")
    update_kpi.add_argument("--report", required=True, help="Path to health report JSON")
    update_kpi.add_argument("--csv-path", help="Path to KPI CSV (default: auto)")

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if args.command == "update-detection-metrics":
        report = json.loads(Path(args.report).read_text())
        week = compute_week_start(report["generated_at"][:10])

        csv_path = Path(args.csv_path) if args.csv_path else (
            find_project_root() / "resources" / "lookup_files" / "crowdstrike" / "detection_health_metrics.csv"
        )

        agg = MetricsAggregator(retention_weeks=52)
        existing = agg.read_csv(csv_path)

        new_rows = []
        for det in report.get("detections", []):
            row = WeeklyDetectionRow.from_health_entry(week, det)
            new_rows.append(row.to_csv_dict())

        merged = agg.merge_rows(existing, new_rows)
        trimmed = agg.trim_old_weeks(merged, week)
        agg.write_csv(csv_path, trimmed, DETECTION_METRICS_HEADER)
        print(f"Updated {csv_path} with {len(new_rows)} rows for week {week}")

    elif args.command == "update-kpis":
        report = json.loads(Path(args.report).read_text())
        summary = report.get("summary", {})
        week = compute_week_start(report["generated_at"][:10])

        csv_path = Path(args.csv_path) if args.csv_path else (
            find_project_root() / "resources" / "lookup_files" / "crowdstrike" / "soc_weekly_kpis.csv"
        )

        total_alerts = sum(d.get("alert_count", 0) for d in report.get("detections", []))

        kpi = WeeklyKPIRow(
            week_start=week,
            total_alerts=total_alerts,
            total_triaged=0,  # Requires separate alert disposition query
            fp_count=0,
            tp_count=0,
            info_count=0,
            fp_rate=0.0,
            mttt_hours=0.0,
            detections_total=summary.get("total_detections", 0),
            detections_enabled=summary.get("total_detections", 0) - summary.get("disabled", 0),
            detections_zero_hit=summary.get("zero_hits", 0),
            detections_error=summary.get("broken_dependencies", 0),
            detections_deployed_new=0,
            detections_tuned=0,
            detections_retired=0,
        )

        agg = MetricsAggregator(retention_weeks=520)  # Keep KPIs indefinitely (~10 years)
        existing = agg.read_csv(csv_path)
        new_row = kpi.to_csv_dict()
        # KPI uses week_start as unique key (no resource_id)
        merged = [r for r in existing if r.get("week_start") != week]
        merged.append(new_row)
        agg.write_csv(csv_path, merged, KPI_HEADER)
        print(f"Updated {csv_path} with KPI for week {week}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
