"""talonctl health — detection health check."""

import json
import logging
from pathlib import Path
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

import click

from talonctl.commands._common import console
from talonctl.core.template_discovery import TemplateDiscovery
from talonctl.core.dependency_validator import DependencyValidator

logger = logging.getLogger(__name__)


class DetectionHealthStatus(str, Enum):
    """Health classification for a detection."""

    HEALTHY = "healthy"
    ZERO_HITS = "zero_hits"
    BROKEN_DEPS = "broken_dependencies"
    DISABLED = "disabled"
    NEW = "new"  # Deployed < 30 days, insufficient data


def classify_platform(template_path: str) -> str:
    """
    Extract platform name from a detection template file path.

    Args:
        template_path: Path like 'resources/detections/aws/rule.yaml'

    Returns:
        Platform string (e.g., 'aws', 'microsoft', 'crowdstrike').
    """
    path = Path(template_path)
    parts = path.parts
    # Find 'detections' in path, next part is platform
    for i, part in enumerate(parts):
        if part == "detections" and i + 1 < len(parts):
            return parts[i + 1]
    return "unknown"


class DetectionHealthReport:
    """
    Holds health check results and provides summary/formatting methods.

    Args:
        period_days: Number of days the alert volume covers.
        detections: List of detection metadata dicts (from build_inventory).
        alert_volumes: Dict mapping detection display name -> {"count": int, ...}.
    """

    def __init__(
        self,
        period_days: int,
        detections: List[Dict[str, Any]],
        alert_volumes: Dict[str, Dict[str, Any]],
    ):
        self.period_days = period_days
        self.detections = detections
        self.alert_volumes = alert_volumes
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def _classify(self, det: Dict[str, Any]) -> DetectionHealthStatus:
        """Classify a single detection."""
        if not det.get("enabled", True):
            return DetectionHealthStatus.DISABLED
        if not det.get("dependencies_valid", True):
            return DetectionHealthStatus.BROKEN_DEPS
        name = det.get("name", "")
        vol = self.alert_volumes.get(name, {})
        count = vol.get("count", 0)
        if count > 0:
            return DetectionHealthStatus.HEALTHY
        return DetectionHealthStatus.ZERO_HITS

    def summary(self) -> Dict[str, int]:
        """Aggregate counts by health status."""
        counts = {
            "total_detections": len(self.detections),
            "healthy": 0,
            "zero_hits": 0,
            "broken_dependencies": 0,
            "disabled": 0,
        }
        for det in self.detections:
            status = self._classify(det)
            if status == DetectionHealthStatus.HEALTHY:
                counts["healthy"] += 1
            elif status == DetectionHealthStatus.ZERO_HITS:
                counts["zero_hits"] += 1
            elif status == DetectionHealthStatus.BROKEN_DEPS:
                counts["broken_dependencies"] += 1
            elif status == DetectionHealthStatus.DISABLED:
                counts["disabled"] += 1
        return counts

    def zero_hit_by_platform(self) -> Dict[str, Dict[str, int]]:
        """Break down zero-hit detections by platform."""
        platforms: Dict[str, Dict[str, int]] = {}
        for det in self.detections:
            plat = det.get("platform", "unknown")
            if plat not in platforms:
                platforms[plat] = {"total": 0, "zero_hit": 0}
            platforms[plat]["total"] += 1
            status = self._classify(det)
            if status == DetectionHealthStatus.ZERO_HITS:
                platforms[plat]["zero_hit"] += 1
        return platforms

    def to_dict(self) -> Dict[str, Any]:
        """Full JSON-serializable report."""
        summary = self.summary()
        enriched = []
        for det in self.detections:
            entry = dict(det)
            status = self._classify(det)
            entry["health"] = status.value
            vol = self.alert_volumes.get(det.get("name", ""), {})
            entry["alert_count"] = vol.get("count", 0)
            enriched.append(entry)

        return {
            "generated_at": self.generated_at,
            "period_days": self.period_days,
            "total_detections": summary["total_detections"],
            "summary": summary,
            "detections": enriched,
            "zero_hit_by_platform": self.zero_hit_by_platform(),
        }

    def format_text(self) -> str:
        """Human-readable text summary."""
        s = self.summary()
        total = s["total_detections"] or 1  # avoid div-by-zero
        lines = [
            f"Detection Health Report ({self.generated_at[:10]}, last {self.period_days} days)",
            "=" * 60,
            f"Total deployed:      {s['total_detections']}",
            f"  Healthy (1+ hits): {s['healthy']:>4}  ({100 * s['healthy'] // total}%)",
            f"  Zero hits:         {s['zero_hits']:>4}  ({100 * s['zero_hits'] // total}%)",
            f"  Broken deps:       {s['broken_dependencies']:>4}  ({100 * s['broken_dependencies'] // total}%)",
            f"  Disabled:          {s['disabled']:>4}  ({100 * s['disabled'] // total}%)",
            "",
            "Zero-hit detections by platform:",
        ]
        for plat, data in sorted(self.zero_hit_by_platform().items()):
            pct = 100 * data["zero_hit"] // max(data["total"], 1)
            lines.append(f"  {plat:>15}: {data['zero_hit']:>3} of {data['total']:<3} ({pct}%)")
        return "\n".join(lines)


class DetectionHealthChecker:
    """
    Orchestrates the detection health check.

    For CI (headless), provide ngsiem_query_fn to execute CQL.
    For unit tests, mock everything.
    """

    def __init__(
        self,
        template_discovery: Optional[TemplateDiscovery] = None,
        dependency_validator: Optional[DependencyValidator] = None,
        ngsiem_query_fn=None,
        alert_volume_fn=None,
    ):
        if template_discovery is None:
            from talonctl.commands._common import resolve_resources_dir

            template_discovery = TemplateDiscovery(resolve_resources_dir())
        self._discovery = template_discovery
        self._dep_validator = dependency_validator or DependencyValidator(self._discovery)
        self._ngsiem_query_fn = ngsiem_query_fn
        self._alert_volume_fn = alert_volume_fn

    def build_inventory(self) -> List[Dict[str, Any]]:
        """
        Build detection inventory from template discovery.

        Returns:
            List of detection metadata dicts with keys:
            resource_id, name, platform, enabled, severity, dependencies_valid
        """
        all_templates = self._discovery.discover_all()
        detections = all_templates.get("detection", [])
        inventory = []

        for det in detections:
            status = det.template_data.get("status", "active")
            enabled = status not in ("inactive", "disabled")
            severity = det.template_data.get("severity", 0)

            # Check dependencies
            dep_issues = self._dep_validator.validate_detection(det)
            deps_valid = len(dep_issues) == 0

            platform = classify_platform(str(det.file_path))

            inventory.append(
                {
                    "resource_id": det.name,
                    "name": det.display_name or det.name,
                    "platform": platform,
                    "enabled": enabled,
                    "severity": severity,
                    "dependencies_valid": deps_valid,
                }
            )

        return inventory

    def query_alert_volumes(self, period_days: int) -> Dict[str, Dict[str, Any]]:
        """
        Query alert volumes per detection over the given period.

        Uses alert_volume_fn (Alerts API) if available, falls back to
        ngsiem_query_fn (CQL) if provided.

        Returns:
            Dict mapping detection name -> {"count": int, "first": str, "last": str}
        """
        # Prefer NGSIEM CQL -- rule trigger events are in xdr_indicatorsrepo
        if self._ngsiem_query_fn:
            cql = (
                '#repo=xdr_indicatorsrepo Ngsiem.event.type="ngsiem-rule-trigger-event"'
                "| groupBy(rule.name, function=[count(), min(@timestamp), max(@timestamp)])"
                "| sort(_count, order=desc)"
            )
            try:
                result = self._ngsiem_query_fn(query=cql, time_range=f"{period_days}d")
                volumes = {}
                for row in result.get("events", []):
                    name = row.get("rule.name", "")
                    if name:
                        volumes[name] = {
                            "count": int(row.get("_count", 0)),
                            "first": row.get("_min", ""),
                            "last": row.get("_max", ""),
                        }
                return volumes
            except Exception as e:
                logger.error(f"Failed to query alert volumes via NGSIEM: {e}")
                return {}

        # Fallback: Alerts API (slower, requires pagination)
        if self._alert_volume_fn:
            try:
                return self._alert_volume_fn(period_days)
            except Exception as e:
                logger.error(f"Failed to query alert volumes via Alerts API: {e}")
                return {}

        logger.warning("No alert query function provided -- returning empty volumes")
        return {}

    def run(self, period_days: int = 90) -> DetectionHealthReport:
        """
        Execute the full health check.

        Args:
            period_days: Number of days of alert history to analyze.

        Returns:
            DetectionHealthReport with full results.
        """
        inventory = self.build_inventory()
        volumes = self.query_alert_volumes(period_days)
        return DetectionHealthReport(
            period_days=period_days,
            detections=inventory,
            alert_volumes=volumes,
        )


@click.command()
@click.option("--period", type=int, default=90, help="Analysis period in days (default: 90)")
@click.option("--output", "-o", type=click.Path(), help="Write JSON report to file")
@click.option("--format", "fmt", type=click.Choice(["json", "text"]), default="text", help="Output format")
@click.pass_context
def health(ctx, period, output, fmt):
    """Check detection health across deployed rules."""
    console.print("[bold cyan]talonctl health[/bold cyan]\n")

    # Wire an authenticated NGSIEM query function so alert volumes are actually
    # fetched. Without this the checker reports every detection as zero-hits.
    # The adapter degrades to empty volumes (with a logged warning) if auth or
    # the query fails, so the inventory report still renders.
    from talonctl.utils.ngsiem_client import make_health_query_fn

    checker = DetectionHealthChecker(ngsiem_query_fn=make_health_query_fn())
    report = checker.run(period_days=period)

    if fmt == "json" or output:
        data = json.dumps(report.to_dict(), indent=2)
        if output:
            Path(output).write_text(data)
            console.print(f"[green]Report written to {output}[/green]")
        else:
            click.echo(data)
    else:
        click.echo(report.format_text())
