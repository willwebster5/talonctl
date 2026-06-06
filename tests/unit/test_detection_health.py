"""
Unit tests for detection_health.py — detection health check engine.

These tests mock all NGSIEM/API calls and test the cross-referencing logic
that classifies detections as healthy, silent, erroring, or broken.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from talonctl.commands.health import (
    DetectionHealthChecker,
    DetectionHealthReport,
    classify_platform,
)
from talonctl.core.template_discovery import DiscoveredTemplate
from tests.unit._helpers import make_envelope


class TestClassifyPlatform:
    """Test platform classification from template file paths."""

    def test_aws_detection(self):
        assert classify_platform("resources/detections/aws/some_rule.yaml") == "aws"

    def test_microsoft_detection(self):
        assert classify_platform("resources/detections/microsoft/some_rule.yaml") == "microsoft"

    def test_crowdstrike_detection(self):
        assert classify_platform("resources/detections/crowdstrike/some_rule.yaml") == "crowdstrike"

    def test_google_detection(self):
        assert classify_platform("resources/detections/google/some_rule.yaml") == "google"

    def test_github_detection(self):
        assert classify_platform("resources/detections/github/some_rule.yaml") == "github"

    def test_nested_path(self):
        assert classify_platform("resources/detections/aws/cloudtrail/deep/rule.yaml") == "aws"

    def test_unknown_platform(self):
        assert classify_platform("resources/detections/unknown_vendor/rule.yaml") == "unknown_vendor"


class TestDetectionHealthReport:
    """Test the report generation logic."""

    def test_empty_report(self):
        report = DetectionHealthReport(
            period_days=90,
            detections=[],
            alert_volumes={},
        )
        summary = report.summary()
        assert summary["total_detections"] == 0
        assert summary["healthy"] == 0
        assert summary["zero_hits"] == 0

    def test_classification_healthy(self):
        """Detection with alert hits in period is healthy."""
        report = DetectionHealthReport(
            period_days=90,
            detections=[
                {
                    "resource_id": "aws___cloudtrail___console_root_login",
                    "name": "AWS - CloudTrail - Console Root Login",
                    "platform": "aws",
                    "enabled": True,
                    "severity": 50,
                    "dependencies_valid": True,
                }
            ],
            alert_volumes={"AWS - CloudTrail - Console Root Login": {"count": 15}},
        )
        summary = report.summary()
        assert summary["total_detections"] == 1
        assert summary["healthy"] == 1
        assert summary["zero_hits"] == 0

    def test_classification_zero_hits(self):
        """Enabled detection with no alerts is zero-hit."""
        report = DetectionHealthReport(
            period_days=90,
            detections=[
                {
                    "resource_id": "aws___some_rule",
                    "name": "AWS - Some Rule",
                    "platform": "aws",
                    "enabled": True,
                    "severity": 30,
                    "dependencies_valid": True,
                }
            ],
            alert_volumes={},
        )
        summary = report.summary()
        assert summary["zero_hits"] == 1

    def test_classification_disabled(self):
        """Disabled detection is classified as disabled, not zero-hit."""
        report = DetectionHealthReport(
            period_days=90,
            detections=[
                {
                    "resource_id": "aws___disabled_rule",
                    "name": "AWS - Disabled Rule",
                    "platform": "aws",
                    "enabled": False,
                    "severity": 30,
                    "dependencies_valid": True,
                }
            ],
            alert_volumes={},
        )
        summary = report.summary()
        assert summary["disabled"] == 1
        assert summary["zero_hits"] == 0

    def test_classification_broken_deps(self):
        """Detection with broken dependencies is classified as broken."""
        report = DetectionHealthReport(
            period_days=90,
            detections=[
                {
                    "resource_id": "aws___broken_rule",
                    "name": "AWS - Broken Rule",
                    "platform": "aws",
                    "enabled": True,
                    "severity": 30,
                    "dependencies_valid": False,
                }
            ],
            alert_volumes={},
        )
        summary = report.summary()
        assert summary["broken_dependencies"] == 1

    def test_zero_hit_by_platform(self):
        """Zero-hit breakdown by platform."""
        report = DetectionHealthReport(
            period_days=90,
            detections=[
                {
                    "resource_id": "a1",
                    "name": "A1",
                    "platform": "aws",
                    "enabled": True,
                    "severity": 30,
                    "dependencies_valid": True,
                },
                {
                    "resource_id": "a2",
                    "name": "A2",
                    "platform": "aws",
                    "enabled": True,
                    "severity": 30,
                    "dependencies_valid": True,
                },
                {
                    "resource_id": "m1",
                    "name": "M1",
                    "platform": "microsoft",
                    "enabled": True,
                    "severity": 30,
                    "dependencies_valid": True,
                },
            ],
            alert_volumes={"A1": {"count": 5}},
        )
        by_plat = report.zero_hit_by_platform()
        assert by_plat["aws"]["zero_hit"] == 1
        assert by_plat["aws"]["total"] == 2
        assert by_plat["microsoft"]["zero_hit"] == 1
        assert by_plat["microsoft"]["total"] == 1


class TestDetectionHealthChecker:
    """Test the main checker orchestration (all API calls mocked)."""

    @pytest.fixture
    def mock_discovery(self):
        discovery = MagicMock()
        det1 = MagicMock()
        det1.name = "aws___cloudtrail___console_root_login"
        det1.display_name = "AWS - CloudTrail - Console Root Login"
        det1.file_path = Path("resources/detections/aws/aws___cloudtrail___console_root_login.yaml")
        det1.template_data = {"severity": 50, "status": "active", "search": {"filter": "| count()"}}
        det1.resource_id = "detection.aws___cloudtrail___console_root_login"

        det2 = MagicMock()
        det2.name = "github___direct_push"
        det2.display_name = "GitHub - Direct Push"
        det2.file_path = Path("resources/detections/github/github___direct_push.yaml")
        det2.template_data = {"severity": 30, "status": "inactive", "search": {"filter": "| count()"}}
        det2.resource_id = "detection.github___direct_push"

        discovery.discover_all.return_value = {
            "detection": [det1, det2],
            "saved_search": [],
            "workflow": [],
            "lookup_file": [],
            "rtr_script": [],
            "rtr_put_file": [],
        }
        return discovery

    @pytest.fixture
    def mock_dep_validator(self):
        validator = MagicMock()
        validator.validate_detection.return_value = []
        return validator

    def test_build_inventory(self, mock_discovery, mock_dep_validator):
        """build_inventory() returns detection metadata from templates."""
        checker = DetectionHealthChecker(
            template_discovery=mock_discovery,
            dependency_validator=mock_dep_validator,
        )
        inventory = checker.build_inventory()
        assert len(inventory) == 2
        assert inventory[0]["resource_id"] == "aws___cloudtrail___console_root_login"
        assert inventory[0]["platform"] == "aws"
        assert inventory[1]["enabled"] is False  # inactive status


def _make_discovered(
    resource_type: str, name: str, flat: dict, file_path: str = "/tmp/ignored.yaml"
) -> DiscoveredTemplate:
    """Build a real DiscoveredTemplate backed by a real Envelope (v2 path)."""
    env = make_envelope({"resource_id": name, **flat}, resource_type)
    return DiscoveredTemplate(
        resource_type=resource_type,
        name=name,
        file_path=Path(file_path),
        tags=[],
        envelope=env,
    )


class TestBuildInventoryWithV2Templates:
    """Verify build_inventory reads status/severity correctly from v2-backed DiscoveredTemplates."""

    def test_active_detection_reads_status_and_severity_from_v2_envelope(self):
        """Status/severity surfaced through template_data property from a real Envelope."""
        det = _make_discovered(
            "detection",
            "aws___root_login",
            {
                "severity": 80,
                "status": "active",
                "search": {"filter": "| count()"},
            },
            file_path="resources/detections/aws/aws___root_login.yaml",
        )

        mock_discovery = MagicMock()
        mock_discovery.discover_all.return_value = {"detection": [det], "saved_search": []}
        mock_dep_validator = MagicMock()
        mock_dep_validator.validate_detection.return_value = []

        checker = DetectionHealthChecker(
            template_discovery=mock_discovery,
            dependency_validator=mock_dep_validator,
        )
        inventory = checker.build_inventory()

        assert len(inventory) == 1
        entry = inventory[0]
        assert entry["resource_id"] == "aws___root_login"
        assert entry["severity"] == 80
        assert entry["enabled"] is True  # "active" -> enabled
        assert entry["platform"] == "aws"

    def test_inactive_detection_reads_status_from_v2_envelope(self):
        """'inactive' status yields enabled=False via the property."""
        det = _make_discovered(
            "detection",
            "aws___disabled_rule",
            {
                "severity": 30,
                "status": "inactive",
                "search": {"filter": "| count()"},
            },
            file_path="resources/detections/aws/aws___disabled_rule.yaml",
        )

        mock_discovery = MagicMock()
        mock_discovery.discover_all.return_value = {"detection": [det], "saved_search": []}
        mock_dep_validator = MagicMock()
        mock_dep_validator.validate_detection.return_value = []

        checker = DetectionHealthChecker(
            template_discovery=mock_discovery,
            dependency_validator=mock_dep_validator,
        )
        inventory = checker.build_inventory()

        assert inventory[0]["enabled"] is False

    def test_v2_template_produces_same_inventory_as_v1_mock(self):
        """v2-backed template yields identical inventory shape as the v1 MagicMock path."""
        # v1-style mock (legacy test pattern)
        det_mock = MagicMock()
        det_mock.name = "aws___test_rule"
        det_mock.display_name = "AWS - Test Rule"
        det_mock.file_path = Path("resources/detections/aws/aws___test_rule.yaml")
        det_mock.template_data = {"severity": 50, "status": "active", "search": {"filter": "| count()"}}
        det_mock.resource_id = "detection.aws___test_rule"

        # v2-backed DiscoveredTemplate
        det_v2 = _make_discovered(
            "detection",
            "aws___test_rule",
            {
                "severity": 50,
                "status": "active",
                "name": "AWS - Test Rule",
                "search": {"filter": "| count()"},
            },
            file_path="resources/detections/aws/aws___test_rule.yaml",
        )

        mock_dep_validator = MagicMock()
        mock_dep_validator.validate_detection.return_value = []

        for det in (det_mock, det_v2):
            mock_discovery = MagicMock()
            mock_discovery.discover_all.return_value = {"detection": [det], "saved_search": []}
            checker = DetectionHealthChecker(
                template_discovery=mock_discovery,
                dependency_validator=mock_dep_validator,
            )
            inv = checker.build_inventory()
            assert inv[0]["resource_id"] == "aws___test_rule"
            assert inv[0]["severity"] == 50
            assert inv[0]["enabled"] is True
            assert inv[0]["platform"] == "aws"
