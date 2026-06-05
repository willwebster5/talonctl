"""Tests for DeploymentOrchestrator.validate_queries."""

from unittest.mock import MagicMock, patch

import pytest

from talonctl.core.deployment_orchestrator import DeploymentOrchestrator
from talonctl.core.template_discovery import DiscoveredTemplate
from tests.unit._helpers import make_envelope


def _template(resource_type, name, data):
    # NOTE: DiscoveredTemplate.tags is required with no default.
    flat = {"resource_id": name, **data}
    return DiscoveredTemplate(
        resource_type=resource_type,
        name=name,
        file_path="/tmp/ignored.yaml",
        tags=[],
        envelope=make_envelope(flat, resource_type),
    )


@pytest.fixture
def orchestrator():
    orch = DeploymentOrchestrator.__new__(DeploymentOrchestrator)
    orch.template_discovery = MagicMock()
    return orch


def test_validate_queries_all_valid(orchestrator):
    orchestrator.template_discovery.discover_all.return_value = {
        "detection": [_template("detection", "a", {"search": {"filter": "A"}})],
        "saved_search": [_template("saved_search", "b", {"queryString": "B"})],
    }

    with patch("talonctl.core.deployment_orchestrator.NGSIEMClient") as MockClient:
        MockClient.return_value.test_query_syntax.return_value = {"valid": True}
        results = orchestrator.validate_queries()

    assert len(results) == 2
    assert all(r.is_valid for r in results)
    assert {r.resource_id for r in results} == {"detection.a", "saved_search.b"}


def test_validate_queries_one_invalid_shows_location(orchestrator):
    orchestrator.template_discovery.discover_all.return_value = {
        "dashboard": [
            _template(
                "dashboard",
                "d",
                {
                    "widgets": {"w1": {"queryString": "bad |"}},
                },
            )
        ],
    }

    with patch("talonctl.core.deployment_orchestrator.NGSIEMClient") as MockClient:
        MockClient.return_value.test_query_syntax.return_value = {
            "valid": False,
            "message": "LogScale rejected query (status=400, no detail returned by API)",
        }
        results = orchestrator.validate_queries()

    assert len(results) == 1
    assert results[0].is_valid is False
    assert results[0].location == "widgets.w1.queryString"
    assert "LogScale rejected" in results[0].error_message


def test_validate_queries_per_query_exception_captured(orchestrator):
    orchestrator.template_discovery.discover_all.return_value = {
        "detection": [
            _template("detection", "a", {"search": {"filter": "A"}}),
            _template("detection", "b", {"search": {"filter": "B"}}),
        ],
    }

    responses = iter(
        [
            {"valid": True},
            None,  # sentinel — we'll raise instead
        ]
    )

    def fake_test(query):
        r = next(responses)
        if r is None:
            raise RuntimeError("boom")
        return r

    with patch("talonctl.core.deployment_orchestrator.NGSIEMClient") as MockClient:
        MockClient.return_value.test_query_syntax.side_effect = fake_test
        results = orchestrator.validate_queries()

    assert len(results) == 2
    bad = [r for r in results if not r.is_valid]
    assert len(bad) == 1
    assert "boom" in bad[0].error_message


def test_validate_queries_empty_fleet_returns_empty(orchestrator):
    orchestrator.template_discovery.discover_all.return_value = {}

    with patch("talonctl.core.deployment_orchestrator.NGSIEMClient") as MockClient:
        results = orchestrator.validate_queries()

    assert results == []
    MockClient.assert_not_called()  # no queries -> no client spin-up


def test_validate_queries_filter_propagates(orchestrator):
    orchestrator.template_discovery.discover_all.return_value = {
        "detection": [_template("detection", "a", {"search": {"filter": "A"}})],
    }

    with patch("talonctl.core.deployment_orchestrator.NGSIEMClient") as MockClient:
        MockClient.return_value.test_query_syntax.return_value = {"valid": True}
        orchestrator.validate_queries(resource_types=["detection"], names=["a"], tags=None)

    orchestrator.template_discovery.discover_all.assert_called_once_with(
        resource_types=["detection"], tags=None, names=["a"]
    )
