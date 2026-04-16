"""Lock-in tests: every provider rejects pre-v0.3.0 top-level ads: and flat metadata:
with the exact CHANGELOG-pointing error. Protects the migration escape hatch from
silent refactors.
"""

from __future__ import annotations

import pytest

from talonctl.providers.dashboard_provider import DashboardProvider
from talonctl.providers.detection_provider import DetectionProvider
from talonctl.providers.lookup_file_provider import LookupFileProvider
from talonctl.providers.rtr_put_file_provider import RTRPutFileProvider
from talonctl.providers.rtr_script_provider import RTRScriptProvider
from talonctl.providers.saved_search_provider import SavedSearchProvider
from talonctl.providers.workflow_provider import WorkflowProvider


def _minimal_template_for(provider_cls, tmp_path):
    """Return a shape that passes other validation requirements per provider, so
    the only source of errors is the old-shape rejection under test."""
    if provider_cls is DetectionProvider:
        return {
            "resource_id": "x",
            "name": "n",
            "description": "d",
            "severity": 50,
            "search": {"filter": "x"},
        }
    if provider_cls is SavedSearchProvider:
        return {
            "resource_id": "x",
            "$schema": "https://schemas.humio.com/query/v0.5.0",
            "name": "n",
            "queryString": "x",
            "_search_domain": "falcon",
        }
    if provider_cls is DashboardProvider:
        return {
            "resource_id": "x",
            "name": "n",
            "sections": {"s0": {"order": 0, "widgetIds": ["w0"]}},
            "widgets": {"w0": {"type": "note", "text": "hi"}},
        }
    if provider_cls is WorkflowProvider:
        return {
            "resource_id": "x",
            "name": "n",
            "enabled": True,
            "trigger": {"event": "e", "type": "Signal"},
            "actions": {"a": {}},
            "conditions": {},
        }
    if provider_cls is LookupFileProvider:
        csv = tmp_path / "ips.csv"
        csv.write_text("ip\n1.2.3.4\n")
        return {
            "resource_id": "x",
            "name": "n",
            "format": "csv",
            "description": "d",
            "source": str(csv),
        }
    if provider_cls is RTRScriptProvider:
        return {
            "resource_id": "x",
            "name": "n",
            "description": "d",
            "platform": "linux",
            "permission_type": "private",
            "content": "#!/bin/sh\necho hi\n",
        }
    if provider_cls is RTRPutFileProvider:
        bin_file = tmp_path / "payload.bin"
        bin_file.write_bytes(b"\x00\x01")
        return {
            "resource_id": "x",
            "name": "n",
            "description": "d",
            "file_path": "payload.bin",
            "_template_path": str(tmp_path / "tmpl.yaml"),
        }
    raise AssertionError(f"no minimal template for {provider_cls!r}")


ALL_PROVIDERS = [
    DetectionProvider,
    SavedSearchProvider,
    DashboardProvider,
    WorkflowProvider,
    LookupFileProvider,
    RTRScriptProvider,
    RTRPutFileProvider,
]


def _build_provider(cls):
    # Providers all accept (falcon_client, config). WorkflowProvider needs credential patching.
    if cls is WorkflowProvider:
        from unittest.mock import patch

        with patch("talonctl.providers.workflow_provider.load_credentials") as mock_creds:
            mock_creds.return_value = {
                "falcon_client_id": "test",
                "falcon_client_secret": "test",
                "base_url": "https://api.crowdstrike.com",
            }
            with patch("talonctl.providers.workflow_provider.Workflows"):
                return cls(None)
    return cls(None)


@pytest.mark.parametrize("cls", ALL_PROVIDERS)
def test_every_provider_rejects_top_level_ads(cls, tmp_path):
    provider = _build_provider(cls)
    tmpl = _minimal_template_for(cls, tmp_path)
    tmpl["ads"] = {"goal": "g"}
    errors = provider.validate_template(tmpl)
    assert any(
        "Top-level 'ads:' is removed in v0.3.0" in e and "metadata.ads" in e and "CHANGELOG.md" in e for e in errors
    ), f"{cls.__name__} missing migration pointer: {errors!r}"


@pytest.mark.parametrize("cls", ALL_PROVIDERS)
def test_every_provider_rejects_flat_metadata_maturity(cls, tmp_path):
    provider = _build_provider(cls)
    tmpl = _minimal_template_for(cls, tmp_path)
    tmpl["metadata"] = {"created": "2026-04-16", "tune_count": 2}
    errors = provider.validate_template(tmpl)
    assert any(
        "Top-level 'metadata:' now reserves sub-namespaces" in e and "metadata.maturity" in e and "CHANGELOG.md" in e
        for e in errors
    ), f"{cls.__name__} missing migration pointer: {errors!r}"
