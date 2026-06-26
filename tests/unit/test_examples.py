"""Parity test: every reference template under examples/resources/ must validate
cleanly against its matching provider. Guards against silent drift of the
reference YAMLs out of schema.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from talonctl.core.envelope_loader import load_envelopes
from talonctl.providers.case_notification_group_provider import CaseNotificationGroupProvider
from talonctl.providers.case_sla_provider import CaseSlaProvider
from talonctl.providers.case_template_provider import CaseTemplateProvider
from talonctl.providers.dashboard_provider import DashboardProvider
from talonctl.providers.detection_provider import DetectionProvider
from talonctl.providers.lookup_file_provider import LookupFileProvider
from talonctl.providers.rtr_put_file_provider import RTRPutFileProvider
from talonctl.providers.rtr_script_provider import RTRScriptProvider
from talonctl.providers.saved_search_provider import SavedSearchProvider
from talonctl.providers.workflow_provider import WorkflowProvider

EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples" / "resources"

PROVIDER_BY_TYPE = {
    "detection": DetectionProvider,
    "saved_search": SavedSearchProvider,
    "dashboard": DashboardProvider,
    "workflow": WorkflowProvider,
    "lookup_file": LookupFileProvider,
    "rtr_script": RTRScriptProvider,
    "rtr_put_file": RTRPutFileProvider,
    "case_notification_group": CaseNotificationGroupProvider,
    "case_sla": CaseSlaProvider,
    "case_template": CaseTemplateProvider,
}


def _example_files():
    if not EXAMPLES_DIR.exists():
        return []
    return sorted(p for p in EXAMPLES_DIR.glob("*.yaml"))


def _resource_type_for(yaml_path):
    """Derive resource_type from filename stem (handles saved_search* prefix)."""
    stem = yaml_path.stem
    if stem.startswith("saved_search"):
        return "saved_search"
    return stem


def _build_provider(cls):
    if cls is WorkflowProvider:
        with patch("talonctl.providers.workflow_provider.load_credentials") as mock_creds:
            mock_creds.return_value = {
                "falcon_client_id": "test",
                "falcon_client_secret": "test",
                "base_url": "https://api.crowdstrike.com",
            }
            with patch("talonctl.providers.workflow_provider.Workflows"):
                return cls(None)
    return cls(None)


@pytest.mark.parametrize("yaml_path", _example_files(), ids=lambda p: p.name)
def test_example_template_validates(yaml_path):
    resource_type = _resource_type_for(yaml_path)
    provider_cls = PROVIDER_BY_TYPE.get(resource_type)
    assert provider_cls is not None, (
        f"{yaml_path.name}: unknown resource type {resource_type!r}. "
        f"Rename the file to match a known provider, or add the type to PROVIDER_BY_TYPE."
    )

    # load_envelopes handles both v1 flat-dict and v2 (apiVersion: talon/v2)
    # documents natively. Pass default_resource_type for v1 files that lack
    # an explicit apiVersion; v2 files derive type from their kind field.
    envelopes = load_envelopes(yaml_path, default_resource_type=resource_type)
    assert len(envelopes) >= 1, f"{yaml_path.name}: no documents loaded"

    provider = _build_provider(provider_cls)
    for env in envelopes:
        # Providers that resolve file-relative paths (rtr_put_file, rtr_script)
        # expect origin_path on the Envelope — simulate what the loader sets.
        env.origin_path = str(yaml_path)
        errors = provider.validate_template(env)
        assert errors == [], f"{yaml_path.name} failed validation: {errors}"
