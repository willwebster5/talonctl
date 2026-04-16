"""Parity test: every reference template under examples/resources/ must validate
cleanly against its matching provider. Guards against silent drift of the
reference YAMLs out of schema.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

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
}


def _example_files():
    if not EXAMPLES_DIR.exists():
        return []
    return sorted(p for p in EXAMPLES_DIR.glob("*.yaml"))


def _resource_type_for(tmpl, yaml_path):
    # Explicit `type:` wins; otherwise map filename stems that have a common prefix
    # (e.g. saved_search_function.yaml -> saved_search).
    rt = tmpl.get("type")
    if rt:
        return rt
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
    with open(yaml_path) as f:
        tmpl = yaml.safe_load(f)

    # Providers that resolve file-relative paths (rtr_put_file, rtr_script) expect
    # the template loader to set _template_path — simulate that here.
    tmpl["_template_path"] = str(yaml_path)

    resource_type = _resource_type_for(tmpl, yaml_path)
    provider_cls = PROVIDER_BY_TYPE.get(resource_type)
    assert provider_cls is not None, (
        f"{yaml_path.name}: unknown resource type {resource_type!r}. "
        f"Either add 'type:' to the template or rename the file to match a provider."
    )

    provider = _build_provider(provider_cls)
    errors = provider.validate_template(tmpl)
    assert errors == [], f"{yaml_path.name} failed validation: {errors}"
