"""Envelope serializer tests: canonical YAML output, round-trip, hash stability."""

from __future__ import annotations

import pytest
import yaml
from unittest.mock import MagicMock

from talonctl.core.envelope import IDENTITY_METADATA_KEYS, Envelope
from talonctl.core.envelope_loader import load_envelopes
from talonctl.core.envelope_serializer import _METADATA_ORDER, serialize_envelope, serialize_envelopes
from talonctl.core.v1_compat import v1_to_v2
from talonctl.providers.dashboard_provider import DashboardProvider
from talonctl.providers.detection_provider import DetectionProvider
from talonctl.providers.saved_search_provider import SavedSearchProvider
from talonctl.providers.workflow_provider import WorkflowProvider


def test_serialize_emits_canonical_top_level_order():
    env = Envelope(
        api_version="talon/v2",
        kind="SavedSearch",
        metadata={"name": "Failed Logins", "resource_id": "failed_logins", "tags": ["auth"]},
        spec={"query_string": "#x | count()", "search_domain": "all", "description": "d"},
    )
    text = serialize_envelope(env)
    keys = [line.split(":")[0] for line in text.splitlines() if line and not line.startswith(" ")]
    assert keys[:4] == ["apiVersion", "kind", "metadata", "spec"]
    assert text.index("resource_id") < text.index("name:") < text.index("tags")
    doc = yaml.safe_load(text)
    assert doc["apiVersion"] == "talon/v2"
    assert doc["kind"] == "SavedSearch"
    assert doc["metadata"]["resource_id"] == "failed_logins"
    assert doc["spec"]["query_string"] == "#x | count()"
    assert "status" not in doc


_DETECTION = {
    "resource_id": "suspicious_process",
    "name": "Suspicious Process",
    "severity": 70,
    "status": "active",
    "type": "ootb",
    "search": {"filter": "#x", "lookback": "1h"},
    "labels": {"team": "td"},
    "metadata": {"maturity": "production"},  # non-identity metadata field; exercises envelope metadata round-trip
}
_SAVED_SEARCH = {
    "resource_id": "failed_logins",
    "name": "Failed Logins",
    "queryString": "#x | count()",
    "_search_domain": "all",
    "labels": {"category": "auth"},
}
_WORKFLOW = {
    "resource_id": "isolate_host",
    "name": "isolate_host_wf",
    "enabled": True,
    "trigger": {"type": "detection"},
    "actions": {"a1": {"type": "network_contain"}},
}
_DASHBOARD = {
    "resource_id": "ops",
    "name": "Ops",
    "title": "Ops",
    "tags": ["ops"],
    "widgets": {"w1": {"type": "time-chart", "queryString": "#r | count()"}},
    "sections": {"s1": {"order": 0, "widgetIds": ["w1"]}},
}

_HASHED_CASES = [
    ("detection", DetectionProvider, _DETECTION),
    ("saved_search", SavedSearchProvider, _SAVED_SEARCH),
    ("workflow", WorkflowProvider, _WORKFLOW),
    ("dashboard", DashboardProvider, _DASHBOARD),
]


@pytest.mark.parametrize("rtype,_provider_cls,flat", _HASHED_CASES)
def test_roundtrip_preserves_envelope(rtype, _provider_cls, flat, tmp_path):
    before = v1_to_v2(dict(flat), resource_type=rtype)
    out = tmp_path / "out.yaml"
    out.write_text(serialize_envelopes([before]))
    after = load_envelopes(out, default_resource_type=rtype)[0]
    assert after.api_version == before.api_version
    assert after.kind == before.kind
    assert after.metadata == before.metadata
    assert after.spec == before.spec


@pytest.mark.parametrize("rtype,provider_cls,flat", _HASHED_CASES)
def test_roundtrip_preserves_content_hash(rtype, provider_cls, flat, tmp_path):
    provider = provider_cls(MagicMock())
    before = v1_to_v2(dict(flat), resource_type=rtype)
    out = tmp_path / "out.yaml"
    out.write_text(serialize_envelopes([before]))
    after = load_envelopes(out, default_resource_type=rtype)[0]
    assert provider.compute_content_hash(after.to_working_dict()) == provider.compute_content_hash(
        before.to_working_dict()
    )


@pytest.mark.parametrize("rtype,_provider_cls,flat", _HASHED_CASES)
def test_serializer_is_idempotent(rtype, _provider_cls, flat, tmp_path):
    before = v1_to_v2(dict(flat), resource_type=rtype)
    first = serialize_envelopes([before])
    out = tmp_path / "out.yaml"
    out.write_text(first)
    after = load_envelopes(out, default_resource_type=rtype)[0]
    assert serialize_envelopes([after]) == first


def test_multi_doc_serialization_reloads_all(tmp_path):
    a = v1_to_v2(dict(_DETECTION), resource_type="detection")
    b = v1_to_v2({**_DETECTION, "resource_id": "other", "name": "Other"}, resource_type="detection")
    out = tmp_path / "multi.yaml"
    out.write_text(serialize_envelopes([a, b]))
    loaded = load_envelopes(out, default_resource_type="detection")
    assert {e.resource_id for e in loaded} == {"suspicious_process", "other"}


def test_metadata_order_covers_identity_keys():
    # _METADATA_ORDER encodes the emit-order of the identity set; if a key is
    # added to IDENTITY_METADATA_KEYS, this forces an explicit ordering decision.
    assert set(_METADATA_ORDER) == set(IDENTITY_METADATA_KEYS)


def test_multiline_string_emits_literal_block_scalar():
    # Multiline queries/descriptions must serialize as `|` literal blocks, not
    # double-quoted strings with embedded \n escapes.
    env = Envelope(
        api_version="talon/v2",
        kind="SavedSearch",
        metadata={"resource_id": "q", "name": "Q"},
        spec={"query_string": "#repo=x\n| head()\n| count()\n", "search_domain": "all"},
    )
    text = serialize_envelope(env)
    assert "query_string: |" in text
    assert "\\n" not in text  # no escaped newlines anywhere


def test_multiline_with_trailing_whitespace_roundtrips_losslessly():
    # Strings with trailing whitespace (or tabs) cannot be `|` block-represented;
    # they fall back to a quoted scalar. The serializer must NEVER mutate content
    # to force block style — doing so changes content hashes and churns deployments.
    q = "#repo=x   \n| head()  \n| count()\n"
    env = Envelope(
        api_version="talon/v2",
        kind="SavedSearch",
        metadata={"resource_id": "q", "name": "Q"},
        spec={"query_string": q, "search_domain": "all"},
    )
    text = serialize_envelope(env)
    assert yaml.safe_load(text)["spec"]["query_string"] == q  # exact, no mutation


def test_multiline_with_tabs_roundtrips_losslessly():
    q = "#x\n| groupBy([a], function=([\n\tcount(),\n]))\n"
    env = Envelope(
        api_version="talon/v2",
        kind="SavedSearch",
        metadata={"resource_id": "q", "name": "Q"},
        spec={"query_string": q, "search_domain": "all"},
    )
    assert yaml.safe_load(serialize_envelope(env))["spec"]["query_string"] == q
