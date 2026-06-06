"""Hash-stability anchor — the merge-blocking correctness contract for v2 Section 3.

Every provider (later) will receive an ``Envelope`` and call ``env.to_working_dict()``
to obtain the flat dict its existing ``compute_content_hash`` reads. If that flat dict
differs in any *hashed* key from the legacy v1 flat dict, every already-deployed resource
would show as "changed" on the next plan — a mass false-positive.

This test proves, per provider type, that::

    compute_content_hash(flat_v1_dict)
        == compute_content_hash(v1_to_v2(flat).to_working_dict())

byte-identical, across ALL SEVEN provider types.

If a case fails, the bug is in ``Envelope.to_working_dict`` / ``v1_compat.v1_to_v2``
(a hashed key not reproduced) — NOT in the provider hash. Do not weaken the assertion.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from talonctl.core.v1_compat import v1_to_v2
from talonctl.providers.dashboard_provider import DashboardProvider
from talonctl.providers.detection_provider import DetectionProvider
from talonctl.providers.lookup_file_provider import LookupFileProvider
from talonctl.providers.rtr_put_file_provider import RTRPutFileProvider
from talonctl.providers.rtr_script_provider import RTRScriptProvider
from talonctl.providers.saved_search_provider import SavedSearchProvider
from talonctl.providers.workflow_provider import WorkflowProvider


# ── Non-file-based fixtures: minimal-but-realistic v1 flat templates ──────────
# Trimmed to keys compute_content_hash actually reads, plus a few realistic extras
# (resource_id, identity) to exercise v1_to_v2's metadata extraction.

_DETECTION_FLAT = {
    "resource_id": "suspicious_process",
    "name": "Suspicious Process Execution",
    "description": "  Detects suspicious process trees.  ",
    "severity": 70,
    "status": "active",
    "type": "ootb",
    "search": {
        "filter": "  #event_simpleName=ProcessRollup2  ",
        "lookback": "1h",
        "outcome": "alert",
        "trigger_mode": "all",
        "use_ingest_time": False,
        "execution_mode": "scheduled",
    },
    "operation": {"schedule": {"interval": "5m"}},
    "mitre_attack": ["Defense Evasion (TA0005):Impair Defenses (T1562.001)"],
    "labels": {"team": "threat-detection"},
}

_SAVED_SEARCH_FLAT = {
    "resource_id": "failed_logins",
    "name": "Failed Logins",
    "queryString": "#event_simpleName=UserLogonFailed | groupBy([UserName])",
    "description": "Tracks failed logon attempts",
    "timeInterval": {"isLive": True, "start": "7d"},
    "visualization": {"options": {}, "type": "table"},
    "labels": {"category": "auth"},
    "_search_domain": "all",
}

_WORKFLOW_FLAT = {
    "resource_id": "isolate_host",
    "name": "isolate_host_response_workflow",
    "enabled": True,
    "trigger": {"type": "detection", "category": "Investigatable"},
    "actions": {"action-1": {"type": "network_contain"}},
    "conditions": {"cond-1": {"expression": "Trigger.Category.Investigatable.Name:'Suspicious Process Execution'"}},
}

_DASHBOARD_FLAT = {
    "resource_id": "ops_overview",
    "name": "Ops Overview",
    "description": "IaC-only dashboard description",
    "tags": ["ops"],
    "title": "Ops Overview",
    "sections": {
        "section-a": {"order": 0, "widgetIds": ["uuid-1", "uuid-2"]},
    },
    "widgets": {
        "uuid-1": {"type": "time-chart", "queryString": "#repo=base | count()"},
        "uuid-2": {"type": "list-view", "queryString": "#repo=base | head()"},
    },
}


# ── File-based fixtures: built inside the test via tmp_path ───────────────────
# lookup_file reads `source` (CWD-relative abspath). rtr_script/rtr_put_file read a
# file resolved relative to Path(_template_path).parent. For the NEW path the file
# is located via env.origin_path -> re-injected _template_path.


def _lookup_file_case(tmp_path):
    csv = tmp_path / "trusted_ips.csv"
    csv.write_text("ip_address,location,owner\n10.0.1.0/24,us-east-1,engineering\n")
    flat = {
        "resource_id": "trusted_ips",
        "name": "trusted_ips.csv",
        "description": "Trusted IP addresses",
        "format": "csv",
        # Absolute so both old (CWD-relative abspath) and new paths read the same file.
        "source": str(csv),
    }
    # lookup_file does not consume _template_path; origin_path is irrelevant to its hash.
    return LookupFileProvider(MagicMock()), flat, None


def _rtr_script_case(tmp_path):
    template_yaml = tmp_path / "template.yaml"
    template_yaml.write_text("")  # _template_path anchor
    script = tmp_path / "Get-ProcessTree.ps1"
    script.write_text("Get-Process | Format-Table\n")
    flat = {
        "resource_id": "get_process_tree",
        "name": "Get-ProcessTree",
        "description": "Enumerate process tree",
        "platform": ["windows"],
        "permission_type": "group",
        # Resolved relative to Path(_template_path).parent == tmp_path.
        "file_path": "Get-ProcessTree.ps1",
        # OLD path needs _template_path to find the file; NEW path re-injects the
        # same value from env.origin_path. Both must read identical bytes.
        "_template_path": str(template_yaml),
    }
    return RTRScriptProvider(MagicMock()), flat, str(template_yaml)


def _rtr_put_file_case(tmp_path):
    template_yaml = tmp_path / "template.yaml"
    template_yaml.write_text("")
    binary = tmp_path / "tool.exe"
    binary.write_bytes(b"\x4d\x5a\x90\x00" + b"\x00" * 100)  # PE header stub
    flat = {
        "resource_id": "tool.exe",
        "name": "tool.exe",
        "description": "Investigation tool",
        # Resolved relative to Path(_template_path).parent == tmp_path.
        "file_path": "tool.exe",
        # OLD path needs _template_path to find the file; NEW path re-injects the
        # same value from env.origin_path. Both must read identical bytes.
        "_template_path": str(template_yaml),
    }
    return RTRPutFileProvider(MagicMock()), flat, str(template_yaml)


_NON_FILE_CASES = [
    ("detection", DetectionProvider, _DETECTION_FLAT),
    ("saved_search", SavedSearchProvider, _SAVED_SEARCH_FLAT),
    ("workflow", WorkflowProvider, _WORKFLOW_FLAT),
    ("dashboard", DashboardProvider, _DASHBOARD_FLAT),
]

_FILE_CASE_BUILDERS = [
    ("lookup_file", _lookup_file_case),
    ("rtr_script", _rtr_script_case),
    ("rtr_put_file", _rtr_put_file_case),
]


def _assert_hash_identical(rtype, provider, flat, origin_path):
    """Old flat path vs Envelope working-dict path must hash byte-identically."""
    old_hash = provider.compute_content_hash(flat)

    env = v1_to_v2(flat, resource_type=rtype)
    if origin_path is not None:
        env.origin_path = origin_path
    new_hash = provider.compute_content_hash(env.to_working_dict())

    assert new_hash == old_hash, f"{rtype}: {old_hash} -> {new_hash}"


@pytest.mark.parametrize("rtype,provider_cls,flat", _NON_FILE_CASES)
def test_hash_identical_old_vs_new_path(rtype, provider_cls, flat):
    provider = provider_cls(MagicMock())
    # The old path mutates nothing it shouldn't, but use a fresh copy to be safe.
    _assert_hash_identical(rtype, provider, dict(flat), origin_path=None)


@pytest.mark.parametrize("rtype,builder", _FILE_CASE_BUILDERS)
def test_hash_identical_old_vs_new_path_file_based(rtype, builder, tmp_path):
    provider, flat, origin_path = builder(tmp_path)
    _assert_hash_identical(rtype, provider, flat, origin_path)


def test_all_seven_provider_types_covered():
    """Guard: this anchor must cover every provider type, or it isn't an anchor."""
    covered = {c[0] for c in _NON_FILE_CASES} | {c[0] for c in _FILE_CASE_BUILDERS}
    assert covered == {
        "detection",
        "saved_search",
        "lookup_file",
        "dashboard",
        "workflow",
        "rtr_script",
        "rtr_put_file",
    }
