"""End-to-end-ish wiring: dependency order is derived correctly and a sibling's
API-id change never drifts a dependent (hash uses the stable ref)."""

from unittest.mock import MagicMock

from talonctl.providers.case_sla_provider import CaseSlaProvider
from talonctl.providers.case_template_provider import CaseTemplateProvider
from tests.unit._helpers import make_envelope


def test_dependency_chain_order():
    sla = CaseSlaProvider(MagicMock())
    tmpl = CaseTemplateProvider(MagicMock())

    sla_flat = {
        "resource_id": "standard_sla",
        "name": "Standard SLA",
        "goals": [
            {
                "type": "time_to_resolution",
                "duration_seconds": 86400,
                "escalation_policy": {"steps": [{"escalate_after_seconds": 3600, "notification_group_ref": "ng_a"}]},
            }
        ],
    }
    tmpl_flat = {
        "resource_id": "phishing",
        "name": "Phishing",
        "sla_ref": "standard_sla",
        "fields": [{"name": "F", "data_type": "string", "input_type": "text"}],
    }

    assert sla.extract_dependencies(make_envelope(sla_flat, "case_sla").to_working_dict()) == [
        "case_notification_group.ng_a"
    ]
    assert tmpl.extract_dependencies(make_envelope(tmpl_flat, "case_template").to_working_dict()) == [
        "case_sla.standard_sla"
    ]


def test_template_hash_unaffected_by_sla_api_id_change():
    class _R:
        def __init__(self, v):
            self.v = v

        def resolve(self, *_):
            return self.v

    tmpl = CaseTemplateProvider(MagicMock())
    flat = {
        "resource_id": "phishing",
        "name": "Phishing",
        "sla_ref": "standard_sla",
        "fields": [{"name": "F", "data_type": "string", "input_type": "text"}],
    }
    working = make_envelope(flat, "case_template").to_working_dict()

    tmpl.ref_resolver = _R("api-1")
    h1 = tmpl.compute_content_hash(working)
    tmpl.ref_resolver = _R("api-2-different")
    h2 = tmpl.compute_content_hash(working)
    assert h1 == h2  # resolved id is not part of the hash
