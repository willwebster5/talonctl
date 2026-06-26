import pytest
from unittest.mock import MagicMock

from talonctl.core.ref_resolver import UnresolvedRefError
from talonctl.providers.case_sla_provider import CaseSlaProvider
from tests.unit._helpers import make_envelope


def _flat(**over):
    base = {
        "resource_id": "standard_sla",
        "name": "Standard Response SLA",
        "description": "24h resolution",
        "goals": [
            {
                "type": "time_to_resolution",
                "duration_seconds": 86400,
                "escalation_policy": {
                    "steps": [{"escalate_after_seconds": 3600, "notification_group_ref": "secops_email_oncall"}]
                },
            }
        ],
    }
    base.update(over)
    return base


def _env(flat):
    return make_envelope(flat, "case_sla")


class _Resolver:
    def __init__(self, mapping):
        self._m = mapping

    def resolve(self, resource_type, resource_id):
        try:
            return self._m[(resource_type, resource_id)]
        except KeyError:
            raise UnresolvedRefError(f"{resource_type} {resource_id}")


@pytest.fixture
def provider():
    p = CaseSlaProvider(MagicMock())
    p.ref_resolver = _Resolver({("case_notification_group", "secops_email_oncall"): "api-ng-123"})
    return p


def test_type(provider):
    assert provider.get_resource_type() == "case_sla"


def test_validate_ok(provider):
    assert provider.validate_template(_env(_flat())) == []


def test_validate_missing_goals(provider):
    flat = _flat()
    del flat["goals"]
    assert any("goals" in e for e in provider.validate_template(_env(flat)))


def test_extract_dependencies(provider):
    deps = provider.extract_dependencies(_env(_flat()).to_working_dict())
    assert "case_notification_group.secops_email_oncall" in deps


def test_apply_create_resolves_ref(provider):
    provider.falcon.command.return_value = {
        "status_code": 201,
        "body": {"resources": [{"id": "api-sla-1"}], "errors": []},
    }
    result = provider.apply_create(_env(_flat()))
    assert result["id"] == "api-sla-1"
    assert result["resource_id"] == "standard_sla"
    body = provider.falcon.command.call_args.kwargs["body"]
    step = body["goals"][0]["escalation_policy"]["steps"][0]
    assert step["notification_group_id"] == "api-ng-123"
    assert "notification_group_ref" not in step


def test_apply_create_unresolved_ref_raises(provider):
    provider.ref_resolver = _Resolver({})
    with pytest.raises(UnresolvedRefError):
        provider.apply_create(_env(_flat()))


def test_hash_stable_regardless_of_resolved_id(provider):
    h1 = provider.compute_content_hash(_env(_flat()).to_working_dict())
    provider.ref_resolver = _Resolver({("case_notification_group", "secops_email_oncall"): "DIFFERENT-API-ID"})
    h2 = provider.compute_content_hash(_env(_flat()).to_working_dict())
    assert h1 == h2


def test_apply_delete_raises_on_failure(provider):
    provider.falcon.command.return_value = {"status_code": 403, "body": {"errors": [{"message": "forbidden"}]}}
    with pytest.raises(RuntimeError):
        provider.apply_delete("api-sla-1")


def test_apply_delete_success(provider):
    provider.falcon.command.return_value = {"status_code": 200, "body": {"resources": [], "errors": []}}
    assert provider.apply_delete("api-sla-1")["id"] == "api-sla-1"


def test_fetch_all_remote_slas(provider):
    provider.falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": ["s1"]}},
        {"status_code": 200, "body": {"resources": [{"id": "s1", "name": "Std SLA"}]}},
    ]
    assert provider._fetch_all_remote_slas() == {"Std SLA": {"id": "s1", "name": "Std SLA"}}


def test_to_template_reverse_maps_notification_group(provider):
    # First two calls satisfy the NG reverse-map (query then get).
    provider.falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": ["ng1"]}},
        {"status_code": 200, "body": {"resources": [{"id": "ng1", "name": "SecOps On-Call (Email)"}]}},
    ]
    remote = {
        "name": "Std SLA",
        "description": "x",
        "goals": [
            {
                "type": "ttr",
                "duration_seconds": 3600,
                "escalation_policy": {"steps": [{"escalate_after_seconds": 60, "notification_group_id": "ng1"}]},
            }
        ],
    }
    tmpl = provider.to_template(remote)
    step = tmpl["goals"][0]["escalation_policy"]["steps"][0]
    assert step["notification_group_ref"] == provider._name_to_resource_id("SecOps On-Call (Email)")
    assert "notification_group_id" not in step
    assert tmpl["resource_id"] == provider._name_to_resource_id("Std SLA")


def test_to_template_preserves_unresolved_notification_group(provider):
    provider.falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": []}},  # no NGs -> empty reverse map
    ]
    remote = {
        "name": "Std SLA",
        "goals": [
            {
                "type": "ttr",
                "duration_seconds": 3600,
                "escalation_policy": {"steps": [{"escalate_after_seconds": 60, "notification_group_id": "ng_unknown"}]},
            }
        ],
    }
    tmpl = provider.to_template(remote)
    step = tmpl["goals"][0]["escalation_policy"]["steps"][0]
    assert step["notification_group_id"] == "ng_unknown"
    assert "notification_group_ref" not in step
