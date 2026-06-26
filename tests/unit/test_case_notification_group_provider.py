import pytest
from unittest.mock import MagicMock

from talonctl.core.base_provider import ResourceAction
from talonctl.providers.case_notification_group_provider import CaseNotificationGroupProvider
from tests.unit._helpers import make_envelope


def _flat(**over):
    base = {
        "resource_id": "secops_email_oncall",
        "name": "SecOps On-Call (Email)",
        "description": "Primary escalation distro",
        "channels": [{"type": "email", "recipients": ["secops@example.com"], "severity": "high"}],
    }
    base.update(over)
    return base


@pytest.fixture
def provider():
    return CaseNotificationGroupProvider(MagicMock())


def _env(flat):
    return make_envelope(flat, "case_notification_group")


def test_type(provider):
    assert provider.get_resource_type() == "case_notification_group"


def test_validate_ok(provider):
    assert provider.validate_template(_env(_flat())) == []


def test_validate_missing_name(provider):
    flat = _flat()
    del flat["name"]
    errors = provider.validate_template(_env(flat))
    assert any("name" in e for e in errors)


def test_validate_bad_channel_type(provider):
    errors = provider.validate_template(_env(_flat(channels=[{"type": "carrier_pigeon"}])))
    assert any("channel" in e.lower() for e in errors)


def test_plan_create(provider):
    change = provider.plan_create(_env(_flat()), "/p.yaml")
    assert change.action == ResourceAction.CREATE
    assert change.resource_type == "case_notification_group"
    assert change.envelope is not None


def test_apply_create(provider):
    provider.falcon.command.return_value = {
        "status_code": 201,
        "body": {"resources": [{"id": "api-ng-123"}], "errors": []},
    }
    result = provider.apply_create(_env(_flat()))
    assert result["id"] == "api-ng-123"
    assert result["resource_id"] == "secops_email_oncall"  # stamped for RefResolver
    call = provider.falcon.command.call_args
    assert "POST" in call.kwargs["override"]
    assert call.kwargs["body"]["name"] == "SecOps On-Call (Email)"
    assert "resource_id" not in call.kwargs["body"]  # stripped before API


def test_apply_delete_idempotent(provider):
    provider.falcon.command.return_value = {"status_code": 200, "body": {"resources": [], "errors": []}}
    assert provider.apply_delete("api-ng-123")["id"] == "api-ng-123"


def test_validate_missing_resource_id(provider):
    # For a non-mintable type, a missing resource_id is rejected at the envelope
    # layer (v1_to_v2) before validate_template is reached. Assert that real
    # enforcement point rather than the provider's (unreachable) defensive check.
    flat = _flat()
    del flat["resource_id"]
    with pytest.raises(ValueError, match="resource_id"):
        _env(flat)


def test_apply_update_sets_id_and_uses_patch(provider):
    provider.falcon.command.return_value = {
        "status_code": 200,
        "body": {"resources": [{"id": "api-ng-123"}], "errors": []},
    }
    result = provider.apply_update("api-ng-123", _env(_flat()), {"content_hash": "old"})
    assert result["id"] == "api-ng-123"
    call = provider.falcon.command.call_args
    assert "PATCH" in call.kwargs["override"]
    assert call.kwargs["body"]["id"] == "api-ng-123"


def test_apply_delete_raises_on_failure(provider):
    provider.falcon.command.return_value = {
        "status_code": 403,
        "body": {"errors": [{"message": "forbidden"}]},
    }
    with pytest.raises(RuntimeError):
        provider.apply_delete("api-ng-123")


def test_extract_dependencies_passthrough(provider):
    flat = _flat(dependencies=["case_sla.standard_sla"])
    assert provider.extract_dependencies(_env(flat).to_working_dict()) == ["case_sla.standard_sla"]


def test_extract_dependencies_empty_by_default(provider):
    assert provider.extract_dependencies(_env(_flat()).to_working_dict()) == []


def test_fetch_all_remote_notification_groups(provider):
    provider.falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": ["id1"]}},  # query (page 1)
        {"status_code": 200, "body": {"resources": [{"id": "id1", "name": "NG One"}]}},  # get
    ]
    out = provider._fetch_all_remote_notification_groups()
    assert out == {"NG One": {"id": "id1", "name": "NG One"}}
