import pytest
from unittest.mock import MagicMock

from talonctl.core.base_provider import ResourceAction
from talonctl.core.ref_resolver import UnresolvedRefError
from talonctl.providers.case_template_provider import CaseTemplateProvider
from tests.unit._helpers import make_envelope


def _flat(**over):
    base = {
        "resource_id": "phishing_investigation",
        "name": "Phishing Investigation",
        "description": "Standard intake",
        "sla_ref": "standard_sla",
        "fields": [
            {"name": "Reported By", "data_type": "string", "input_type": "text", "required": True, "multivalued": False}
        ],
    }
    base.update(over)
    return base


def _env(flat):
    return make_envelope(flat, "case_template")


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
    p = CaseTemplateProvider(MagicMock())
    p.ref_resolver = _Resolver({("case_sla", "standard_sla"): "api-sla-1"})
    return p


def test_type(provider):
    assert provider.get_resource_type() == "case_template"


def test_validate_ok(provider):
    assert provider.validate_template(_env(_flat())) == []


def test_validate_bad_field_input_type(provider):
    flat = _flat(fields=[{"name": "X", "data_type": "string", "input_type": "telepathy"}])
    assert any("input_type" in e for e in provider.validate_template(_env(flat)))


def test_validate_missing_fields(provider):
    flat = _flat()
    del flat["fields"]
    assert any("fields" in e for e in provider.validate_template(_env(flat)))


def test_validate_bad_field_data_type(provider):
    flat = _flat(fields=[{"name": "X", "data_type": "quantum", "input_type": "text"}])
    assert any("data_type" in e for e in provider.validate_template(_env(flat)))


def test_extract_dependencies(provider):
    deps = provider.extract_dependencies(_env(_flat()).to_working_dict())
    assert deps == ["case_sla.standard_sla"]


def test_plan_create(provider):
    change = provider.plan_create(_env(_flat()), "/p.yaml")
    assert change.action == ResourceAction.CREATE
    assert change.resource_type == "case_template"


def test_apply_create_resolves_sla(provider):
    provider.falcon.command.return_value = {
        "status_code": 201,
        "body": {"resources": [{"id": "api-tmpl-1"}], "errors": []},
    }
    result = provider.apply_create(_env(_flat()))
    assert result["id"] == "api-tmpl-1"
    assert result["resource_id"] == "phishing_investigation"
    body = provider.falcon.command.call_args.kwargs["body"]
    assert body["sla_id"] == "api-sla-1"
    assert "sla_ref" not in body


def test_apply_create_unresolved_sla_raises(provider):
    provider.ref_resolver = _Resolver({})
    with pytest.raises(UnresolvedRefError):
        provider.apply_create(_env(_flat()))


def test_hash_excludes_resolved_id(provider):
    h1 = provider.compute_content_hash(_env(_flat()).to_working_dict())
    provider.ref_resolver = _Resolver({("case_sla", "standard_sla"): "DIFFERENT"})
    h2 = provider.compute_content_hash(_env(_flat()).to_working_dict())
    assert h1 == h2


def test_apply_delete_raises_on_failure(provider):
    provider.falcon.command.return_value = {"status_code": 500, "body": {"errors": [{"message": "boom"}]}}
    with pytest.raises(RuntimeError):
        provider.apply_delete("api-tmpl-1")


def test_apply_delete_success(provider):
    provider.falcon.command.return_value = {"status_code": 200, "body": {"resources": [], "errors": []}}
    assert provider.apply_delete("api-tmpl-1")["id"] == "api-tmpl-1"


def test_fetch_all_remote_templates(provider):
    provider.falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": ["t1"]}},
        {"status_code": 200, "body": {"resources": [{"id": "t1", "name": "Phishing"}]}},
    ]
    assert provider._fetch_all_remote_templates() == {"Phishing": {"id": "t1", "name": "Phishing"}}


def test_to_template_reverse_maps_sla(provider):
    provider.falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": ["s1"]}},
        {"status_code": 200, "body": {"resources": [{"id": "s1", "name": "Standard Response SLA"}]}},
    ]
    tmpl = provider.to_template({"name": "Phishing", "description": "x", "fields": [], "sla_id": "s1"})
    assert tmpl["sla_ref"] == provider._name_to_resource_id("Standard Response SLA")
    assert "sla_id" not in tmpl


def test_to_template_preserves_unresolved_sla(provider):
    provider.falcon.command.side_effect = [
        {"status_code": 200, "body": {"resources": []}},  # no SLAs -> empty reverse map
    ]
    tmpl = provider.to_template({"name": "Phishing", "fields": [], "sla_id": "unknown"})
    assert tmpl["sla_id"] == "unknown"
    assert "sla_ref" not in tmpl
