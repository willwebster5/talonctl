from types import SimpleNamespace

import pytest

from talonctl.core.ref_resolver import RefResolver, UnresolvedRefError


def _state(**kw):
    return SimpleNamespace(id=kw["id"], provider_metadata=kw["provider_metadata"])


class _FakeStateManager:
    def __init__(self, by_type):
        self._by_type = by_type  # {resource_type: {qualified_key: state}}

    def get_all_resources(self, resource_type=None):
        return self._by_type.get(resource_type, {})


def test_resolve_matches_provider_metadata_resource_id():
    sm = _FakeStateManager(
        {
            "case_notification_group": {
                "case_notification_group.secops_email_oncall": _state(
                    id="api-ng-123",
                    provider_metadata={"resource_id": "secops_email_oncall", "id": "api-ng-123"},
                )
            }
        }
    )
    resolver = RefResolver(sm)
    assert resolver.resolve("case_notification_group", "secops_email_oncall") == "api-ng-123"


def test_resolve_raises_when_missing():
    resolver = RefResolver(_FakeStateManager({"case_sla": {}}))
    with pytest.raises(UnresolvedRefError) as exc:
        resolver.resolve("case_sla", "nonexistent")
    assert "case_sla" in str(exc.value)
    assert "nonexistent" in str(exc.value)


def test_resolve_does_not_cross_types():
    sm = _FakeStateManager(
        {
            "case_sla": {
                "case_sla.standard_sla": _state(
                    id="api-sla-1", provider_metadata={"resource_id": "standard_sla", "id": "api-sla-1"}
                )
            }
        }
    )
    resolver = RefResolver(sm)
    with pytest.raises(UnresolvedRefError):
        resolver.resolve("case_notification_group", "standard_sla")
