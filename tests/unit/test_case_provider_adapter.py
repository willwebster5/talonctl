from pathlib import Path
from unittest.mock import MagicMock

from talonctl.core.provider_adapter import ProviderAdapter
from talonctl.core.ref_resolver import RefResolver


def _adapter(tmp_path: Path) -> ProviderAdapter:
    return ProviderAdapter(MagicMock(), state_file_path=tmp_path / "state.json", auto_save=False)


def test_case_providers_registered(tmp_path):
    adapter = _adapter(tmp_path)
    for t in ("case_notification_group", "case_sla", "case_template"):
        assert t in adapter.providers
        assert adapter.providers[t].get_resource_type() == t


def test_ref_resolver_attached_to_case_providers(tmp_path):
    adapter = _adapter(tmp_path)
    for t in ("case_notification_group", "case_sla", "case_template"):
        assert isinstance(getattr(adapter.providers[t], "ref_resolver", None), RefResolver)
    resolvers = [adapter.providers[t].ref_resolver for t in ("case_notification_group", "case_sla", "case_template")]
    assert resolvers[0] is resolvers[1] is resolvers[2], "all case providers must share one RefResolver instance"


def test_existing_providers_still_registered(tmp_path):
    adapter = _adapter(tmp_path)
    for t in ("detection", "workflow", "saved_search", "lookup_file", "rtr_script", "rtr_put_file", "dashboard"):
        assert t in adapter.providers
