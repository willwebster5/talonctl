from unittest.mock import MagicMock

from talonctl.core.deployment_orchestrator import DeploymentOrchestrator


def test_fetch_all_deployed_dispatches_case_types():
    orch = DeploymentOrchestrator.__new__(DeploymentOrchestrator)  # bypass heavy __init__
    for rtype, method in [
        ("case_notification_group", "_fetch_all_remote_notification_groups"),
        ("case_sla", "_fetch_all_remote_slas"),
        ("case_template", "_fetch_all_remote_templates"),
    ]:
        provider = MagicMock()
        getattr(provider, method).return_value = {"X": {"id": "1", "name": "X"}}
        result = orch._fetch_all_deployed(provider, rtype)
        assert result == {"X": {"id": "1", "name": "X"}}
        getattr(provider, method).assert_called_once()
