from pathlib import Path
from unittest.mock import MagicMock

from talonctl.core.envelope_loader import load_envelopes
from talonctl.providers.case_notification_group_provider import CaseNotificationGroupProvider
from talonctl.providers.case_sla_provider import CaseSlaProvider
from talonctl.providers.case_template_provider import CaseTemplateProvider

EXAMPLES = Path("examples/resources")


def _only_env(path):
    envs = load_envelopes(path)
    assert len(envs) == 1
    return envs[0]


def test_notification_group_example_valid():
    env = _only_env(EXAMPLES / "case_notification_group.yaml")
    assert CaseNotificationGroupProvider(MagicMock()).validate_template(env) == []


def test_sla_example_valid():
    env = _only_env(EXAMPLES / "case_sla.yaml")
    assert CaseSlaProvider(MagicMock()).validate_template(env) == []


def test_template_example_valid():
    env = _only_env(EXAMPLES / "case_template.yaml")
    assert CaseTemplateProvider(MagicMock()).validate_template(env) == []
