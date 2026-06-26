from talonctl.commands.init import RESOURCE_DIRS
from talonctl.core.envelope import KIND_TO_TYPE, TYPE_TO_KIND
from talonctl.core.template_discovery import TemplateDiscovery


def test_kinds_registered():
    assert KIND_TO_TYPE["CaseNotificationGroup"] == "case_notification_group"
    assert KIND_TO_TYPE["CaseSla"] == "case_sla"
    assert KIND_TO_TYPE["CaseTemplate"] == "case_template"
    assert TYPE_TO_KIND["case_template"] == "CaseTemplate"


def test_discovery_types_and_dirs():
    for t in ("case_notification_group", "case_sla", "case_template"):
        assert t in TemplateDiscovery.VALID_RESOURCE_TYPES
    assert TemplateDiscovery.TYPE_TO_DIR["case_notification_group"] == "case_notification_groups"
    assert TemplateDiscovery.TYPE_TO_DIR["case_sla"] == "case_slas"
    assert TemplateDiscovery.TYPE_TO_DIR["case_template"] == "case_templates"


def test_init_scaffolds_dirs():
    for d in ("case_notification_groups", "case_slas", "case_templates"):
        assert d in RESOURCE_DIRS
