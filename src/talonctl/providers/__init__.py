"""
Resource Providers

This package contains all resource provider implementations:
- DetectionProvider: NGSIEM detection rules
- WorkflowProvider: SOAR workflows
- SavedSearchProvider: NGSIEM saved queries
- LookupFileProvider: NGSIEM lookup files
- RTRScriptProvider: RTR custom scripts for runscript command
- RTRPutFileProvider: RTR put files for put/put-and-run commands
- DashboardProvider: NGSIEM dashboards
- CaseNotificationGroupProvider: Case management notification groups
- CaseSlaProvider: Case management SLA policies
- CaseTemplateProvider: Case management templates
- CorrelationRuleProvider: Correlation rules (Future)
"""

from .detection_provider import DetectionProvider
from .workflow_provider import WorkflowProvider
from .saved_search_provider import SavedSearchProvider
from .lookup_file_provider import LookupFileProvider
from .rtr_script_provider import RTRScriptProvider
from .rtr_put_file_provider import RTRPutFileProvider
from .dashboard_provider import DashboardProvider
from .case_notification_group_provider import CaseNotificationGroupProvider
from .case_sla_provider import CaseSlaProvider
from .case_template_provider import CaseTemplateProvider

__all__ = [
    "DetectionProvider",
    "WorkflowProvider",
    "SavedSearchProvider",
    "LookupFileProvider",
    "RTRScriptProvider",
    "RTRPutFileProvider",
    "DashboardProvider",
    "CaseNotificationGroupProvider",
    "CaseSlaProvider",
    "CaseTemplateProvider",
]
