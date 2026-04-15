"""
Core Infrastructure for Unified IaC System

This package provides the foundational components for the unified resource management system:
- BaseResourceProvider: Abstract interface for all resource providers
- ResourceGraph: Dependency tracking and topological sorting
- StateManager: State file management with v2→v3 migration
- ProviderRegistry: Dynamic provider loading and management
- DeploymentOrchestrator: Unified deployment orchestration
- TemplateDiscovery: Resource template discovery
- PlanFormatter: Terraform-style output formatting
"""

from talonctl.core.base_provider import (
    BaseResourceProvider,
    ResourceAction,
    ResourceChange
)
from talonctl.core.resource_graph import (
    ResourceGraph,
    DependencyCycle
)
from talonctl.core.state_manager import (
    StateManager,
    ResourceState
)
from talonctl.core.provider_registry import (
    ProviderRegistry
)
from talonctl.core.provider_adapter import (
    ProviderAdapter
)
from talonctl.core.deployment_orchestrator import (
    DeploymentOrchestrator,
    DeploymentPlan,
    DeploymentResult,
    ResourceChange as OrchestratorResourceChange
)
from talonctl.core.template_discovery import (
    TemplateDiscovery,
    DiscoveredTemplate
)
from talonctl.core.plan_formatter import (
    PlanFormatter
)
from talonctl.core.drift_detector import (
    DriftDetector,
    DriftReport,
    DriftItem
)
from talonctl.core.dependency_validator import (
    DependencyValidator,
    DependencyIssue
)

__all__ = [
    # Base provider
    'BaseResourceProvider',
    'ResourceAction',
    'ResourceChange',

    # Resource graph
    'ResourceGraph',
    'DependencyCycle',

    # State management
    'StateManager',
    'ResourceState',

    # Provider registry
    'ProviderRegistry',

    # Backward compatibility
    'ProviderAdapter',

    # Orchestration (Week 5)
    'DeploymentOrchestrator',
    'DeploymentPlan',
    'DeploymentResult',
    'OrchestratorResourceChange',

    # Template discovery
    'TemplateDiscovery',
    'DiscoveredTemplate',

    # Plan formatting
    'PlanFormatter',

    # Drift detection
    'DriftDetector',
    'DriftReport',
    'DriftItem',

    # Dependency validation
    'DependencyValidator',
    'DependencyIssue',
]
