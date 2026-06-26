"""Resolve a sibling resource's stable resource_id to its live API id.

Case-management resources reference each other by API id in their payloads
(case_sla.goals[].escalation_policy.steps[].notification_group_id, and
case_template.sla_id). Authors write the sibling's stable resource_id in a
`*_ref` field; this resolver maps that to the deployed API id at apply time.

Matching is on provider_metadata["resource_id"] (which each case provider stamps
into its apply result), not the state dict key, so it is independent of the
display-name-vs-resource_id key semantics elsewhere in state.
"""

from __future__ import annotations

from typing import Any


class UnresolvedRefError(Exception):
    """Raised when a `*_ref` points at a resource not yet deployed / not in state."""


class RefResolver:
    def __init__(self, state_manager: Any):
        self._state_manager = state_manager

    def resolve(self, resource_type: str, resource_id: str) -> str:
        """Return the live API id of the deployed sibling identified by
        (resource_type, stable resource_id). Raise UnresolvedRefError if absent."""
        deployed = self._state_manager.get_all_resources(resource_type)
        for state in deployed.values():
            metadata = getattr(state, "provider_metadata", None) or {}
            if metadata.get("resource_id") == resource_id:
                return state.id
        raise UnresolvedRefError(
            f"Unresolved reference: no deployed {resource_type} with resource_id "
            f"'{resource_id}' found in state. Ensure it is applied first."
        )
