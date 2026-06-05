"""The canonical read-only v2 `status` projection over a deployed ResourceState.

`status` is server-assigned observed state. This module derives it from fields
already in state — it captures no new data and never round-trips into a template.
A pure function with no I/O; Section 3 attaches its output to Envelope.status.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, TYPE_CHECKING

from talonctl.core.state_manager import ResourceState

if TYPE_CHECKING:
    from talonctl.core.envelope import Envelope


def _project(entry: Mapping[str, Any], resource_type: str) -> Dict[str, Any]:
    """Project an on-disk state entry (mapping) into the read-only v2 status view.

    Never-deployed signal is structural: an id is treated as a placeholder only
    when there is no `deployed_at` AND it looks like "<type>.<id>". The string check
    is now just a fallback for rows that predate `deployed_at`.

    Unresolvable fields are omitted (never emitted empty or as a placeholder).
    """
    status: Dict[str, Any] = {}

    rid = entry.get("id") or ""
    deployed_at = entry.get("deployed_at")
    server_id = rid if rid and not (not deployed_at and rid.startswith(f"{resource_type}.")) else None
    if server_id:
        status["server_id"] = server_id

    if resource_type == "detection":
        rule_id = (entry.get("provider_metadata") or {}).get("rule_id") or server_id
        if rule_id:
            status["rule_id"] = rule_id  # detection rule UUID; falls back to server_id

    if deployed_at:
        status["deployed_at"] = deployed_at
    if entry.get("content_hash"):
        status["content_hash"] = entry["content_hash"]

    return status


def project_status(rs: "ResourceState") -> Dict[str, Any]:  # back-compat wrapper (Section 2 callers)
    """Project a ResourceState into the canonical read-only v2 `status` view."""
    return _project(
        {
            "id": rs.id,
            "deployed_at": rs.deployed_at,
            "content_hash": rs.content_hash,
            "provider_metadata": rs.provider_metadata,
        },
        rs.type,
    )


def attach_status(env: "Envelope", state_entry: Optional[Mapping[str, Any]], resource_type: str) -> None:
    """Attach the read-only status projection onto an Envelope (in place).

    `state_entry` is the on-disk state dict, or None if unmanaged (never deployed) —
    in which case status stays None and plan emits CREATE.
    """
    env.status = _project(state_entry, resource_type) if state_entry is not None else None
