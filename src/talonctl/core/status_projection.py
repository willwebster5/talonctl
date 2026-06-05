"""The canonical read-only v2 `status` projection over a deployed ResourceState.

`status` is server-assigned observed state. This module derives it from fields
already in state — it captures no new data and never round-trips into a template.
A pure function with no I/O; Section 3 attaches its output to Envelope.status.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from talonctl.core.state_manager import ResourceState


def _resolve_server_id(rs: ResourceState) -> Optional[str]:
    """The server-assigned id, or None if missing / a never-deployed placeholder.

    A ``"<type>.<resource_id>"`` id (e.g. "saved_search.example_source_enrich") is
    a locally-minted placeholder for an undeployed resource — not a server id — so
    it is reported as absent. Real server ids (UUIDs, opaque tokens, "*.csv"
    filenames, "<hash>_<clientid>") never start with a talonctl "<type>." prefix.
    """
    rid = rs.id or ""
    if not rid or rid.startswith(f"{rs.type}."):
        return None
    return rid


def project_status(rs: ResourceState) -> Dict[str, Any]:
    """Project a ResourceState into the canonical read-only v2 `status` view.

    Unresolvable fields are omitted (never emitted empty or as a placeholder).
    """
    status: Dict[str, Any] = {}

    server_id = _resolve_server_id(rs)
    if server_id:
        status["server_id"] = server_id

    if rs.type == "detection":
        rule_id = (rs.provider_metadata or {}).get("rule_id") or server_id
        if rule_id:
            status["rule_id"] = rule_id  # detection rule UUID; equals server_id

    if rs.deployed_at:
        status["deployed_at"] = rs.deployed_at
    if rs.content_hash:
        status["content_hash"] = rs.content_hash

    return status
