"""The canonical talonctl v2 resource envelope (in-memory model).

A single dataclass that every loaded resource normalizes to, plus the
kind <-> resource_type <-> depends_on-ref vocabulary shared across the
loader, validator, and (later) providers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

API_VERSION = "talon/v2"

# Canonical kind (PascalCase) -> resource_type (snake_case, used in state,
# directories, and the `<type>.<resource_id>` depends_on ref format).
KIND_TO_TYPE: Dict[str, str] = {
    "Detection": "detection",
    "SavedSearch": "saved_search",
    "LookupFile": "lookup_file",
    "Workflow": "workflow",
    "Dashboard": "dashboard",
    "RtrScript": "rtr_script",
    "RtrPutFile": "rtr_put_file",
}
TYPE_TO_KIND: Dict[str, str] = {v: k for k, v in KIND_TO_TYPE.items()}
VALID_KINDS = frozenset(KIND_TO_TYPE)


@dataclass
class Envelope:
    """One resource in canonical v2 form. `status` is read-only/server-assigned
    and is never present on authored files (the loader/validator reject it)."""

    api_version: str
    kind: str
    metadata: Dict[str, Any]
    spec: Dict[str, Any]
    status: Optional[Dict[str, Any]] = None

    @property
    def resource_id(self) -> str:
        return self.metadata["resource_id"]

    @property
    def resource_type(self) -> str:
        return KIND_TO_TYPE[self.kind]

    @property
    def ref(self) -> str:
        """`<type>.<resource_id>` — the depends_on / dependency ref format."""
        return f"{self.resource_type}.{self.resource_id}"
