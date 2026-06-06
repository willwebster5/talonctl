"""The canonical talonctl v2 resource envelope (in-memory model).

A single dataclass that every loaded resource normalizes to, plus the
kind <-> resource_type <-> depends_on-ref vocabulary shared across the
loader, validator, and (later) providers.
"""

from __future__ import annotations

import copy
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

# Canonical identity-metadata key set — the ONE source of truth for the two
# halves of identity extraction, which must stay in lockstep:
#   * forward (v1_compat.v1_to_v2): these keys are lifted OUT of the v1 top
#     level INTO envelope metadata and never land in spec.
#   * inverse (Envelope.to_working_dict): these keys are NOT placed into the
#     reconstructed working["metadata"] block (they round-trip as top-level
#     working keys instead).
# A divergence between the two would be invisible to the hash-stability anchor
# (the metadata block is stripped before hashing), so both derive from here.
IDENTITY_METADATA_KEYS = frozenset({"resource_id", "name", "labels", "tags"})


@dataclass
class Envelope:
    """One resource in canonical v2 form. `status` is read-only/server-assigned
    and is never present on authored files (the loader/validator reject it)."""

    api_version: str
    kind: str
    metadata: Dict[str, Any]
    spec: Dict[str, Any]
    status: Optional[Dict[str, Any]] = None
    origin_path: Optional[str] = None  # absolute path of the source YAML; re-injected as _template_path

    _SPEC_TO_WORKING_RENAMES = {
        "query_string": "queryString",
        "search_domain": "_search_domain",
        "depends_on": "dependencies",
    }

    def to_working_dict(self) -> Dict[str, Any]:
        """Reconstruct the legacy flat dict the providers' internals read.

        The round-trip-tested inverse of v1_compat.v1_to_v2. Provider internals
        (payload build, compute_content_hash, dependency/FQL extraction) read this
        dict's keys unchanged, so content hashes stay byte-identical.

        The returned dict is a deep copy fully independent of this Envelope:
        callers may mutate it (including nested values) without corrupting the
        shared Envelope's spec/metadata.
        """
        working: Dict[str, Any] = dict(self.spec)
        for spec_key, legacy_key in Envelope._SPEC_TO_WORKING_RENAMES.items():
            if spec_key in working:
                working[legacy_key] = working.pop(spec_key)
        md = self.metadata
        for ident in ("resource_id", "name"):
            if ident in md:
                working[ident] = md[ident]
        if md.get("labels"):
            working["labels"] = md["labels"]
        if md.get("tags"):
            working["tags"] = md["tags"]
        # Reconstruct the internal v1 `metadata:` block (everything in envelope
        # metadata that isn't identity). Providers read working["metadata"] for
        # maturity/ads validation; stripped before hashing, so hashes stay stable.
        block = {k: v for k, v in md.items() if k not in IDENTITY_METADATA_KEYS}
        if block:
            working["metadata"] = block
        if self.origin_path:
            working["_template_path"] = self.origin_path
        return copy.deepcopy(working)

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
