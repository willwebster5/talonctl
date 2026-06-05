"""v1 -> v2 normalization. The single seam that lets the loader (and, later,
`talonctl migrate`) read legacy flat-dict templates as canonical Envelopes."""

from __future__ import annotations

from typing import Any, Dict

from talonctl.core.base_provider import BaseResourceProvider
from talonctl.core.envelope import Envelope, TYPE_TO_KIND

# Identity keys pulled OUT of the v1 top level into metadata (never land in spec).
_IDENTITY_KEYS = {"resource_id", "name", "labels", "tags"}
# Dropped entirely (subsumed or reconciled elsewhere).
_DROP_KEYS = {"rule_id"}
# Explicit camelCase -> snake_case spec renames (allow-list, not blanket).
_RENAME_MAP = {"queryString": "query_string"}
# Kinds with no stable v1 identifier — mint resource_id from name.
_MINTABLE_TYPES = {"rtr_script", "rtr_put_file"}


def _build_labels(data: Dict[str, Any]) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    raw = data.get("labels")
    if isinstance(raw, dict):
        labels.update({str(k): str(v) for k, v in raw.items()})
    return labels


def v1_to_v2(data: Dict[str, Any], *, resource_type: str) -> Envelope:
    """Normalize one v1 flat-dict template into a canonical Envelope.

    `resource_type` is the snake_case type the template was discovered as
    (from its directory), used to choose the v2 kind and minting policy.
    """
    kind = TYPE_TO_KIND[resource_type]

    resource_id = data.get("resource_id")
    name = data.get("name")
    if not resource_id:
        if resource_type in _MINTABLE_TYPES and name:
            resource_id = BaseResourceProvider._name_to_resource_id(name)
        else:
            raise ValueError(f"{resource_type}: template is missing 'resource_id'")

    metadata: Dict[str, Any] = {"resource_id": resource_id}
    if name is not None:
        metadata["name"] = name
    labels = _build_labels(data)
    if labels:
        metadata["labels"] = labels
    if isinstance(data.get("tags"), list):
        metadata["tags"] = list(data["tags"])

    spec: Dict[str, Any] = {}
    for key, value in data.items():
        if key == "_search_domain":
            spec["search_domain"] = value
            continue
        if key in _IDENTITY_KEYS or key in _DROP_KEYS:
            continue
        if key == "dependencies":
            spec["depends_on"] = value
            continue
        spec[_RENAME_MAP.get(key, key)] = value

    return Envelope(api_version="talon/v2", kind=kind, metadata=metadata, spec=spec)
