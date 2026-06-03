"""Bytes-on-disk -> List[Envelope]. The dual-read seam: v2 docs map straight in,
v1 docs route through v1_to_v2. Supports 1 resource, multi-doc (---), or a
top-level list per file (spec §6 — no Module kind)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from talonctl.core.envelope import API_VERSION, Envelope, VALID_KINDS
from talonctl.core.v1_compat import v1_to_v2


def _iter_documents(raw: Any) -> List[Dict[str, Any]]:
    """Flatten YAML load(s) into a list of mapping documents."""
    docs: List[Dict[str, Any]] = []
    for item in raw:
        if item is None:
            continue
        if isinstance(item, list):
            docs.extend(d for d in item if isinstance(d, dict))
        elif isinstance(item, dict):
            docs.append(item)
        else:
            raise ValueError(f"document is not a mapping: {type(item).__name__}")
    return docs


def _parse_v2(doc: Dict[str, Any]) -> Envelope:
    kind = doc.get("kind")
    if kind not in VALID_KINDS:
        raise ValueError(f"unknown or missing kind: {kind!r}")
    if "status" in doc:
        raise ValueError(f"{kind}: top-level `status` is read-only and must not be authored")
    metadata = doc.get("metadata") or {}
    spec = doc.get("spec") or {}
    return Envelope(api_version=API_VERSION, kind=kind, metadata=metadata, spec=spec)


def load_envelopes(path: Path, *, default_resource_type: Optional[str] = None) -> List[Envelope]:
    """Load every resource declared in `path`.

    v1 documents require `default_resource_type` (the directory-derived type,
    as TemplateDiscovery already knows). v2 documents derive type from `kind`.
    """
    path = Path(path)
    raw_docs = list(yaml.safe_load_all(path.read_text()))
    envelopes: List[Envelope] = []
    for doc in _iter_documents(raw_docs):
        if doc.get("apiVersion") == API_VERSION:
            envelopes.append(_parse_v2(doc))
        else:
            if default_resource_type is None:
                raise ValueError(
                    f"{path}: v1 document needs a resource type (no apiVersion and no default_resource_type given)"
                )
            envelopes.append(v1_to_v2(doc, resource_type=default_resource_type))
    return envelopes
