"""Envelope -> canonical v2 YAML text.

The structural inverse of ``core.envelope_loader``: deterministic key order,
comments dropped (PyYAML cannot preserve them; see the Section 4 design doc).
``talonctl migrate`` uses this to rewrite v1 templates in place as v2.
"""

from __future__ import annotations

from typing import Any, List

import yaml

from talonctl.core.envelope import IDENTITY_METADATA_KEYS, Envelope

# Emit-order for identity metadata keys (must cover exactly IDENTITY_METADATA_KEYS
# from talonctl.core.envelope — the frozenset is the source of truth for *which*
# keys are identity; this tuple encodes *in what order* they appear in serialized
# YAML).  A drift-guard test in test_envelope_serializer.py enforces parity.
_METADATA_ORDER = ("resource_id", "name", "labels", "tags")


def _canonical(obj: Any) -> Any:
    """Rebuild dicts with sorted keys (lists recursed, scalars untouched) so
    PyYAML's ``sort_keys=False`` emits deterministic output while leaving our
    hand-ordered top level/metadata intact."""
    if isinstance(obj, dict):
        return {k: _canonical(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_canonical(v) for v in obj]
    return obj


def _document(env: Envelope) -> dict:
    metadata: dict = {}
    for key in _METADATA_ORDER:
        if key in env.metadata:
            metadata[key] = _canonical(env.metadata[key])
    for key in sorted(env.metadata):  # remaining (non-identity) metadata-block keys, sorted
        if key not in IDENTITY_METADATA_KEYS:
            metadata[key] = _canonical(env.metadata[key])
    # status is server-assigned and never authored -> never serialized.
    return {
        "apiVersion": env.api_version,
        "kind": env.kind,
        "metadata": metadata,
        "spec": _canonical(env.spec),
    }


def serialize_envelope(env: Envelope) -> str:
    """Render one envelope to canonical v2 YAML text (trailing newline)."""
    return yaml.safe_dump(
        _document(env),
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )


def serialize_envelopes(envs: List[Envelope]) -> str:
    """Render one or many envelopes. Multiple resources are joined as a YAML
    multi-document stream (the loader reads multi-doc and top-level-list files)."""
    return "---\n".join(serialize_envelope(e) for e in envs)
