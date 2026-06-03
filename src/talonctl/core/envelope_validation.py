"""Validation for v2 envelopes. The JSON Schema is the single source of truth
for structure (spec §7); the depends_on cycle check is the one rule schema
cannot express."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any, Dict, List

import jsonschema

from talonctl.core.envelope import Envelope


@lru_cache(maxsize=1)
def _schema() -> Dict[str, Any]:
    text = resources.files("talonctl.schemas").joinpath("envelope.schema.json").read_text()
    return json.loads(text)


def _to_document(env: Envelope) -> Dict[str, Any]:
    doc: Dict[str, Any] = {
        "apiVersion": env.api_version,
        "kind": env.kind,
        "metadata": env.metadata,
        "spec": env.spec,
    }
    if env.status is not None:
        doc["status"] = env.status
    return doc


def validate_envelope(env: Envelope) -> List[str]:
    """Return a list of human-readable schema errors ('' empty == valid)."""
    validator = jsonschema.Draft202012Validator(_schema())
    errors = []
    for err in sorted(validator.iter_errors(_to_document(env)), key=lambda e: list(e.path)):
        loc = ".".join(str(p) for p in err.path) or "<root>"
        errors.append(f"{loc}: {err.message}")
    return errors


def check_depends_on_cycles(envs: List[Envelope]) -> List[str]:
    """Detect cycles in the depends_on graph (Kahn's algorithm)."""
    nodes = {e.ref for e in envs}
    # Only consider edges whose target is in this set. Refs to resources defined
    # in other files (or v1 files, or filtered out) are NOT cycles — they resolve
    # elsewhere (spec §7). Counting them would produce false-positive cycles.
    edges = {e.ref: [d for d in (e.spec.get("depends_on") or []) if d in nodes] for e in envs}
    indeg = {n: 0 for n in nodes}
    for ref, deps in edges.items():
        for _ in deps:
            indeg[ref] += 1
    queue = [n for n in nodes if indeg[n] == 0]
    seen = 0
    while queue:
        n = queue.pop(0)
        seen += 1
        for ref, deps in edges.items():
            if n in deps:
                indeg[ref] -= 1
                if indeg[ref] == 0:
                    queue.append(ref)
    if seen != len(nodes):
        return ["dependency cycle detected among depends_on refs"]
    return []
