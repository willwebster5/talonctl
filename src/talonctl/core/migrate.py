# src/talonctl/core/migrate.py
"""Core engines for `talonctl migrate`: v1->v2 template rewrap (file-oriented)
and v3->v4 state reconciliation (resource-oriented, pure). I/O writes live in
the command; everything here computes a plan a caller can apply or just report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

from talonctl.core.envelope_loader import load_envelopes
from talonctl.core.envelope_serializer import serialize_envelopes
from talonctl.core.envelope_validation import validate_authored_envelope
from talonctl.core.template_discovery import TemplateDiscovery


# -- Template rewrap -----------------------------------------------------------


@dataclass
class FileRewrap:
    """One template file's rewrap outcome. ``new_text`` is set only for
    ``status == "rewrap"``; the command writes it under ``--write``."""

    path: Path
    status: str  # "rewrap" | "skip" | "error"
    new_text: Optional[str] = None
    comments_dropped: int = 0
    kinds: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _all_docs_v2(raw_text: str) -> bool:
    """True iff every mapping document in the file already declares apiVersion
    talon/v2 (handles multi-doc and top-level-list files like the loader does).

    Raises ``ValueError`` on non-None, non-mapping, non-list scalar documents
    (e.g. a bare ``hello world`` YAML document), matching the behaviour of
    ``envelope_loader._iter_documents``."""
    docs: List[dict] = []
    for item in yaml.safe_load_all(raw_text):
        if item is None:
            continue
        if isinstance(item, list):
            docs.extend(d for d in item if isinstance(d, dict))
        elif isinstance(item, dict):
            docs.append(item)
        else:
            raise ValueError(f"document is not a mapping: {type(item).__name__}")
    return bool(docs) and all(d.get("apiVersion") == "talon/v2" for d in docs)


def _count_comment_lines(raw_text: str) -> int:
    return sum(1 for line in raw_text.splitlines() if line.strip().startswith("#"))


def _scan_file(path: Path, resource_type: str) -> FileRewrap:
    raw = path.read_text()
    try:
        if _all_docs_v2(raw):
            return FileRewrap(path=path, status="skip")
        envelopes = load_envelopes(path, default_resource_type=resource_type)
    except Exception as e:  # malformed YAML, non-mapping doc, missing resource_id, etc.
        return FileRewrap(path=path, status="error", errors=[str(e)])

    errors: List[str] = []
    for env in envelopes:
        errors.extend(f"{env.resource_id}: {msg}" for msg in validate_authored_envelope(env))
    if errors:
        return FileRewrap(path=path, status="error", errors=errors)

    return FileRewrap(
        path=path,
        status="rewrap",
        new_text=serialize_envelopes(envelopes),
        comments_dropped=_count_comment_lines(raw),
        kinds=[env.kind for env in envelopes],
    )


def scan_templates(resources_dir: Path) -> List[FileRewrap]:
    """Scan every `*.yaml` under each resource-type directory and classify it as
    rewrap / skip / error. Pure of writes; safe to call in dry-run."""
    results: List[FileRewrap] = []
    for rtype, dir_name in TemplateDiscovery.TYPE_TO_DIR.items():
        type_dir = resources_dir / dir_name
        if not type_dir.exists():
            continue
        for yaml_file in sorted(type_dir.rglob("*.yaml")):
            results.append(_scan_file(yaml_file, rtype))
    return results
