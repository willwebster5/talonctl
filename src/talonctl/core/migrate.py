# src/talonctl/core/migrate.py
"""Core engines for `talonctl migrate`: v1->v2 template rewrap (file-oriented)
and v3->v4 state reconciliation (resource-oriented, pure). I/O writes live in
the command; everything here computes a plan a caller can apply or just report.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from talonctl.core.envelope_loader import load_envelopes
from talonctl.core.envelope_serializer import serialize_envelopes
from talonctl.core.envelope_validation import validate_authored_envelope
from talonctl.core.template_discovery import DiscoveredTemplate, TemplateDiscovery


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


# -- State reconciliation ------------------------------------------------------


@dataclass
class TemplateIndex:
    """Lookups over discovered templates for re-keying state."""

    ids: Set[Tuple[str, str]]  # (resource_type, resource_id)
    by_path: Dict[str, List[Tuple[str, str]]]  # resolved file path -> resources declared in it
    by_display: Dict[Tuple[str, str], Optional[str]]  # (rtype, display_name) -> resource_id, None if ambiguous


@dataclass
class StateReconcile:
    rekeyed: List[Tuple[str, str, str]] = field(default_factory=list)  # (rtype, old_key, new_id)
    orphans: List[Tuple[str, str]] = field(default_factory=list)  # (rtype, key)
    unmanaged: List[Tuple[str, str]] = field(default_factory=list)  # (rtype, resource_id)
    conflicts: List[Tuple[str, str, str, str]] = field(default_factory=list)  # (rtype, key, target, reason)


def build_template_index(discovered: Dict[str, List[DiscoveredTemplate]]) -> TemplateIndex:
    """Build a TemplateIndex from TemplateDiscovery.discover_all() output."""
    ids: Set[Tuple[str, str]] = set()
    by_path: Dict[str, List[Tuple[str, str]]] = {}
    display_seen: Dict[Tuple[str, str], Set[str]] = {}
    for rtype, templates in discovered.items():
        for t in templates:
            ids.add((rtype, t.name))
            by_path.setdefault(str(Path(t.file_path).resolve()), []).append((rtype, t.name))
            if t.display_name:
                display_seen.setdefault((rtype, t.display_name), set()).add(t.name)
    by_display: Dict[Tuple[str, str], Optional[str]] = {
        key: (next(iter(rids)) if len(rids) == 1 else None) for key, rids in display_seen.items()
    }
    return TemplateIndex(ids=ids, by_path=by_path, by_display=by_display)


def _resolve(rtype: str, entry: Dict[str, Any], index: TemplateIndex) -> Tuple[Optional[str], bool]:
    """Resolve a state entry to a resource_id. Returns (resource_id, ambiguous)."""
    path = entry.get("template_path")
    if path:
        candidates = [rid for (rt, rid) in index.by_path.get(str(Path(path).resolve()), []) if rt == rtype]
        if len(candidates) == 1:
            return candidates[0], False
        if len(candidates) > 1:
            display = entry.get("display_name")
            picked = [rid for rid in candidates if index.by_display.get((rtype, display)) == rid]
            if len(picked) == 1:
                return picked[0], False
            return None, True
    display = entry.get("display_name")
    if display is not None and (rtype, display) in index.by_display:
        rid = index.by_display[(rtype, display)]
        return (rid, False) if rid is not None else (None, True)
    return None, False


def reconcile_state(resources: Dict[str, Dict[str, Dict[str, Any]]], index: TemplateIndex) -> StateReconcile:
    """Pure: compute the v3->v4 re-key plan + orphan/unmanaged/conflict reports.
    `resources` is the state file's `resources` mapping ({type: {key: entry}}).

    Two-phase so two-into-one collisions never "guess" a winner: phase one collects
    re-key proposals (recording orphans/ambiguous as it goes); phase two groups by
    target and only emits a re-key when exactly one source resolves to a target that
    does not already exist as its own key — otherwise ALL colliding sources conflict."""
    rep = StateReconcile()
    proposals: List[Tuple[str, str, str]] = []  # (rtype, old_key, target_id)

    for rtype, entries in resources.items():
        for key, entry in entries.items():
            if (rtype, key) in index.ids:
                continue  # already resource_id-keyed
            rid, ambiguous = _resolve(rtype, entry, index)
            if ambiguous:
                rep.conflicts.append((rtype, key, "", "ambiguous resolution"))
                continue
            if rid is None:
                rep.orphans.append((rtype, key))
                continue
            if rid == key:
                continue  # resolves to itself; nothing to move
            proposals.append((rtype, key, rid))

    by_target: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for rtype, key, rid in proposals:
        by_target[(rtype, rid)].append(key)

    for (rtype, rid), keys in by_target.items():
        if rid in resources.get(rtype, {}):  # target already present as its own key
            for key in keys:
                rep.conflicts.append((rtype, key, rid, "target resource_id already present"))
        elif len(keys) > 1:  # two-into-one: report both, move neither
            for key in keys:
                rep.conflicts.append((rtype, key, rid, "multiple entries resolve to same resource_id"))
        else:
            rep.rekeyed.append((rtype, keys[0], rid))

    rekeyed_targets = {(rtype, rid) for rtype, _old, rid in rep.rekeyed}
    for rtype, rid in sorted(index.ids):
        if rid not in resources.get(rtype, {}) and (rtype, rid) not in rekeyed_targets:
            rep.unmanaged.append((rtype, rid))
    return rep


@dataclass
class MigrationReport:
    """Aggregate result of a migrate run, for rich + JSON rendering."""

    dry_run: bool
    rewraps: List[FileRewrap] = field(default_factory=list)
    state: StateReconcile = field(default_factory=StateReconcile)

    def to_dict(self) -> Dict[str, Any]:
        def bucket(status: str) -> List[Dict[str, Any]]:
            return [
                {
                    "path": str(fr.path),
                    "kinds": fr.kinds,
                    "comments_dropped": fr.comments_dropped,
                    "errors": fr.errors,
                }
                for fr in self.rewraps
                if fr.status == status
            ]

        return {
            "dry_run": self.dry_run,
            "templates": {"rewrap": bucket("rewrap"), "skip": bucket("skip"), "error": bucket("error")},
            "state": {
                "rekeyed": [list(x) for x in self.state.rekeyed],
                "orphans": [list(x) for x in self.state.orphans],
                "unmanaged": [list(x) for x in self.state.unmanaged],
                "conflicts": [list(x) for x in self.state.conflicts],
            },
        }
